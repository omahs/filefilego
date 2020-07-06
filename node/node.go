package node

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/gogo/protobuf/proto"
	"github.com/libp2p/go-libp2p"
	connmgr "github.com/libp2p/go-libp2p-connmgr"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"

	discovery "github.com/libp2p/go-libp2p-discovery"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	mplex "github.com/libp2p/go-libp2p-mplex"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	secio "github.com/libp2p/go-libp2p-secio"
	libp2ptls "github.com/libp2p/go-libp2p-tls"
	yamux "github.com/libp2p/go-libp2p-yamux"
	"github.com/multiformats/go-multiaddr"
	"github.com/rs/cors"
	"gitlab.com/younixcc/filefilego/common/hexutil"
	"gitlab.com/younixcc/filefilego/keystore"
	brpc "gitlab.com/younixcc/filefilego/rpc"
)

type PubSubMetadata struct {
	PubSub       *pubsub.PubSub       // PubSub of each individual node
	Subscription *pubsub.Subscription // Subscription of individual node
	Topic        string               // PubSub topic
}

// Broadcast Uses PubSub publish to broadcast messages to other peers
func (c *PubSubMetadata) Broadcast(data []byte) error {

	if len(data) == 0 {
		return errors.New("No data to send")
	}
	err := c.PubSub.Publish(c.Topic, data)
	if err != nil {
		return err
	}
	return nil
}

// Node represents all the node functionalities
type Node struct {
	Host             host.Host
	BlockService     *BlockService
	DHT              *dht.IpfsDHT
	RoutingDiscovery *discovery.RoutingDiscovery
	Gossip           PubSubMetadata
	Keystore         *keystore.KeyStore
	BlockChain       *Blockchain
	isSyncing        bool
	IsSyncingMux     *sync.Mutex
}

func NewNode(ctx context.Context, listenAddrPort string, key *keystore.Key, ks *keystore.KeyStore) (Node, error) {
	node := Node{
		IsSyncingMux: &sync.Mutex{},
	}
	host, err := libp2p.New(ctx,
		libp2p.Identity(key.Private),
		libp2p.ListenAddrStrings(listenAddrPort),
		libp2p.Ping(false),
		libp2p.Security(libp2ptls.ID, libp2ptls.New),
		libp2p.Security(secio.ID, secio.New),
		libp2p.DefaultTransports,
		// Let's prevent our peer from having too many
		libp2p.ConnectionManager(connmgr.NewConnManager(
			100,         // Lowwater
			400,         // HighWater,
			time.Minute, // GracePeriod
		)),
		// Attempt to open ports using uPNP for NATed hosts.
		libp2p.NATPortMap(),
		libp2p.Muxer("/yamux/1.0.0", yamux.DefaultTransport),
		libp2p.Muxer("/mplex/6.7.0", mplex.DefaultTransport),
	)
	if err != nil {
		return node, err
	}

	node.Host = host

	// DHT
	kademliaDHT, err := dht.New(ctx, host, dht.Mode(dht.ModeServer))
	if err != nil {
		return node, err
	}

	node.DHT = kademliaDHT
	node.Keystore = ks

	return node, nil
}

// IsSyncing
func (n *Node) IsSyncing() bool {
	n.IsSyncingMux.Lock()
	sts := n.isSyncing
	n.IsSyncingMux.Unlock()
	return sts
}

// SetSyncing
func (n *Node) SetSyncing(val bool) {
	n.IsSyncingMux.Lock()
	if val {
		n.isSyncing = true
	} else {
		for _, v := range n.BlockService.RemoteHosts {
			n.BlockService.RemoveFromRemoteHosts(v.PeerID)
		}
		n.BlockService.ClearRequiredBlock()
		n.isSyncing = false
	}
	n.IsSyncingMux.Unlock()
}

func (n *Node) HandleGossip(msg *pubsub.Message) error {

	gossip := GossipPayload{}
	if err := proto.Unmarshal(msg.Data, &gossip); err != nil {
		return err
	}
	if gossip.Type == GossipPayload_TRANSACTION {
		tx := UnserializeTransaction(gossip.Payload)
		ok, err := n.BlockChain.IsValidTransaction(tx)
		if err != nil {
			log.Warn("Error while validating tx from broadcast: ", err)
		}

		if len(tx.Data) > MAX_TX_DATA_SIZE {
			log.Warn("a transaction with long data field was rejected. ", hexutil.Encode(tx.Hash))
			return errors.New("a transaction with long data field was rejected. " + hexutil.Encode(tx.Hash))
		}
		if ok {
			err := n.BlockChain.AddMemPool(tx)
			if err != nil {
				log.Warn("Problem while adding tx to mempool from broadcast: ", err)
			}
		}

	} else if gossip.Type == GossipPayload_BLOCK {
		// node is syncing
		if n.IsSyncing() {
			return nil
		}

		// find previous hash, and append it to
		blc, _ := DeserializeBlock(gossip.Payload)
		log.Println("New block broadcasted by verifiers\t", hexutil.Encode(blc.Hash))

		ok := ValidateBlock(blc)
		if ok {
			n.BlockChain.AddBlockPool(blc)

		} else {
			log.Warn("Got an invalid block")
		}
	}
	return nil
}
func (n *Node) ApplyGossip(ctx context.Context) (err error) {
	n.Gossip = PubSubMetadata{}

	optsPS := []pubsub.Option{
		pubsub.WithMessageSigning(true),
	}

	n.Gossip.PubSub, err = pubsub.NewGossipSub(ctx, n.Host, optsPS...)
	if err != nil {
		return err
	}

	n.Gossip.Topic = "TOPIC"
	n.Gossip.Subscription, err = n.Gossip.PubSub.Subscribe(n.Gossip.Topic)
	if err != nil {
		return err
	}

	// run and listen for events
	go func() {
		for {
			// this is blocking so no worries
			msg, err := n.Gossip.Subscription.Next(ctx)
			if err != nil {
				continue
			}
			n.HandleGossip(msg)
		}
	}()

	return nil
}

func (n *Node) GetAddrs() ([]multiaddr.Multiaddr, error) {
	peerInfo := peer.AddrInfo{
		ID:    n.Host.ID(),
		Addrs: n.Host.Addrs(),
	}
	return peer.AddrInfoToP2pAddrs(&peerInfo)
}

func (n *Node) Bootstrap(ctx context.Context, bootstrapPeers []string) error {
	if err := n.DHT.Bootstrap(ctx); err != nil {
		return err
	}
	if len(bootstrapPeers) > 0 {
		var wg sync.WaitGroup
		for _, peerAddr := range bootstrapPeers {
			if peerAddr == "" {
				continue
			}
			wg.Add(1)
			go func(peer string) {
				defer wg.Done()
				_, err := n.ConnectToPeerWithMultiaddr(peer, ctx)
				if err != nil {
					log.Warn("error while connecting to peer: ", err)
				}
			}(peerAddr)
		}
		wg.Wait()
	}
	return nil
}

func (n *Node) ConnectToPeerWithMultiaddr(remoteAddr string, ctx context.Context) (*peer.AddrInfo, error) {

	addr, err := multiaddr.NewMultiaddr(remoteAddr)
	if err != nil {
		return nil, err
	}
	p, err := peer.AddrInfoFromP2pAddr(addr)
	if err != nil {
		return nil, err
	}
	if err := n.Host.Connect(ctx, *p); err != nil {
		return nil, err
	}

	return p, nil
}

func (n *Node) Advertise(ctx context.Context) {
	n.RoutingDiscovery = discovery.NewRoutingDiscovery(n.DHT)
	discovery.Advertise(ctx, n.RoutingDiscovery, "FINDMEHERE")
}

func (n *Node) FindPeers(ctx context.Context) error {
	peerChan, err := n.RoutingDiscovery.FindPeers(ctx, "FINDMEHERE")
	if err != nil {
		return err
	}

	for peer := range peerChan {
		if peer.ID == n.Host.ID() {
			continue
		}
	}
	return nil
}

func (n *Node) Peers() peer.IDSlice {
	return n.Host.Peerstore().Peers()
}

type BlockQueryResponsePayload struct {
	BlockQueryResponse BlockQueryResponse
	PeerID             peer.ID
}

// Sync the blockchain with other nodes
func (n *Node) Sync(ctx context.Context) error {
	if n.IsSyncing() {
		return nil
	}

	// n.SetSyncing(true)
	// produce blocks
	currentHeight := n.BlockChain.GetHeight()
	for _, p := range n.Peers() {
		if n.Host.ID() != p {
			go NewRemoteHost(ctx, n.BlockService, p, currentHeight)
		}
	}
	return nil
}

// StartRPCHTTP starts http json
func (n *Node) StartRPCHTTP(ctx context.Context, address string, port int) error {
	apis := []brpc.API{
		{
			Namespace:    "transaction",
			Version:      "1.0",
			Service:      NewTransactionAPI(n),
			Public:       true,
			AuthRequired: "",
		},
		{
			Namespace:    "account",
			Version:      "1.0",
			Service:      NewAccountAPI(n),
			Public:       true,
			AuthRequired: "",
		},
		{
			Namespace:    "block",
			Version:      "1.0",
			Service:      NewBlockAPI(n),
			Public:       true,
			AuthRequired: "",
		},
		{
			Namespace:    "ffg",
			Version:      "1.0",
			Service:      NewFilefilegoAPI(n),
			Public:       true,
			AuthRequired: "",
		},
	}
	serveMux := http.NewServeMux()
	serveMux.Handle("/", brpc.ServeHTTP(apis))
	handler := cors.AllowAll().Handler(serveMux)
	httpAddr := fmt.Sprintf("%s:%d", address, port)
	log.Fatal(http.ListenAndServe(httpAddr, handler))
	return nil
}
