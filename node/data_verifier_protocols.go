package node

import (
	"bytes"
	"context"
	"io/ioutil"
	"sync"

	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/crypto"
	"github.com/golang/protobuf/proto"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	log "github.com/sirupsen/logrus"
)

// DataVerifierRequestID represents a request to get interested verifiers
const DataVerifierRequestID = "/ffg/dv_verifier_req/1.0.0"

// DataVerifierProtocol wraps the protocols
type DataVerifierProtocol struct {
	Enabled   bool
	Node      *Node
	contMutex sync.Mutex
	contracts []DataContract
}

func (dqp *DataVerifierProtocol) onDataVerifierRequest(s network.Stream) {
	buf, err := ioutil.ReadAll(s)
	defer s.Close()
	if err != nil {
		s.Reset()
		log.Error(err)
		return
	}

	dc := DataContract{}
	err = proto.Unmarshal(buf, &dc)
	if err != nil {
		log.Error(err)
		return
	}

	pPubKey, err := s.Conn().RemotePeer().ExtractPublicKey()
	if err != nil {
		log.Error("couldnt get public key of remote peer in onDataVerifierRequest", err)
		return
	}

	rawBits, err := pPubKey.Raw()
	if err != nil {
		return
	}

	if !bytes.Equal(rawBits, dc.VerifierPubKey) {
		log.Warn("verifier's pubkey mismatch")
		return
	}

	dqp.contMutex.Lock()
	dqp.contracts = append(dqp.contracts, dc)
	dqp.contMutex.Unlock()

	currentNodePubKeyRawBytes, _ := dqp.Node.GetPublicKeyBytes()

	if bytes.Equal(dc.RequesterNodePubKey, currentNodePubKeyRawBytes) {
		log.Println("I am the downloader")
	} else if bytes.Equal(dc.HostResponse.PubKey, currentNodePubKeyRawBytes) {
		log.Println("I am the hoster")
	}
}

// NewDataVerifierProtocol returns a new instance and registers the handlers
func NewDataVerifierProtocol(n *Node) *DataVerifierProtocol {
	p := &DataVerifierProtocol{
		Enabled: true,
		Node:    n,
	}
	n.Host.SetStreamHandler(DataVerifierRequestID, p.onDataVerifierRequest)
	// n.Host.SetStreamHandler(DataVerifierDownloaderRequestID, p.onDataVerifierForDownloaderRequest)
	return p
}

// HandleIncomingBlock searches sealed txs from incoming blocks and checks for data contracts
func (dqp *DataVerifierProtocol) HandleIncomingBlock(block Block) {
	nodePubKeyBytes, err := dqp.Node.GetPublicKeyBytes()
	if err != nil {
		log.Error(err)
		return
	}
	for _, tx := range block.Transactions {
		tpl := TransactionDataPayload{}
		err := proto.Unmarshal(tx.Data, &tpl)
		if err != nil {
			continue
		}

		if tpl.Type == TransactionDataPayloadType_DATA_CONTRACT {
			dc := DataContract{}
			err := proto.Unmarshal(tpl.Payload, &dc)
			if err != nil {
				continue
			}
			// handle this data contract
			if bytes.Equal(dc.VerifierPubKey, nodePubKeyBytes) {
				dqp.contMutex.Lock()
				dqp.contracts = append(dqp.contracts, dc)
				dqp.contMutex.Unlock()
				dqp.coordinate(dc)

			}
		}
	}
}

func (dqp *DataVerifierProtocol) coordinate(contract DataContract) {
	log.Println("coordinating contract...")
	peerIDs := []peer.ID{}

	// downloader
	pubKeyDownloader, err := crypto.PublicKeyFromRawHex(hexutil.Encode(contract.RequesterNodePubKey))
	if err != nil {
		log.Error("unable to get public key of downloader: ", err)
		return
	}
	downloaderID, err := peer.IDFromPublicKey(pubKeyDownloader)
	if err != nil {
		log.Error("unable to get downloader ID from pubkey", err)
		return
	}
	peerIDs = append(peerIDs, downloaderID)

	// data hoster
	pubKeyHost, err := crypto.PublicKeyFromRawHex(hexutil.Encode(contract.HostResponse.PubKey))
	if err != nil {
		log.Error("unable to get public key of data hoster: ", err)
		return
	}

	hostID, err := peer.IDFromPublicKey(pubKeyHost)
	if err != nil {
		log.Error("unable to get host ID from pubkey", err)
		return
	}

	peerIDs = append(peerIDs, hostID)

	accessiblePeers := dqp.Node.FindPeers(peerIDs)
	if len(accessiblePeers) != 2 {
		log.Warn("couldn't find both nodes")
		return
	}

	for _, addr := range accessiblePeers {
		if err := dqp.Node.Host.Connect(context.Background(), addr); err != nil {
			log.Warn("unable to connect to remote host/downloader nodes ", err)
			return
		}
	}

	// connect to hostID
	hostStream, err := dqp.Node.Host.NewStream(context.Background(), hostID, DataVerifierRequestID)
	if err != nil {
		log.Warn("unable to connect to data hoster: ", err)
		return
	}
	downloaderStream, err := dqp.Node.Host.NewStream(context.Background(), downloaderID, DataVerifierRequestID)
	if err != nil {
		log.Warn("unable to connect to downloader: ", err)
		return
	}
	bts, err := proto.Marshal(&contract)
	if err != nil {
		log.Error(err)
		return
	}
	hostStream.Write(bts)
	hostStream.Close()
	downloaderStream.Write(bts)
	downloaderStream.Close()
}
