package node

import (
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
const DataVerifierRequestID = "/ffg/dvreq/1.0.0"

// DataVerifierProtocol wraps the protocols
type DataVerifierProtocol struct {
	Enabled   bool
	Node      *Node
	contMutex sync.Mutex
	contracts []DataContract
}

func (dqp *DataVerifierProtocol) onDataVerifierRequest(s network.Stream) {
	// s.Conn().RemotePeer() is the remote peer
	buf, err := ioutil.ReadAll(s)
	defer s.Close()
	if err != nil {
		s.Reset()
		log.Warn(err)
		return
	}

	env := DataQueryResponseEnvelope{}
	err = proto.Unmarshal(buf, &env)
	if err != nil {
		s.Reset()
		log.Warn(err)
		return
	}

	tmp := DataQueryResponse{}
	err = proto.Unmarshal(env.Payload, &tmp)
	if err != nil {
		s.Reset()
		log.Warn(err)
		return
	}

	// verify response
	if !dqp.Node.VerifyData(env.Payload, env.Signature, s.Conn().RemotePeer(), tmp.PubKey) {
		log.Warn("couldn't verify incoming data")
		return
	}

}

// NewDataVerifierProtocol returns a new instance and registers the handlers
func NewDataVerifierProtocol(n *Node) *DataVerifierProtocol {
	p := &DataVerifierProtocol{
		Enabled: true,
		Node:    n,
	}
	n.Host.SetStreamHandler(DataVerifierRequestID, p.onDataVerifierRequest)
	return p
}

// HandleIncomingBlock searches sealed txs from incoming blocks and checks for data contracts
func (dqp *DataVerifierProtocol) HandleIncomingBlock(block Block) {
	nodePubKeyBytes, err := dqp.Node.GetPublicKeyBytes()
	if err != nil {
		log.Fatal(err)
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
			if hexutil.Encode(dc.VerifierPubKey) == hexutil.Encode(nodePubKeyBytes) {
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
		return
	}
	downloaderID, err := peer.IDFromPublicKey(pubKeyDownloader)
	if err != nil {
		return
	}
	peerIDs = append(peerIDs, downloaderID)

	// data hoster
	pubKeyHost, err := crypto.PublicKeyFromRawHex(hexutil.Encode(contract.HostResponse.PubKey))
	if err != nil {
		return
	}

	hostID, err := peer.IDFromPublicKey(pubKeyHost)
	if err != nil {
		return
	}

	peerIDs = append(peerIDs, hostID)

	accessiblePeers := dqp.Node.FindPeers(peerIDs)
	if len(accessiblePeers) != 2 {
		log.Warn("Couldn't find both nodes")
		return
	}

	for _, addr := range accessiblePeers {
		if err := dqp.Node.Host.Connect(context.Background(), addr); err != nil {
			log.Warn("Unable to connect to remote host/downloader nodes ", err)
			return
		}
	}

	// connected to both nodes
	// start the communication

	// contract.RequesterNodePubKey
}
