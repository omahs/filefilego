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

	tx := Transaction{}
	err = proto.Unmarshal(buf, &tx)
	if err != nil {
		log.Error(err)
		return
	}

	dc, ok := dqp.extractContractFromTransaction(&tx)
	if !ok {
		log.Warn("transaction is not valid")
		return
	}

	// hostID, downloaderID, ok := dqp.verifyContract(dc, &tx)
	_, _, ok = dqp.verifyContract(dc, &tx)
	if !ok {
		log.Warn("contract is invalid")
		return
	}

	// check if request came from verifier
	pPubKeyVerifier, err := s.Conn().RemotePeer().ExtractPublicKey()
	if err != nil {
		log.Error("couldnt get public key of remote peer in onDataVerifierRequest", err)
		return
	}

	rawBitsVerifier, err := pPubKeyVerifier.Raw()
	if err != nil {

		return
	}

	if !bytes.Equal(rawBitsVerifier, dc.VerifierPubKey) {
		log.Warn("verifier's pubkey mismatch")
		return
	}

	dqp.contMutex.Lock()
	dqp.contracts = append(dqp.contracts, dc)
	dqp.contMutex.Unlock()

	// find is current node is downloader or hoster
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

// extractContractFromTransaction extracts a valid contract
func (dqp *DataVerifierProtocol) extractContractFromTransaction(tx *Transaction) (dc DataContract, _ bool) {
	if len(tx.Data) == 0 {
		return dc, false
	}
	tpl := TransactionDataPayload{}
	err := proto.Unmarshal(tx.Data, &tpl)
	if err != nil {
		return dc, false
	}

	if tpl.Type == TransactionDataPayloadType_DATA_CONTRACT {
		err := proto.Unmarshal(tpl.Payload, &dc)
		if err != nil {
			return dc, false
		}
	}

	return dc, true
}

// HandleIncomingBlock searches sealed txs from incoming blocks and checks for data contracts
func (dqp *DataVerifierProtocol) HandleIncomingBlock(block Block) {
	nodePubKeyBytes, err := dqp.Node.GetPublicKeyBytes()
	if err != nil {
		log.Error(err)
		return
	}
	for _, tx := range block.Transactions {
		dc, ok := dqp.extractContractFromTransaction(tx)
		if !ok {
			continue
		}

		// handle this data contract
		if bytes.Equal(dc.VerifierPubKey, nodePubKeyBytes) {
			if dqp.coordinate(dc, tx) {
				dqp.contMutex.Lock()
				dqp.contracts = append(dqp.contracts, dc)
				dqp.contMutex.Unlock()
			} else {
				log.Warn("coordination failed")
			}
		}
	}
}

func (dqp *DataVerifierProtocol) verifyContract(contract DataContract, tx *Transaction) (hostID peer.ID, downloaderID peer.ID, _ bool) {

	// verify transaction
	ok, _ := dqp.Node.BlockChain.IsValidTransaction(*tx)
	if !ok {
		log.Error("invalid transaction")
		return hostID, downloaderID, false
	}

	// downloader
	pubKeyDownloader, err := crypto.PublicKeyFromRawHex(hexutil.Encode(contract.RequesterNodePubKey))
	if err != nil {
		log.Error("unable to get public key of downloader: ", err)
		return hostID, downloaderID, false
	}
	downloaderID, err = peer.IDFromPublicKey(pubKeyDownloader)
	if err != nil {
		log.Error("unable to get downloader ID from pubkey", err)
		return hostID, downloaderID, false
	}

	// data hoster
	pubKeyHost, err := crypto.PublicKeyFromRawHex(hexutil.Encode(contract.HostResponse.PubKey))
	if err != nil {
		log.Error("unable to get public key of data hoster: ", err)
		return hostID, downloaderID, false
	}

	hostID, err = peer.IDFromPublicKey(pubKeyHost)
	if err != nil {
		log.Error("unable to get host ID from pubkey", err)
		return hostID, downloaderID, false
	}

	// verify if the host response is ok
	sig := contract.HostResponse.Signature
	contract.HostResponse.Signature = []byte{}
	dt, _ := proto.Marshal(contract.HostResponse)
	ok = dqp.Node.VerifyData(dt, sig, hostID, contract.HostResponse.PubKey)

	if !ok {
		log.Warn("couldn't verify host's response")
		return hostID, downloaderID, false
	}

	txValue, _ := hexutil.DecodeBig(tx.Value)
	totalFeesRequired, err := hexutil.DecodeBig(contract.HostResponse.TotalFeesRequired)
	if err != nil {
		log.Error("invalid TotalFeesRequired value in the contract")
		return hostID, downloaderID, false
	}

	if txValue.Cmp(totalFeesRequired) == -1 {
		log.Warn("transaction value amount is smaller than TotalFeesRequired")
		return hostID, downloaderID, false
	}

	return hostID, downloaderID, true

}

// coordinate validates the tx and contract and sends the tx to the host and downloader
func (dqp *DataVerifierProtocol) coordinate(contract DataContract, tx *Transaction) bool {
	log.Println("executing data contract")
	hostID, downloaderID, ok := dqp.verifyContract(contract, tx)
	if !ok {
		log.Warn("contract invalid")
		return false
	}

	peerIDs := []peer.ID{}
	peerIDs = append(peerIDs, hostID, downloaderID)

	accessiblePeers := dqp.Node.FindPeers(peerIDs)
	if len(accessiblePeers) != 2 {
		log.Warn("couldn't find both nodes")
		return false
	}

	for _, addr := range accessiblePeers {
		if err := dqp.Node.Host.Connect(context.Background(), addr); err != nil {
			log.Warn("unable to connect to remote host/downloader nodes ", err)
			return false
		}
	}

	// connect to hostID
	hostStream, err := dqp.Node.Host.NewStream(context.Background(), hostID, DataVerifierRequestID)
	if err != nil {
		log.Warn("unable to connect to data hoster: ", err)
		return false
	}
	downloaderStream, err := dqp.Node.Host.NewStream(context.Background(), downloaderID, DataVerifierRequestID)
	if err != nil {
		log.Warn("unable to connect to downloader: ", err)
		return false
	}
	bts, err := proto.Marshal(tx)
	if err != nil {
		log.Error(err)
		return false
	}
	hostStream.Write(bts)
	hostStream.Close()
	downloaderStream.Write(bts)
	downloaderStream.Close()
	return true
}
