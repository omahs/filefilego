package node

import (
	"bytes"
	"container/list"
	"context"
	"io"
	"io/ioutil"
	"os"
	"path"
	"sync"
	"time"

	"github.com/boltdb/bolt"
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/crypto"
	"github.com/golang/protobuf/proto"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	log "github.com/sirupsen/logrus"
)

// DataVerifierRequestID represents a request to get interested verifiers
const DataVerifierRequestID = "/ffg/dv_verifier_req/1.0.0"

// NodeRangeDataRequestID used to allow downloader ask for range of bytes
const NodeRangeDataRequestID = "/ffg/dv_range_data_req/1.0.0"

// KeyRequestFromVerifierID this protocol is runned by verifier
const KeyRequestFromVerifierID = "/ffg/dv_key_req/1.0.0"

type ContractTransaction struct {
	tx        Transaction
	timestamp time.Time
}

// DataVerificationProtocol wraps the protocols
type DataVerificationProtocol struct {
	VerifierMode bool
	Node         *Node
	contMutex    sync.Mutex
	contracts    map[string]ContractTransaction
}

// GetContract returns a contract that has been validated before
func (dqp *DataVerificationProtocol) GetContract(hash string) (dataContract DataContract, _ bool) {
	dqp.contMutex.Lock()
	defer dqp.contMutex.Unlock()

	c, ok := dqp.contracts[hash]
	if !ok {
		return dataContract, false
	}

	dcs, _ := dqp.extractContractsFromTransaction(&c.tx)

	for _, dc := range dcs {
		bts, err := proto.Marshal(dc)
		if err != nil {
			log.Error(err)
			continue
		}

		hashContract, _ := hexutil.Decode(hash)
		if bytes.Equal(crypto.Sha256HashHexBytes(bts), hashContract) {
			dataContract = *dc
			break
		}

	}

	return dataContract, true
}

func (dqp *DataVerificationProtocol) AddContract(contract DataContract, tx Transaction) bool {
	dqp.contMutex.Lock()
	defer dqp.contMutex.Unlock()
	bts, _ := proto.Marshal(&contract)
	contractHash := hexutil.Encode(crypto.Sha256HashHexBytes(bts))
	_, ok := dqp.contracts[contractHash]
	if ok {
		// contract already exists in the map
		return false
	}
	dqp.contracts[contractHash] = ContractTransaction{
		tx:        tx,
		timestamp: time.Now(),
	}
	return true
}

// onDataVerifierRequest handles one contract at a time using tx and hash of contract
func (dqp *DataVerificationProtocol) onDataVerifierRequest(s network.Stream) {
	buf, err := ioutil.ReadAll(s)
	defer s.Close()
	if err != nil {
		s.Reset()
		log.Error(err)
		return
	}

	dvrp := DataVerifierRequestPayload{}

	err = proto.Unmarshal(buf, &dvrp)
	if err != nil {
		log.Error(err)
		return
	}

	tx := dvrp.Transaction

	dcs, ok := dqp.extractContractsFromTransaction(tx)
	if !ok {
		log.Warn("transaction is not valid")
		return
	}

	foundContract := DataContract{}

	for _, dc := range dcs {

		bts, err := proto.Marshal(dc)
		if err != nil {
			log.Error(err)
			continue
		}

		if bytes.Equal(crypto.Sha256HashHexBytes(bts), dvrp.ContractHash) {
			foundContract = *dc
			break
		}

	}

	// hostID, downloaderID, ok := dqp.verifyContract(dc, &tx)
	_, _, ok = dqp.verifyContract(foundContract, tx)
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

	if !bytes.Equal(rawBitsVerifier, foundContract.VerifierPubKey) {
		log.Warn("verifier's pubkey mismatch")
		return
	}

	dqp.AddContract(foundContract, *tx)

	// find is current node is downloader or hoster
	currentNodePubKeyRawBytes, _ := dqp.Node.GetPublicKeyBytes()
	if bytes.Equal(foundContract.RequesterNodePubKey, currentNodePubKeyRawBytes) {
		log.Println("I am the downloader")
	} else if bytes.Equal(foundContract.HostResponse.PubKey, currentNodePubKeyRawBytes) {
		log.Println("I am the hoster")
	}
}

func (dqp *DataVerificationProtocol) onKeyRequestFromVerifier(s network.Stream) {

}

func (dqp *DataVerificationProtocol) GetFileNodesFromContract(contract DataContract) (files []NodeToFileInfo, _ error) {
	availableNodes := []ChanNode{}

	dqp.Node.BlockChain.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(nodesBucket))
		for _, v := range contract.HostResponse.Nodes {
			if len(v) == 0 {
				continue
			}

			bts := b.Get(v)
			if bts == nil {
				continue
			}
			tmp := ChanNode{}
			proto.Unmarshal(bts, &tmp)

			// we accept only entries, dirs and files
			if tmp.NodeType == ChanNodeType_ENTRY || tmp.NodeType == ChanNodeType_DIR || tmp.NodeType == ChanNodeType_FILE {
				availableNodes = append(availableNodes, tmp)
			}
		}

		return nil
	})

	queue := list.New()
	for _, reqNode := range availableNodes {
		queue.PushBack(reqNode)
	}

	err := dqp.Node.BlockChain.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(nodesBucket))
		for queue.Len() > 0 {
			el := queue.Front()
			tmp := el.Value.(ChanNode)
			if tmp.NodeType == ChanNodeType_ENTRY || tmp.NodeType == ChanNodeType_DIR {
				// get its childs and append to queue accordingly

				c := tx.Bucket([]byte(nodeNodesBucket)).Cursor()
				prefix := []byte(tmp.Hash)
				for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
					// fmt.Printf("key=%s, value=%s\n", k, v)
					val := b.Get(v)
					if val == nil {
						continue
					}

					tmpNode := ChanNode{}
					err := proto.Unmarshal(val, &tmpNode)
					if err != nil {
						return err
					}
					queue.PushBack(tmpNode)
				}

			} else {
				size, _ := hexutil.DecodeUint64(tmp.Size)
				finfo := NodeToFileInfo{
					Name: tmp.Name,
					Hash: tmp.Hash,
					Size: size,
				}
				files = append(files, finfo)
			}
			queue.Remove(el)
		}
		return nil
	})

	if err != nil {
		return files, err
	}

	return files, nil
}

func (dqp *DataVerificationProtocol) onNodeRangeDataRequest(s network.Stream) {
	buf, err := ioutil.ReadAll(s)
	defer s.Close()
	if err != nil {
		s.Reset()
		log.Error(err)
		return
	}

	nrdr := NodeRangeDataRequest{}

	err = proto.Unmarshal(buf, &nrdr)
	if err != nil {
		log.Error(err)
		return
	}

	contract, ok := dqp.GetContract(hexutil.Encode(nrdr.ContractHash))
	if !ok {
		log.Error("contract not found, make sure it has been negotiated before requesting data")
		return
	}

	fileNodes, _ := dqp.GetFileNodesFromContract(contract)

	for _, fn := range fileNodes {
		if fn.Hash == hexutil.Encode(nrdr.ContractHash) {
			fileItem, err := dqp.Node.BinLayerEngine.GetBinaryItem(fn.Hash)
			if err != nil {
				log.Error("couldn't find binary in binlayer")
				return
			}
			bitem := BinlayerBinaryItem{}
			err = proto.Unmarshal(fileItem, &bitem)
			if err != nil {
				log.Error("couldn't find binary in binlayer")
				return
			}

			readFromFile := path.Join(dqp.Node.BinLayerEngine.Path, bitem.FilePath, fn.Hash)
			infile, err := os.Open(readFromFile)
			if err != nil {
				log.Error("couldn't open binlayer file" + err.Error())
				return
			}

			buf := make([]byte, 1024)
			for {
				n, err := infile.Read(buf)
				if n > 0 {
					s.Write(buf[:n])
				}

				if err == io.EOF {
					break
				}

				if err != nil {
					log.Printf("Read %d bytes: %v", n, err)
					break
				}
			}

			// already found, just break
			break
		}
	}

}

// DataVerificationProtocol returns a new instance and registers the handlers
func NewDataVerificationProtocol(n *Node) *DataVerificationProtocol {
	p := &DataVerificationProtocol{
		Node:      n,
		contMutex: sync.Mutex{},
		contracts: make(map[string]ContractTransaction),
	}
	n.Host.SetStreamHandler(DataVerifierRequestID, p.onDataVerifierRequest)
	n.Host.SetStreamHandler(NodeRangeDataRequestID, p.onNodeRangeDataRequest)

	return p
}

// EnableVerifierMode enables verification mode and registers protocols
func (dqp *DataVerificationProtocol) EnableVerifierMode() {
	dqp.VerifierMode = true
	dqp.Node.Host.SetStreamHandler(KeyRequestFromVerifierID, dqp.onKeyRequestFromVerifier)
}

// extractContractFromTransaction extracts a valid contract
func (dqp *DataVerificationProtocol) extractContractsFromTransaction(tx *Transaction) (dcs []*DataContract, _ bool) {
	if len(tx.Data) == 0 {
		return dcs, false
	}
	tpl := TransactionDataPayload{}
	err := proto.Unmarshal(tx.Data, &tpl)
	if err != nil {
		return dcs, false
	}

	dce := DataContractsEnvelop{}

	if tpl.Type == TransactionDataPayloadType_DATA_CONTRACT {
		err := proto.Unmarshal(tpl.Payload, &dce)
		if err != nil {
			return dcs, false
		}
		dcs = append(dcs, dce.Contracts...)
	}

	return dcs, true
}

// HandleIncomingBlock searches sealed txs from incoming blocks and checks for data contracts
func (dqp *DataVerificationProtocol) HandleIncomingBlock(block Block) {
	nodePubKeyBytes, err := dqp.Node.GetPublicKeyBytes()
	if err != nil {
		log.Error(err)
		return
	}
	for _, tx := range block.Transactions {
		dcs, ok := dqp.extractContractsFromTransaction(tx)
		if !ok {
			continue
		}
		for _, contract := range dcs {
			dc := *contract
			// handle this data contract
			if bytes.Equal(dc.VerifierPubKey, nodePubKeyBytes) {
				if dqp.coordinate(dc, tx) {
					dqp.AddContract(dc, *tx)
				} else {
					log.Warn("coordination failed")
				}
			}
		}

	}
}

func (dqp *DataVerificationProtocol) verifyContract(contract DataContract, tx *Transaction) (hostID peer.ID, downloaderID peer.ID, _ bool) {

	// check validity of verifier in contract
	isValidVerifier := false
	for _, v := range GetBlockchainSettings().Verifiers {
		if v.DataVerifier {
			localVerifirPk, _ := hexutil.Decode(v.PublicKey)
			if bytes.Equal(localVerifirPk, contract.VerifierPubKey) {
				isValidVerifier = true
				break
			}
		}
	}
	if !isValidVerifier {
		log.Error("invalid verifier")
		return hostID, downloaderID, false
	}

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
	contract.HostResponse.Signature = sig

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
func (dqp *DataVerificationProtocol) coordinate(contract DataContract, tx *Transaction) bool {
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

	contBits, _ := proto.Marshal(&contract)
	chash := crypto.Sha256HashHexBytes(contBits)
	tvrp := DataVerifierRequestPayload{
		Transaction:  tx,
		ContractHash: chash,
	}

	bts, err := proto.Marshal(&tvrp)
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
