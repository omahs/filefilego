package node

import (
	"context"
	"io/ioutil"
	"sync"

	"github.com/golang/protobuf/proto"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	log "github.com/sirupsen/logrus"
)

// DataQueryRequestID represents the req protocol version
// const DataQueryRequestID = "/ffg/dqrequest/1.0.0"

// DataQueryResponseID represents the response protocol version
const DataQueryResponseID = "/ffg/dqresponse/1.0.0"

// DataQueryProtocol wraps the data query protocols and handlers
type DataQueryProtocol struct {
	Node             *Node
	queryHistory     map[string]DataQueryRequest
	queryHistoryMux  *sync.Mutex
	queryResponse    map[string][]DataQueryResponse
	queryResponseMux *sync.Mutex
}

// PutQueryHistory put into history
func (dqp *DataQueryProtocol) PutQueryHistory(key string, val DataQueryRequest) {
	dqp.queryHistoryMux.Lock()
	defer dqp.queryHistoryMux.Unlock()
	dqp.queryHistory[key] = val

}

// GetQueryHistory gets a val from history
func (dqp *DataQueryProtocol) GetQueryHistory(key string) (DataQueryRequest, bool) {
	dqp.queryHistoryMux.Lock()
	defer dqp.queryHistoryMux.Unlock()
	v, ok := dqp.queryHistory[key]
	return v, ok

}

// PutQueryResponse put into responses
func (dqp *DataQueryProtocol) PutQueryResponse(key string, val DataQueryResponse) {
	dqp.queryResponseMux.Lock()
	defer dqp.queryResponseMux.Unlock()
	tmp, _ := dqp.queryResponse[key]
	idx := -1
	for i, v := range tmp {
		if v.FromPeerAddr == val.FromPeerAddr {
			idx = i
		}
	}
	// if answer from same nodes, just replace
	if idx > -1 {
		tmp[idx] = val

	} else {
		tmp = append(tmp, val)
	}
	dqp.queryResponse[key] = tmp

}

// GetQueryResponse gets a val from responses
func (dqp *DataQueryProtocol) GetQueryResponse(key string) ([]DataQueryResponse, bool) {
	dqp.queryResponseMux.Lock()
	defer dqp.queryResponseMux.Unlock()
	v, ok := dqp.queryResponse[key]
	return v, ok
}

// func (dqp *DataQueryProtocol) onDataQueryRequest(s network.Stream) {

// 	// s.Conn().RemotePeer() is the remote peer

// 	buf, err := ioutil.ReadAll(s)
// 	if err != nil {
// 		s.Reset()
// 		log.Println(err)
// 		return
// 	}
// 	s.Close()
// 	fmt.Println(buf)
// }

// NewDataQueryProtocol returns a new instance and registers the handlers
func NewDataQueryProtocol(n *Node) *DataQueryProtocol {
	p := &DataQueryProtocol{
		Node:             n,
		queryHistoryMux:  &sync.Mutex{},
		queryResponseMux: &sync.Mutex{},
		queryHistory:     make(map[string]DataQueryRequest),
		queryResponse:    make(map[string][]DataQueryResponse),
	}
	// n.Host.SetStreamHandler(DataQueryRequestID, p.onDataQueryRequest)
	n.Host.SetStreamHandler(DataQueryResponseID, p.onDataQueryResponse)
	return p
}

func (dqp *DataQueryProtocol) onDataQueryResponse(s network.Stream) {
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

	// check if this node has requested
	_, ok := dqp.GetQueryHistory(tmp.Hash)
	if !ok {
		return
	}

	// need the sig for later verification
	tmp.Signature = env.Signature
	dqp.PutQueryResponse(tmp.Hash, tmp)

	// pbkey, err := crypto.UnmarshalPublicKey(tmp.PubKey)
	// if err != nil {
	// 	log.Warn(err)
	// }
	// pb, err := pbkey.Raw()
	// addr := crypto.PublicToAddress(pb)
	// log.Println("Remote peer who hosts the file has the following address: ", addr)

}

// SendDataQueryResponse sends back the response to initiator
func (dqp *DataQueryProtocol) SendDataQueryResponse(addrInfo *peer.AddrInfo, payload *DataQueryResponseEnvelope) bool {
	s, err := dqp.Node.Host.NewStream(context.Background(), addrInfo.ID, DataQueryResponseID)
	if err != nil {
		log.Warn(err)
		return false
	}
	defer s.Close()

	bts, err := proto.Marshal(payload)
	if err != nil {
		log.Warn(err)
		return false
	}

	_, err = s.Write(bts)
	if err != nil {
		log.Println(err)
		s.Reset()
		return false
	}

	return true
}
