package node

import (
	"context"
	"fmt"
	"io/ioutil"

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
	Node *Node
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

func (dqp *DataQueryProtocol) onDataQueryResponse(s network.Stream) {
	// s.Conn().RemotePeer() is the remote peer
	buf, err := ioutil.ReadAll(s)
	defer s.Close()
	if err != nil {
		s.Reset()
		log.Warn(err)
		return
	}

	tmp := DataQueryResponse{}
	err = proto.Unmarshal(buf, &tmp)
	if err != nil {
		s.Reset()
		log.Warn(err)
		return
	}

	fmt.Println("DataQueryResponse came back to this node: ", tmp)
}

// NewDataQueryProtocol returns a new instance and registers the handlers
func NewDataQueryProtocol(n *Node) *DataQueryProtocol {
	p := &DataQueryProtocol{
		Node: n,
	}
	// n.Host.SetStreamHandler(DataQueryRequestID, p.onDataQueryRequest)
	n.Host.SetStreamHandler(DataQueryResponseID, p.onDataQueryResponse)
	return p
}

// SendDataQueryResponse sends back the response to initiator
func (dqp *DataQueryProtocol) SendDataQueryResponse(addrInfo *peer.AddrInfo, payload *DataQueryResponse) bool {
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
