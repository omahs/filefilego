package node

import (
	"context"
	"encoding/binary"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	log "github.com/sirupsen/logrus"
	proto "google.golang.org/protobuf/proto"
)

// BlockProtocolID represents the block protocol version
const BlockProtocolID = "/ffg/block/1.0.0"

// BlockHeightProtocolID is the protocol which returns the heighest block
const BlockHeightProtocolID = "/ffg/blockheight/1.0.0"

// RemotePeer represents a remote peer
type RemotePeer struct {
	Peer          peer.ID
	BlockStream   network.Stream
	Height        uint64
	Disconnect    bool
	BlockProtocol *BlockProtocol
}

func (rp *RemotePeer) ReadStream(breq BlockQueryRequest) {
	buf := []byte{}
	defer rp.Disconn()

	future := time.Now().Add(10 * time.Second)
	rp.BlockStream.SetDeadline(future)

	bts, _ := proto.Marshal(&breq)
	msg := make([]byte, 8+len(bts))
	binary.LittleEndian.PutUint64(msg, uint64(len(bts)))
	copy(msg[8:], bts)
	_, err := rp.BlockStream.Write(msg)
	if err != nil {
		rp.Disconn()
		// rp.BlockProtocol.CheckSyncingProgress()
		rp.BlockStream.Close() // this might not be required
		return
	}

	for {
		// 100 KB buffer

		chunk := make([]byte, 1024*100)
		n, err := rp.BlockStream.Read(chunk)

		if err != nil {
			// log.Warn("stream closed from remote peer: ", err)
			// rm.Close()

			return
		}
		defer rp.BlockStream.Close()

		if n == 0 {
			log.Println("read 0 bytes")
			continue
		}

		// copy the content of chunk to buffer
		cut := chunk[0:n]
		buf = append(buf, cut...)

		// we don't have the length prefix yet
		if len(buf) < 8 {
			continue
		}

		lengthPrefix := int64(binary.LittleEndian.Uint64(buf[0:8]))

		// if buffer contains the message length + content or more
		// 1. go on and cut up to the message content
		// 2. put back the remaining to the buffer for the next read
		if int64(len(buf)) >= lengthPrefix+8 {
			// bytes of the message
			dt := buf[8 : lengthPrefix+8]

			if int64(len(buf)) > lengthPrefix+8 {
				// cut the buff remaining and put in back to the buf
				buf = buf[lengthPrefix+9:]
			} else {
				// reset the buf
				buf = []byte{}
			}

			bqr := BlockQueryResponse{}
			if err := proto.Unmarshal(dt, &bqr); err != nil {
				log.Warn("error while unmarshalling data from stream: ", err)

				return
			}
			rp.Height = bqr.NodeHeight

			c <- bqr

			if rp.BlockProtocol.Node.BlockChain.GetHeight() > rp.Height {
				return
			}

			if bqr.Error {
				return
			}
		}
	}
}

// Disconnect
func (rp *RemotePeer) Disconn() {
	rp.Disconnect = true
}

// NewRemotePeer returns a new remotepeer
func NewRemotePeer(n *Node, pid peer.ID) (*RemotePeer, error) {
	rp := &RemotePeer{
		Peer:          pid,
		BlockProtocol: n.BlockProtocol,
	}
	s, err := n.Host.NewStream(context.Background(), rp.Peer, BlockProtocolID)
	if err != nil {
		rp.Disconn()
		return rp, err
	}
	rp.BlockStream = s
	return rp, nil
}

// BlockProtocol handles block exchange
type BlockProtocol struct {
	Node             *Node
	RemotePeers      []*RemotePeer
	RemotePeersMux   *sync.Mutex
	HeighestBlock    uint64
	HeighestBlockMux *sync.Mutex
	TmpHeight        uint64
	TmpHeightMux     *sync.Mutex
}

// NewBlockProtocol returns a new instance of BlockProtocol
func NewBlockProtocol(n *Node) *BlockProtocol {
	bp := &BlockProtocol{
		Node:             n,
		RemotePeers:      []*RemotePeer{},
		RemotePeersMux:   &sync.Mutex{},
		HeighestBlock:    0,
		HeighestBlockMux: &sync.Mutex{},
		TmpHeight:        0,
		TmpHeightMux:     &sync.Mutex{},
	}
	n.Host.SetStreamHandler(BlockProtocolID, bp.onBlockRequest)
	n.Host.SetStreamHandler(BlockHeightProtocolID, bp.onBlockHeightRequest)
	return bp
}

// GetNextTempHeight gets next seq
func (bp *BlockProtocol) GetNextTempHeight(node uint64) (start uint64, end uint64, _ bool) {
	bp.TmpHeightMux.Lock()
	defer bp.TmpHeightMux.Unlock()

	if node == 0 {
		start = bp.TmpHeight + 1

	} else {
		start = node + 1
	}
	end = start + 5

	if end > bp.Node.BlockChain.GetHeight() {
		end = bp.Node.BlockChain.GetHeight()
	}

	if node == 0 && start > bp.Node.BlockChain.GetHeight() {
		return start, end, false
	}

	return start, end, true
}

// SetHeighestBlock sets the heighest block
func (bp *BlockProtocol) SetHeighestBlock(h uint64) bool {
	bp.HeighestBlockMux.Lock()
	if h > bp.HeighestBlock {
		bp.HeighestBlock = h
	}
	bp.HeighestBlockMux.Unlock()
	return true
}

// GetHeighestBlock gets the heighest block
func (bp *BlockProtocol) GetHeighestBlock() uint64 {
	bp.HeighestBlockMux.Lock()
	h := bp.HeighestBlock
	bp.HeighestBlockMux.Unlock()
	return h
}

// AddRemotePeer ads a rp to the slice
func (bp *BlockProtocol) AddRemotePeer(rp *RemotePeer) bool {
	bp.RemotePeersMux.Lock()
	for _, v := range bp.RemotePeers {
		if v.Peer.String() == rp.Peer.String() {
			return false
		}
	}
	bp.RemotePeers = append(bp.RemotePeers, rp)
	bp.RemotePeersMux.Unlock()
	return true
}

// func (bp *BlockProtocol) CheckSyncingProgress() {
// 	availableConnectedPeers := false
// 	for _, v := range bp.RemotePeers {
// 		if !v.Disconnect {
// 			availableConnectedPeers = true
// 		}
// 	}

// 	if !availableConnectedPeers {
// 		bp.ClearRemotePeers()
// 		bp.Node.SetSyncing(false)
// 		log.Info("Batch of required blocks were downloaded")
// 	}
// }

// NextQuerySequence returns the next from, to
// func (bp *BlockProtocol) NextQuerySequence(peersHeight uint64, remotePeer *RemotePeer) (bqr BlockQueryRequest, _ error) {
// 	bp.MaxHeightAssignedMux.Lock()
// 	defer bp.MaxHeightAssignedMux.Unlock()

// 	// check if peers height is smaller than local node
// 	if peersHeight <= bp.Node.BlockChain.GetHeight() {
// 		remotePeer.Disconnect = true
// 		bp.CheckSyncingProgress()
// 		return bqr, errors.New("Remote is behind current chain")
// 	}

// 	if peersHeight <= bp.MaxHeightAssigned {
// 		remotePeer.Disconnect = true
// 		bp.CheckSyncingProgress()
// 		return bqr, errors.New("node " + remotePeer.Peer.String() + " is behind current blockchain")
// 	}

// 	if bp.MaxHeightAssigned == 0 {
// 		bqr.BlockNoFrom = bp.Node.BlockChain.GetHeight() + 1
// 	} else {
// 		bqr.BlockNoFrom = bp.MaxHeightAssigned + 1
// 	}

// 	next := bqr.BlockNoFrom + 2

// 	if next > peersHeight {
// 		next = peersHeight
// 	}

// 	bp.MaxHeightAssigned = next
// 	bqr.BlockNoTo = next

// 	return bqr, nil
// }

func (bp *BlockProtocol) onBlockRequest(s network.Stream) {
	// constantly read bytes from the stream
	buf := []byte{}

	for {
		// 10 KB buffer
		chunk := make([]byte, 1024*10)
		n, err := s.Read(chunk)

		if err != nil {
			log.Warn("err reading from remote peer stream: ", err)
			s.Close()
			log.Warn("closed stream locally")
			return
		}

		if n == 0 {
			continue
		}

		// copy the content of chunk to buffer
		cut := chunk[0:n]
		buf = append(buf, cut...)

		// we don't have the length prefix yet
		if len(buf) < 8 {
			continue
		}

		lengthPrefix := int64(binary.LittleEndian.Uint64(buf[0:8]))

		// if buffer contains the message length + content or more
		// 1. go on and cut up to the message content
		// 2. put back the remaining to the buffer for the next read
		if int64(len(buf)) >= lengthPrefix+8 {
			// bytes of the message
			dt := buf[8 : lengthPrefix+8]

			if int64(len(buf)) > lengthPrefix+8 {
				buf = buf[lengthPrefix+9:]
			} else {
				// reset the buf
				buf = []byte{}
			}

			bqr := BlockQueryRequest{}
			if err := proto.Unmarshal(dt, &bqr); err != nil {
				log.Warn("error while unmarshalling data from stream: ", err)
				s.Close()
				log.Warn("closed stream locally")
				return
			}

			bqResponse := BlockQueryResponse{}
			bqResponse.From = bqr.BlockNoFrom
			bqResponse.To = bqr.BlockNoTo
			nh := bp.Node.BlockChain.GetHeight()
			bqResponse.NodeHeight = nh
			if (bqr.BlockNoFrom > bqr.BlockNoTo) || (bqr.BlockNoTo > nh) {
				bqResponse.Error = true
			} else {
				blocks, err := bp.Node.BlockChain.GetBlocksByRange(bqr.BlockNoFrom, bqr.BlockNoTo)
				if err != nil {
					bqResponse.Error = true
				} else {
					bqResponse.Payload = blocks
				}
			}

			queryBts, _ := proto.Marshal(&bqResponse)
			msg := make([]byte, 8+len(queryBts))
			binary.LittleEndian.PutUint64(msg, uint64(len(queryBts)))
			copy(msg[8:], queryBts)

			_, err = s.Write(msg)
			if err != nil {
				log.Warn("error while writing to stream: ", err)
				s.Close()
				log.Warn("closed stream locally")
				return
			}
		}
	}
}

// AddRemotePeer adds a remote peer
// func (bp *BlockProtocol) AddRemotePeer(peerID peer.ID) bool {
// 	log.Println("Connecting to remote peer: ", peerID)
// 	for _, v := range bp.RemotePeers {
// 		if v.Peer == peerID {
// 			return false
// 		}
// 	}
// 	bp.RemotePeersMux.Lock()
// 	rp := NewRemotePeer(bp, peerID)
// 	go rp.Start()
// 	bp.RemotePeers = append(bp.RemotePeers, rp)
// 	bp.RemotePeersMux.Unlock()
// 	return true
// }

// ClearRemotePeers clears all peers
// func (bp *BlockProtocol) ClearRemotePeers() bool {
// 	bp.RemotePeersMux.Lock()
// 	for i := 0; i < len(bp.RemotePeers); i++ {
// 		if !bp.RemotePeers[i].Disconnect {
// 			bp.RemotePeers[i].BlockStream.Close()
// 		}
// 		bp.RemotePeers[i] = &RemotePeer{}
// 	}
// 	bp.MaxHeightAssigned = 0
// 	bp.RemotePeers = []*RemotePeer{}
// 	bp.RemotePeersMux.Unlock()
// 	return true
// }

func (bp *BlockProtocol) onBlockHeightRequest(s network.Stream) {
	tmp := NodeHeightResponse{
		NodeHeight: bp.Node.BlockChain.GetHeight(),
	}
	bts, _ := proto.Marshal(&tmp)
	msg := make([]byte, 8+len(bts))
	binary.LittleEndian.PutUint64(msg, uint64(len(bts)))
	copy(msg[8:], bts)
	_, err := s.Write(msg)
	if err != nil {
		s.Close()
		log.Warn(err)
		return
	}
}
