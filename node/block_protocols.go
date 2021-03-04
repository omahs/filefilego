package node

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/filefilego/filefilego/common/hexutil"
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
	PeerBlockHeight uint64
	Peer            peer.ID
	BlockProtocol   *BlockProtocol
	BlockStream     network.Stream
	Disconnect      bool
}

// ReadStream reads underlying stream
func (rp *RemotePeer) ReadStream() {
	buf := []byte{}

	for {
		// 100 KB buffer

		future := time.Now().Add(10 * time.Second)
		rp.BlockStream.SetDeadline(future)

		chunk := make([]byte, 1024*100)
		n, err := rp.BlockStream.Read(chunk)

		if err != nil {
			// log.Warn("stream closed from remote peer: ", err)
			// rm.Close()
			rp.Disconnect = true
			rp.BlockProtocol.CheckSyncingProgress()
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
				rp.Disconnect = true
				rp.BlockProtocol.CheckSyncingProgress()
				return
			}

			rp.PeerBlockHeight = bqr.NodeHeight

			// if rp.PeerBlockHeight > rm.BlockService.GetHeighestBlock() {
			// 	rm.BlockService.AddHeighestBlock(pl.BlockQueryResponse.NodeHeight)
			// }

			if len(bqr.Payload) > 0 {
				for _, block := range bqr.Payload {
					log.Println("Downloaded Block:\t", hexutil.Encode(block.Hash), " From Peer:\t", rp.Peer.String())
					err := rp.BlockProtocol.Node.BlockChain.AddBlockPool(*block)
					if err != nil {
						log.Warn("Adding block to blockchain: ", err)
					}
				}
			}

			// add the next value to the channel
			blockRequest, err := rp.BlockProtocol.NextQuerySequence(rp.PeerBlockHeight, rp)
			if err != nil {
				return
			}
			rp.Query(blockRequest.BlockNoFrom, blockRequest.BlockNoTo)
		}

	}
}

// Query queries remote peer
func (rp *RemotePeer) Query(from, to uint64) {
	bqr := BlockQueryRequest{
		BlockNoFrom: from,
		BlockNoTo:   to,
	}
	bts, _ := proto.Marshal(&bqr)
	msg := make([]byte, 8+len(bts))
	binary.LittleEndian.PutUint64(msg, uint64(len(bts)))
	copy(msg[8:], bts)
	_, err := rp.BlockStream.Write(msg)
	if err != nil {
		rp.Disconnect = true
		rp.BlockProtocol.CheckSyncingProgress()
		rp.BlockStream.Close() // this might not be required
	}
}

// Start the process
func (rp *RemotePeer) Start() {
	stream, err := rp.BlockProtocol.Node.Host.NewStream(context.Background(), rp.Peer, BlockHeightProtocolID)
	if err != nil {
		rp.Disconnect = true
		rp.BlockProtocol.CheckSyncingProgress()
		return
	}
	defer stream.Close()
	// just write something to trigger the remote protocol
	_, err = stream.Write([]byte("0"))
	if err != nil {
		rp.Disconnect = true
		rp.BlockProtocol.CheckSyncingProgress()
		return
	}

	buf := []byte{}
	nhr := NodeHeightResponse{}
	for {
		// 10 KB buffer
		chunk := make([]byte, 1024*10)
		n, err := stream.Read(chunk)

		if err != nil {
			log.Warn(err)
			rp.Disconnect = true
			rp.BlockProtocol.CheckSyncingProgress()
			return
		}

		if n == 0 {
			continue
		}

		cut := chunk[0:n]
		buf = append(buf, cut...)

		if len(buf) < 8 {
			continue
		}

		lengthPrefix := int64(binary.LittleEndian.Uint64(buf[0:8]))

		if int64(len(buf)) >= lengthPrefix+8 {
			dt := buf[8 : lengthPrefix+8]
			if int64(len(buf)) > lengthPrefix+8 {
				buf = buf[lengthPrefix+9:]
			} else {
				buf = []byte{}
			}

			if err := proto.Unmarshal(dt, &nhr); err != nil {
				log.Warn("error while unmarshalling data from stream: ", err)
				rp.Disconnect = true
				rp.BlockProtocol.CheckSyncingProgress()
				return
			}
			break
		}

	}

	// Remote Peer blockheight
	rp.PeerBlockHeight = nhr.NodeHeight

	rp.BlockStream, err = rp.BlockProtocol.Node.Host.NewStream(context.Background(), rp.Peer, BlockProtocolID)

	if err != nil {
		log.Warn(err)
		rp.Disconnect = true
		rp.BlockProtocol.CheckSyncingProgress()
		return
	}

	blockRequest, err := rp.BlockProtocol.NextQuerySequence(rp.PeerBlockHeight, rp)
	if err != nil {
		log.Warn(err)
		return
	}

	go rp.Query(blockRequest.BlockNoFrom, blockRequest.BlockNoTo)

	rp.ReadStream()
}

// NewRemotePeer returns a new remotepeer
func NewRemotePeer(bp *BlockProtocol, pid peer.ID) *RemotePeer {
	rp := &RemotePeer{
		Peer:          pid,
		BlockProtocol: bp,
	}
	return rp
}

// BlockProtocol handles block exchange
type BlockProtocol struct {
	Node                 *Node
	RemotePeers          []*RemotePeer
	RemotePeersMux       *sync.Mutex
	MaxHeightAssigned    uint64
	MaxHeightAssignedMux *sync.Mutex
}

// NewBlockProtocol returns a new instance of BlockProtocol
func NewBlockProtocol(n *Node) *BlockProtocol {
	bp := &BlockProtocol{
		Node:                 n,
		RemotePeers:          []*RemotePeer{},
		RemotePeersMux:       &sync.Mutex{},
		MaxHeightAssigned:    0,
		MaxHeightAssignedMux: &sync.Mutex{},
	}
	n.Host.SetStreamHandler(BlockProtocolID, bp.onBlockRequest)
	n.Host.SetStreamHandler(BlockHeightProtocolID, bp.onBlockHeightRequest)
	return bp
}

func (bp *BlockProtocol) CheckSyncingProgress() {
	availableConnectedPeers := false
	for _, v := range bp.RemotePeers {
		if !v.Disconnect {
			availableConnectedPeers = true
		}
	}

	if !availableConnectedPeers {
		bp.ClearRemotePeers()
		bp.Node.SetSyncing(false)
		log.Info("Batch of required blocks were downloaded")
	}
}

// NextQuerySequence returns the next from, to
func (bp *BlockProtocol) NextQuerySequence(peersHeight uint64, remotePeer *RemotePeer) (bqr BlockQueryRequest, _ error) {
	bp.MaxHeightAssignedMux.Lock()
	defer bp.MaxHeightAssignedMux.Unlock()

	// check if peers height is smaller than local node
	if peersHeight <= bp.Node.BlockChain.GetHeight() {
		remotePeer.Disconnect = true
		bp.CheckSyncingProgress()
		return bqr, errors.New("Remote is behind current chain")
	}

	if peersHeight <= bp.MaxHeightAssigned {
		remotePeer.Disconnect = true
		bp.CheckSyncingProgress()
		return bqr, errors.New("node " + remotePeer.Peer.String() + " is behind current blockchain")
	}

	if bp.MaxHeightAssigned == 0 {
		bqr.BlockNoFrom = bp.Node.BlockChain.GetHeight() + 1
	} else {
		bqr.BlockNoFrom = bp.MaxHeightAssigned + 1
	}

	next := bqr.BlockNoFrom + 2

	if next > peersHeight {
		next = peersHeight
	}

	bp.MaxHeightAssigned = next
	bqr.BlockNoTo = next

	return bqr, nil
}

func (bp *BlockProtocol) onBlockRequest(s network.Stream) {
	// constantly read bytes from the stream
	buf := []byte{}

	for {
		// 100 KB buffer
		chunk := make([]byte, 1024*100)
		n, err := s.Read(chunk)

		if err != nil {
			// log.Warn("Stream closed by remote peer: ", err)
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
				return
			}

			bqResponse := BlockQueryResponse{}
			bqResponse.NodeHeight = bp.Node.BlockChain.GetHeight()
			bqResponse.To = bqr.BlockNoTo
			blocks, err := bp.Node.BlockChain.GetBlocksByRange(bqr.BlockNoFrom, bqr.BlockNoTo)
			if err != nil {
				bqResponse.Error = true
			} else {
				bqResponse.From = bqr.BlockNoFrom
				bqResponse.Payload = blocks
			}

			queryBts, _ := proto.Marshal(&bqResponse)
			msg := make([]byte, 8+len(queryBts))
			binary.LittleEndian.PutUint64(msg, uint64(len(queryBts)))
			copy(msg[8:], queryBts)

			_, err = s.Write(msg)
			if err != nil {
				log.Warn("error while writing stream: ", err)
			}
		}
	}
}

// AddRemotePeer adds a remote peer
func (bp *BlockProtocol) AddRemotePeer(peerID peer.ID) bool {
	log.Println("Connecting to remote peer: ", peerID)
	for _, v := range bp.RemotePeers {
		if v.Peer == peerID {
			return false
		}
	}
	bp.RemotePeersMux.Lock()
	rp := NewRemotePeer(bp, peerID)
	go rp.Start()
	bp.RemotePeers = append(bp.RemotePeers, rp)
	bp.RemotePeersMux.Unlock()
	return true
}

// ClearRemotePeers clears all peers
func (bp *BlockProtocol) ClearRemotePeers() bool {
	bp.RemotePeersMux.Lock()
	for i := 0; i < len(bp.RemotePeers); i++ {
		if !bp.RemotePeers[i].Disconnect {
			bp.RemotePeers[i].BlockStream.Close()
		}
		bp.RemotePeers[i] = &RemotePeer{}
	}
	bp.MaxHeightAssigned = 0
	bp.RemotePeers = []*RemotePeer{}
	bp.RemotePeersMux.Unlock()
	return true
}

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
		s.Reset()
		log.Warn(err)
		return
	}
}
