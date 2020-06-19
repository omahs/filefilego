package node

import (
	"context"
	"encoding/binary"
	"errors"
	"sort"
	"sync"

	log "github.com/sirupsen/logrus"

	proto "github.com/golang/protobuf/proto"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"gitlab.com/younixcc/filefilego/common/hexutil"
)

var (
	BlockRequiredGlobalMutex = sync.Mutex{}
)

type BlockService struct {
	Node              *Node
	RemoteHosts       []*RemoteHost
	RemoteHostsMux    *sync.Mutex
	HeighestBlock     uint64
	HeighestBlockMux  *sync.Mutex
	RequiredBlocks    []uint64
	RequiredBlocksMux *sync.Mutex
}

type RemoteHost struct {
	RhMux        *sync.Mutex
	HeightMux    *sync.Mutex
	Height       uint64
	PeerID       peer.ID
	Stream       network.Stream
	BlockService *BlockService
	// RW     *bufio.ReadWriter
}

const BlockServiceID = "/ffg/block/1.0.0"

func NewBlockService(n *Node) *BlockService {
	bs := BlockService{
		Node:              n,
		RemoteHosts:       []*RemoteHost{},
		HeighestBlockMux:  &sync.Mutex{},
		RequiredBlocksMux: &sync.Mutex{},
		RemoteHostsMux:    &sync.Mutex{}}
	bs.Node.Host.SetStreamHandler(BlockServiceID, bs.BlockHandler)
	return &bs
}

// AddHeight
func (rm *RemoteHost) AddHeight(h uint64) {
	rm.HeightMux.Lock()
	rm.Height = h
	rm.HeightMux.Unlock()
}

// GetHeigh
func (rm *RemoteHost) GetHeight() uint64 {
	rm.HeightMux.Lock()
	height := rm.Height
	rm.HeightMux.Unlock()
	return height
}

// ClearRequiredBlock clears everything
func (bs *BlockService) ClearRequiredBlock() {
	bs.RequiredBlocksMux.Lock()
	bs.RequiredBlocks = []uint64{}
	bs.RequiredBlocksMux.Unlock()
}

// AddRequiredBlock adds a blockno to the required blocks
func (bs *BlockService) AddRequiredBlock(h uint64) {
	bs.RequiredBlocksMux.Lock()
	defer bs.RequiredBlocksMux.Unlock()
	for _, v := range bs.RequiredBlocks {
		if v == h {
			return
		}
	}
	// log.Println("Need block ", h)
	bs.RequiredBlocks = append(bs.RequiredBlocks, h)
}

// RemoveRequiredBlock removes from requiredBlocks
func (bs *BlockService) RemoveRequiredBlock(h uint64, lock bool) bool {
	if lock {
		bs.RequiredBlocksMux.Lock()
		defer bs.RequiredBlocksMux.Unlock()
	}

	for s, v := range bs.RequiredBlocks {
		if v == h {
			bs.RequiredBlocks = append(bs.RequiredBlocks[:s], bs.RequiredBlocks[s+1:]...)
			return true
		}
	}
	return false
}

// PopNextRequiredBlock
func (bs *BlockService) PopNextRequiredBlock() (uint64, bool) {
	bs.RequiredBlocksMux.Lock()
	defer bs.RequiredBlocksMux.Unlock()

	// check blockpool to see if there is any block there
	// so we ignore them

	if len(bs.RequiredBlocks) > 0 {
		sort.Slice(bs.RequiredBlocks, func(i, j int) bool {
			return bs.RequiredBlocks[i] < bs.RequiredBlocks[j]
		})

		poped := bs.RequiredBlocks[0]
		bs.RemoveRequiredBlock(poped, false)
		return poped, true
	}
	return 0, false
}

// AddHeighestBlock adds the highest block found from peers
func (bs *BlockService) AddHeighestBlock(h uint64) {
	bs.HeighestBlockMux.Lock()
	bs.HeighestBlock = h
	bs.HeighestBlockMux.Unlock()
}

// GetHeighestBlock gets the highest block found from peers
func (bs *BlockService) GetHeighestBlock() uint64 {
	bs.HeighestBlockMux.Lock()
	height := bs.HeighestBlock
	bs.HeighestBlockMux.Unlock()
	return height
}

func (bs *BlockService) BlockHandler(s network.Stream) {
	// constantly read bytes from the stream
	buf := []byte{}

	for {
		// 100 KB buffer
		chunk := make([]byte, 1024*100)
		n, err := s.Read(chunk)

		if err != nil {
			log.Warn("error while reading from stream: ", err)
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

			bqr := BlockQuery{}
			if err := proto.Unmarshal(dt, &bqr); err != nil {
				log.Warn("error while unmarshalling data from stream: ", err)
				return
			}

			bqResponse := BlockQueryResponse{}
			bqResponse.Type = bqr.Type
			bsch := bs.Node
			bqResponse.NodeHeight = bsch.BlockChain.GetHeight()
			if bqr.Type == BlockQueryType_HEIGHT {
				// the request was for current height
				bqResponse.Height = bqResponse.NodeHeight
				bqResponse.Payload = nil

			} else if bqr.Type == BlockQueryType_BLOCK {
				block, err := bs.Node.BlockChain.GetBlockByHeight(bqr.BlockNo)
				log.Info("Sending block number ", bqr.BlockNo, " with hash ", hexutil.Encode(block.Hash))
				if err != nil {
					bqResponse.Error = true
				} else {
					bqResponse.Height = bqr.BlockNo
					bqResponse.Payload = Serialize(block)
				}
			}

			queryBts, _ := proto.Marshal(&bqResponse)
			msg := make([]byte, 8+len(queryBts))
			binary.LittleEndian.PutUint64(msg, uint64(len(queryBts)))
			copy(msg[8:], queryBts)

			_, err := s.Write(msg)
			if err != nil {
				log.Warn("error while writing stream: ", err)
			}
		}

	}
}

func (bs *BlockService) AddToRemoteHosts(rh *RemoteHost) error {
	bs.RemoteHostsMux.Lock()
	defer bs.RemoteHostsMux.Unlock()
	for _, v := range bs.RemoteHosts {
		if v.PeerID == rh.PeerID {
			return errors.New("there is already an open stream to remote host")
		}
	}
	bs.RemoteHosts = append(bs.RemoteHosts, rh)
	return nil
}

func (bs *BlockService) RemoveFromRemoteHosts(peer peer.ID) error {
	bs.RemoteHostsMux.Lock()
	defer bs.RemoteHostsMux.Unlock()
	for s, v := range bs.RemoteHosts {
		if v.PeerID == peer {
			v.Close()
			bs.RemoteHosts = append(bs.RemoteHosts[:s], bs.RemoteHosts[s+1:]...)

			// if all hosts removed then we have closed all streams
			// so we stoped syncing

			return nil
		}
	}
	return errors.New("no connection to remote host")
}

func (rm *RemoteHost) Query(blockNo uint64) {
	// log.Info("Query remote host with blockno ", blockNo)
	query := BlockQuery{
		Type: BlockQueryType_HEIGHT,
	}

	if blockNo == 0 {
		query.Type = BlockQueryType_HEIGHT

	} else {
		query.Type = BlockQueryType_BLOCK
		query.BlockNo = blockNo
	}

	queryBts, err := proto.Marshal(&query)
	if err != nil {
		return
	}

	msg := make([]byte, 8+len(queryBts))
	binary.LittleEndian.PutUint64(msg, uint64(len(queryBts)))
	copy(msg[8:], queryBts)

	_, err = rm.Stream.Write(msg)
	if err != nil {
		log.Warn("error while writing to stream: ", err)
	}

}

func (rm *RemoteHost) Read() {
	buf := []byte{}

	for {
		// 100 KB buffer
		chunk := make([]byte, 1024*100)
		n, err := rm.Stream.Read(chunk)

		if err != nil {
			log.Warn("error while reading from stream: ", err)
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

			pl := BlockQueryResponsePayload{
				BlockQueryResponse: bqr,
				PeerID:             rm.PeerID,
			}

			if pl.BlockQueryResponse.Type == BlockQueryType_HEIGHT {
				BlockRequiredGlobalMutex.Lock()
				for i := rm.BlockService.Node.BlockChain.GetHeight() + 1; i <= pl.BlockQueryResponse.NodeHeight; i++ {
					rm.BlockService.Node.BlockService.AddRequiredBlock(i)
				}
				BlockRequiredGlobalMutex.Unlock()
			}

			rm.AddHeight(pl.BlockQueryResponse.NodeHeight)

			if pl.BlockQueryResponse.NodeHeight > rm.BlockService.GetHeighestBlock() {
				rm.BlockService.AddHeighestBlock(pl.BlockQueryResponse.NodeHeight)
			}

			if pl.BlockQueryResponse.NodeHeight <= rm.BlockService.Node.BlockChain.GetHeight() {
				rm.BlockService.Node.BlockService.RemoveFromRemoteHosts(pl.PeerID)
				continue
			}

			if len(pl.BlockQueryResponse.Payload) > 0 {
				block, _ := DeserializeBlock(pl.BlockQueryResponse.Payload)
				log.Println("Downloaded Block:\t", hexutil.Encode(block.Hash), " From Peer:\t", pl.PeerID, " Height:\t", pl.BlockQueryResponse.Height)

				err := rm.BlockService.Node.BlockChain.AddBlockPool(block)
				if err != nil {
					log.Warn(err)
					// rm.BlockService.Node.BlockChain.ClearBlockPool()
					// rm.BlockService.Node.SetSyncing(false)
					// rm.BlockService.Node.Sync(context.Background())
				}

			}

			// add the next value to the channel
			rm.SendJob()

		}

	}
}

// SendJob
func (rm *RemoteHost) SendJob() {
	// rand.Seed(time.Now().UnixNano())
	// r := rand.Intn(2000)
	// time.Sleep(time.Duration(r) * time.Millisecond)
	hb := rm.BlockService.Node.BlockService.GetHeighestBlock()
	nodesHeight := rm.BlockService.Node.BlockChain.GetHeight()

	if hb > 0 && nodesHeight >= hb {
		log.Println("All blocks downloaded")
		rm.BlockService.Node.SetSyncing(false)
		return
	}

	// for i := nodesHeight + 1; i <= hb; i++ {
	// 	rm.BlockService.Node.BlockService.AddRequiredBlock(i)
	// }

	job, ok := rm.BlockService.PopNextRequiredBlock()

	if !ok {
		for {
			job, ok = rm.BlockService.PopNextRequiredBlock()
			if ok {
				break
			}
			// time.Sleep(1 * time.Second)
		}
	}

	if ok {
		if job > rm.GetHeight() {
			// we need to remove it from the array of remote hosts too
			rm.BlockService.RemoveFromRemoteHosts(rm.PeerID)

			// send back the value which we didnt use
			rm.BlockService.AddRequiredBlock(job)

		}
		log.Println("Client Node: ", nodesHeight, " NetworkHeight: ", hb, " Sendjob height: ", job)
		rm.Query(job)
	}

}

// NewRemoteHost
func NewRemoteHost(ctx context.Context, bs *BlockService, p peer.ID) error {
	rh := &RemoteHost{
		BlockService: bs,
		HeightMux:    &sync.Mutex{},
		RhMux:        &sync.Mutex{},
	}
	s, err := bs.Node.Host.NewStream(ctx, p, BlockServiceID)
	if err != nil {
		return err
	}
	rh.Stream = s
	rh.PeerID = p
	bs.AddToRemoteHosts(rh)
	go rh.Query(0)
	go rh.Read()
	rh.BlockService.Node.SetSyncing(true)
	return nil
}

func (rm *RemoteHost) Close() error {
	return rm.Stream.Close()
}
