package node

import (
	"context"

	"github.com/filefilego/filefilego/common/hexutil"
)

// BlockAPI represents a block service
type BlockAPI struct {
	Node *Node
}

// NewBlockAPI returns an instance of block service
func NewBlockAPI(node *Node) *BlockAPI {
	return &BlockAPI{Node: node}
}

// BlockJSON represents a block in json format
type BlockJSON struct {
	Timestamp     int64  `json:"timestamp"`
	Data          string `json:"data"`
	PrevBlockHash string `json:"prev_block_hash"`
	Hash          string `json:"hash"`
	Signature     string `json:"signature"`
}

// GetByNumber returns a block by height
func (api *BlockAPI) GetByNumber(ctx context.Context, heightHex string) (b BlockJSON, err error) {
	h, err := hexutil.DecodeUint64(heightHex)
	if err != nil {
		return b, err
	}
	block, err := api.Node.BlockChain.GetBlockByHeight(h)
	if err != nil {
		return b, err
	}
	b = BlockJSON{
		Timestamp:     block.Timestamp,
		Data:          hexutil.Encode(block.Data),
		Hash:          hexutil.Encode(block.Hash),
		PrevBlockHash: hexutil.Encode(block.PrevBlockHash),
		Signature:     hexutil.Encode(block.Signature),
	}
	return b, nil
}

// GetByHash returns a block by hash
func (api *BlockAPI) GetByHash(ctx context.Context, hash string) (b BlockJSON, err error) {
	block, err := api.Node.BlockChain.GetBlockByHash(hash)
	if err != nil {
		return b, err
	}
	b = BlockJSON{
		Timestamp:     block.Timestamp,
		Data:          hexutil.Encode(block.Data),
		Hash:          hexutil.Encode(block.Hash),
		PrevBlockHash: hexutil.Encode(block.PrevBlockHash),
		Signature:     hexutil.Encode(block.Signature),
	}

	return b, nil
}

// GetTransactionsByNumber return transactions of a block
func (api *BlockAPI) GetTransactionsByNumber(ctx context.Context, heightHex string) (b []TransactionJSON, err error) {
	h, err := hexutil.DecodeUint64(heightHex)
	if err != nil {
		return b, err
	}
	block, err := api.Node.BlockChain.GetBlockByHeight(h)
	if err != nil {
		return b, err
	}
	for _, v := range block.Transactions {
		t := TransactionJSON{
			Hash:            hexutil.Encode(v.Hash),
			Data:            hexutil.Encode(v.Data),
			From:            v.From,
			Nounce:          v.Nounce,
			PubKey:          v.PubKey,
			Signature:       hexutil.Encode(v.Signature),
			To:              v.To,
			TransactionFees: v.TransactionFees,
			Value:           v.Value,
		}
		b = append(b, t)
	}
	return b, nil
}

// GetTransactionsByHash return transactions by block hash
func (api *BlockAPI) GetTransactionsByHash(ctx context.Context, hash string) (b []TransactionJSON, err error) {
	block, err := api.Node.BlockChain.GetBlockByHash(hash)
	if err != nil {
		return b, err
	}

	for _, v := range block.Transactions {
		t := TransactionJSON{
			Hash:            hexutil.Encode(v.Hash),
			Data:            hexutil.Encode(v.Data),
			From:            v.From,
			Nounce:          v.Nounce,
			PubKey:          v.PubKey,
			Signature:       hexutil.Encode(v.Signature),
			To:              v.To,
			TransactionFees: v.TransactionFees,
			Value:           v.Value,
		}
		b = append(b, t)
	}

	return b, nil
}

// Pool return block pool
func (api *BlockAPI) Pool(ctx context.Context) (b []string, err error) {
	for _, v := range api.Node.BlockChain.BlockPool {
		b = append(b, hexutil.Encode(v.Hash))
	}
	return b, nil
}
