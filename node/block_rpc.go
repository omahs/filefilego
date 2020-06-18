package node

import (
	"context"

	"gitlab.com/younixcc/filefilego/common/hexutil"
)

// TransactionAPI
type BlockAPI struct {
	Node *Node
}

// NewBlockAPI
func NewBlockAPI(node *Node) *BlockAPI {
	return &BlockAPI{Node: node}
}

type BlockJson struct {
	Timestamp     int64  `json:"timestamp"`
	Data          string `json:"data"`
	PrevBlockHash string `json:"prev_block_hash"`
	Hash          string `json:"hash"`
	Signature     string `json:"signature"`
}

// GetByNumber
func (api *BlockAPI) GetByNumber(ctx context.Context, heightHex string) (b BlockJson, err error) {
	h, err := hexutil.DecodeUint64(heightHex)
	if err != nil {
		return b, err
	}
	block, err := api.Node.BlockChain.GetBlockByHeight(h)
	if err != nil {
		return b, err
	}
	b = BlockJson{
		Timestamp:     block.Timestamp,
		Data:          hexutil.Encode(block.Data),
		Hash:          hexutil.Encode(block.Hash),
		PrevBlockHash: hexutil.Encode(block.PrevBlockHash),
		Signature:     hexutil.Encode(block.Signature),
	}
	return b, nil
}

// GetByHash
func (api *BlockAPI) GetByHash(ctx context.Context, hash string) (b BlockJson, err error) {
	block, err := api.Node.BlockChain.GetBlockByHash(hash)
	if err != nil {
		return b, err
	}
	b = BlockJson{
		Timestamp:     block.Timestamp,
		Data:          hexutil.Encode(block.Data),
		Hash:          hexutil.Encode(block.Hash),
		PrevBlockHash: hexutil.Encode(block.PrevBlockHash),
		Signature:     hexutil.Encode(block.Signature),
	}

	return b, nil
}

// GetTransactionsByNumber
func (api *BlockAPI) GetTransactionsByNumber(ctx context.Context, heightHex string) (b []TransactionJson, err error) {
	h, err := hexutil.DecodeUint64(heightHex)
	if err != nil {
		return b, err
	}
	block, err := api.Node.BlockChain.GetBlockByHeight(h)
	if err != nil {
		return b, err
	}
	for _, v := range block.Transactions {
		t := TransactionJson{
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

// GetTransactionsByHash
func (api *BlockAPI) GetTransactionsByHash(ctx context.Context, hash string) (b []TransactionJson, err error) {
	block, err := api.Node.BlockChain.GetBlockByHash(hash)
	if err != nil {
		return b, err
	}

	for _, v := range block.Transactions {
		t := TransactionJson{
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
