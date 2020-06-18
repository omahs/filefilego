package node

import (
	"context"
	"errors"
	"math/big"

	log "github.com/sirupsen/logrus"

	proto "github.com/golang/protobuf/proto"
	"gitlab.com/younixcc/filefilego/common/hexutil"
)

var (
	MAX_TX_DATA_SIZE = 1024 * 300
)

// TransactionAPI
type TransactionAPI struct {
	Node *Node
}

// NewTransactionAPI
func NewTransactionAPI(node *Node) *TransactionAPI {
	return &TransactionAPI{Node: node}
}

// SendTransaction sends a transaction to the network
func (api *TransactionAPI) SendTransaction(ctx context.Context, access_token string, to string, value string, txfees string, nounce string, data string) (string, error) {

	if len(to) > 100 || len(value) > 500 || len(txfees) > 500 || len(nounce) > 100 {
		return "", errors.New("fields size too big")
	}

	if len(data) > MAX_TX_DATA_SIZE { // 300 KB
		return "", errors.New("\"data\" field is too big")
	}

	if access_token == "" {
		return "", errors.New("\"access_token\" is a required field")
	}

	if to == "" {
		return "", errors.New("\"to\" is a required field")
	}

	val, err := hexutil.DecodeBig(value)
	if err != nil {
		return "", err
	}

	txf, err := hexutil.DecodeBig(txfees)
	if err != nil {
		txf, _ = new(big.Int).SetString("0", 10)
	}

	addrNounce, err := hexutil.DecodeBig(nounce)
	if err != nil {
		return "", err
	}

	// check if authorized token
	ok, retAddr, unlockedAccount, err := api.Node.Keystore.Authorized(access_token)
	if err != nil {
		return "", err
	}

	if ok {
		hasBalance, _, _, err := api.Node.BlockChain.HasThisBalance(retAddr, val.Add(val, txf))
		if err != nil {
			return "", err
		}

		pbBytes, err := unlockedAccount.Key.Private.GetPublic().Raw()
		if err != nil {
			return "", err
		}

		if hasBalance {
			tx := Transaction{
				Data:            []byte(data),
				From:            "0x" + unlockedAccount.Key.Address,
				Nounce:          hexutil.EncodeBig(addrNounce),
				PubKey:          hexutil.Encode(pbBytes),
				To:              to,
				Value:           hexutil.EncodeBig(val),
				TransactionFees: hexutil.EncodeBig(txf),
			}
			signedTx, err := api.Node.BlockChain.SignTransaction(tx, unlockedAccount.Key)
			if err != nil {
				return "", err
			}
			err = api.Node.BlockChain.AddMemPool(signedTx)
			if err != nil {
				return "", err
			}
			// broadcast the transaction to the network
			gpl := GossipPayload{
				Type:    GossipPayload_TRANSACTION,
				Payload: SerializeTransaction(signedTx),
			}

			gplBts, err := proto.Marshal(&gpl)
			if err != nil {
				log.Warn("Error while marshaling transaction to protobuff: ", err)
			} else {
				// if api.Node.Peers().Len() > 1 {
				api.Node.Gossip.Broadcast(gplBts)
				// }
			}

			return hexutil.Encode(signedTx.Hash), nil
		}
	}

	return "", errors.New("Unable to send transaction. Check your balance")
}

type TransactionJson struct {
	Hash            string `json:"hash"`
	PubKey          string `json:"pub_key"`
	Nounce          string `json:"nounce"`
	Data            string `json:"data"`
	From            string `json:"from"`
	To              string `json:"to"`
	Value           string `json:"value"`
	TransactionFees string `json:"transaction_fees"`
	Signature       string `json:"signature"`
}

// Pool
func (api *TransactionAPI) Pool(ctx context.Context) (txs []TransactionJson, err error) {
	for _, v := range api.Node.BlockChain.MemPool {
		t := TransactionJson{
			Data:            hexutil.Encode(v.Data),
			From:            v.From,
			Hash:            hexutil.Encode(v.Hash),
			Nounce:          v.Nounce,
			PubKey:          v.PubKey,
			Signature:       hexutil.Encode(v.Signature),
			To:              v.To,
			TransactionFees: v.TransactionFees,
			Value:           v.Value,
		}
		txs = append(txs, t)
	}
	return txs, nil
}

type ReceiptPayload struct {
	BlockHash   string          `json:"block_hash"`
	BlockHeight uint64          `json:"block_height"`
	Transaction TransactionJson `json:"transaction"`
}

// Receipt
func (api *TransactionAPI) Receipt(ctx context.Context, hash string) (txpl ReceiptPayload, err error) {
	v, block, blockHeight, err := api.Node.BlockChain.GetTransactionByHash(hash)
	if err != nil {
		return txpl, err
	}
	tx := TransactionJson{
		Data:            hexutil.Encode(v.Data),
		From:            v.From,
		Hash:            hexutil.Encode(v.Hash),
		Nounce:          v.Nounce,
		PubKey:          v.PubKey,
		Signature:       hexutil.Encode(v.Signature),
		To:              v.To,
		TransactionFees: v.TransactionFees,
		Value:           v.Value,
	}

	txpl = ReceiptPayload{
		BlockHash:   hexutil.Encode(block.Hash),
		BlockHeight: blockHeight,
		Transaction: tx,
	}

	return txpl, nil
}
