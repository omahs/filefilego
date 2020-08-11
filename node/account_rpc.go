package node

import (
	"context"
	"errors"

	"github.com/filefilego/filefilego/common"
	"github.com/filefilego/filefilego/common/hexutil"
)

// AccountAPI
type AccountAPI struct {
	Node *Node
}

// NewAccountAPI
func NewAccountAPI(node *Node) *AccountAPI {
	return &AccountAPI{Node: node}
}

// Unlock an account
func (api *AccountAPI) Unlock(ctx context.Context, address string, passphrase string) (string, error) {
	if !hexutil.Has0xPrefix(address) {
		address = "0x" + address
	}

	jwt, err := api.Node.Keystore.UnlockAccount(address, passphrase)
	if err != nil {
		return "", err
	}
	return jwt, nil
}

// Lock an account
func (api *AccountAPI) Lock(ctx context.Context, access_token string, address string) (string, error) {
	if !hexutil.Has0xPrefix(address) {
		address = "0x" + address
	}
	msg, err := api.Node.Keystore.LockAccount(address, access_token)
	if err != nil {
		return "", err
	}
	return msg, nil
}

// AccountStateResult ...
type AccountStateResult struct {
	Balance    string `json:"balance"`
	BalanceHex string `json:"balance_hex"`
	Nounce     string `json:"nounce"`
	NextNounce string `json:"next_nounce"`
}

// Balance Get the balanace of an address
func (api *AccountAPI) Balance(ctx context.Context, address string) (AccountStateResult, error) {
	acRes := AccountStateResult{
		Balance:    "0",
		BalanceHex: "0x0",
		Nounce:     "0x0",
	}

	if !hexutil.Has0xPrefix(address) {
		address = "0x" + address
	}

	addressData, err := api.Node.BlockChain.GetAddressData(address)
	if err == AddressDecodeError {
		return acRes, errors.New("Unable to decode address")
	}

	if err == NoBalance {
		return acRes, nil
	}

	blncInt, err2 := hexutil.DecodeBig(string(addressData.Balance))
	if err2 != nil {
		return acRes, err2
	}

	acRes.BalanceHex = hexutil.EncodeBig(blncInt)
	bigIntTxt := blncInt.Text(10)
	acRes.Balance = common.FormatBigWithSeperator(common.LeftPad2Len(bigIntTxt, "0", 19), ".", 18)
	acRes.Nounce = string(addressData.Nounce)
	bigOne, _ := hexutil.DecodeBig("0x1")
	currentNounce, _ := hexutil.DecodeBig(string(addressData.Nounce))
	currentNounce = currentNounce.Add(currentNounce, bigOne)
	acRes.NextNounce = hexutil.EncodeBig(currentNounce)

	return acRes, nil
}
