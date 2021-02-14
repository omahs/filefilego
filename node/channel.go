package node

import (
	"math/big"

	proto "google.golang.org/protobuf/proto"

	"github.com/filefilego/filefilego/common/hexutil"
	log "github.com/sirupsen/logrus"
)

// IsValidChannelPayload checks if a valid channel payload
func IsValidChannelPayload(t Transaction, currentBalance *big.Int) bool {
	ap := TransactionDataPayload{}
	bts, _ := proto.Marshal(&ap)
	originHex := hexutil.Encode(bts) // need this to see if the ChanActionPayload is the same after unmarshalling
	if err := proto.Unmarshal(t.Data, &ap); err != nil {
		log.Warn("Invalid transaction payload of type ChanActionPayload. Ignore as it's possible to store any arbitrary data", err)
		return true
	}

	bts, _ = proto.Marshal(&ap)
	afterUnmarshalHex := hexutil.Encode(bts)

	// check if balance is available to register a namespace
	if originHex != afterUnmarshalHex && ap.Type == TransactionDataPayloadType_CREATE_NODE {
		var regFee, _ = new(big.Int).SetString(GetBlockchainSettings().NamespaceRegistrationFee, 10)
		if currentBalance.Cmp(regFee) < 0 {
			return false
		}
	}

	return true
}
