package node

import (
	log "github.com/sirupsen/logrus"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/libp2p/go-libp2p-core/crypto"
	ffgcrypto "github.com/filefilego/filefilego/crypto"
)

type Verifier struct {
	Address         string
	InitialBalance  string
	PublicKey       string
	PublicKeyCrypto crypto.PubKey
}

var (
	// BlockSealers are the sealers
	BlockSealers []Verifier
)

func init() {
	for _, v := range GetBlockchainSettings().Verifiers {
		pubBytesFromHex, _ := hexutil.Decode(v.PublicKey)
		newPub, err := ffgcrypto.RestorePubKey(pubBytesFromHex)
		if err != nil {
			log.Fatal("Unable to load verifier list")
		}
		v.PublicKeyCrypto = newPub
		BlockSealers = append(BlockSealers, v)
	}
}
