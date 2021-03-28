package node

import (
	log "github.com/sirupsen/logrus"

	"github.com/ethereum/go-ethereum/common/hexutil"
	ffgcrypto "github.com/filefilego/filefilego/crypto"
	"github.com/libp2p/go-libp2p-core/crypto"
)

// Verifier represents a block verifier/sealer
type Verifier struct {
	Address         string `json:"address"`
	InitialBalance  string `json:"initial_balance"`
	PublicKey       string `json:"public_key"`
	DataVerifier    bool   `json:"data_verifier"`
	PublicKeyCrypto crypto.PubKey
}

var (
	// BlockSealers are the sealers
	BlockSealers []Verifier
)

func init() {
	for _, v := range GetBlockchainSettings().Verifiers {
		pubBytesFromHex, _ := hexutil.Decode(v.PublicKey)
		newPub, err := ffgcrypto.UnmarshalSecp256k1PubKey(pubBytesFromHex)
		if err != nil {
			log.Fatal("Unable to load verifier list")
		}
		v.PublicKeyCrypto = newPub
		BlockSealers = append(BlockSealers, v)
	}
}
