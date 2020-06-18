package node

import (
	"bytes"
	"crypto/sha256"
	"reflect"

	log "github.com/sirupsen/logrus"

	proto "github.com/golang/protobuf/proto"
	"gitlab.com/younixcc/filefilego/common/hexutil"
	"gitlab.com/younixcc/filefilego/keystore"
)

// Serialize serializes the block
func Serialize(b Block) []byte {
	blkBts, _ := proto.Marshal(&b)
	return blkBts
}

// HashTransactions returns a hash of the transactions in the block
func (b *Block) HashTransactions() []byte {
	var txHashes [][]byte
	var txHash [32]byte

	for _, tx := range b.Transactions {
		txHashes = append(txHashes, GetTransactionID(tx))
	}
	txHash = sha256.Sum256(bytes.Join(txHashes, []byte{}))

	return txHash[:]
}

// NewBlock creates and returns Block
func NewBlock(transactions []*Transaction, prevBlockHash []byte, data []byte, unixtime int64, signer *keystore.Key) Block {

	block := Block{Timestamp: unixtime, Data: data, PrevBlockHash: prevBlockHash, Hash: []byte{}, Signature: []byte{}, Transactions: transactions}
	hash, sig := SealBlock(block, signer)
	block.Hash = hash[:]
	block.Signature = sig
	return block
}

// SealBlock seals a block
func SealBlock(b Block, signer *keystore.Key) ([]byte, []byte) {
	data := bytes.Join(
		[][]byte{
			IntToHex(b.Timestamp),
			b.Data,
			b.PrevBlockHash,
			b.HashTransactions(),
		},
		[]byte{},
	)

	hash := sha256.Sum256(data)
	signedData, err := signer.Private.Sign(hash[:])
	if err != nil {
		log.Fatal("Unable to sign block")
	}
	return hash[:], signedData
}

// LogDetails
func (b *Block) LogDetails() {
	if b.PrevBlockHash == nil || len(b.PrevBlockHash) == 0 {
		log.Println("Problem =========================================>>")
		log.Println("Hash: ", hexutil.Encode(b.Hash))
		log.Println(b.PrevBlockHash)
		return
	}
	log.Println("Hash: ", hexutil.Encode(b.Hash))
	log.Println("Previous Hash: ", hexutil.Encode(b.PrevBlockHash))
	log.Println("TS: ", b.Timestamp)
	log.Println("Sig: ", hexutil.Encode(b.Signature))
	log.Println("TX: ", hexutil.Encode(b.Transactions[0].Hash))
}

// ValidateBlock validates a block
func ValidateBlock(b Block) bool {
	data := bytes.Join(
		[][]byte{
			IntToHex(b.Timestamp),
			b.Data,
			b.PrevBlockHash,
			b.HashTransactions(),
		},
		[]byte{},
	)

	hash := sha256.Sum256(data)

	if !reflect.DeepEqual(b.Hash, hash[:]) {
		log.Println("Unable to verify block")
		return false
	}

	// find the coinbase tx
	var coinbase *Transaction
	for _, v := range b.Transactions {
		if v.From == "" {
			coinbase = v
			break
		}
	}

	// find who signed the block
	for _, v := range BlockSealers {
		if v.Address == coinbase.To {
			// found the verifier
			if ok, err := v.PublicKeyCrypto.Verify(b.Hash, b.Signature); err == nil && ok {

				return true
			}
		}
	}
	return false
}

// DeserializeBlock deserializes a block
func DeserializeBlock(dt []byte) (Block, error) {
	block := Block{}
	if err := proto.Unmarshal(dt, &block); err != nil {
		log.Warn("error while unmarshalling data from stream: ", err)
		return block, err
	}
	return block, nil
}
