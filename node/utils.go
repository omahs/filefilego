package node

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"

	log "github.com/sirupsen/logrus"
	proto "google.golang.org/protobuf/proto"
)

// GetTransactionID gets a hash of a transaction
func GetTransactionID(tx *Transaction) []byte {
	data := bytes.Join(
		[][]byte{
			[]byte(tx.PubKey),
			[]byte(tx.Nounce),
			tx.Data,
			[]byte(tx.From),
			[]byte(tx.To),
			[]byte(tx.Value),
			[]byte(tx.TransactionFees),
			GetBlockchainSettings().Chain,
		},
		[]byte{},
	)
	hash := sha256.Sum256(data)
	bts := hash[:]
	return bts
}

// SerializeTransaction serialized  transaction
func SerializeTransaction(tx Transaction) []byte {
	blkBts, err := proto.Marshal(&tx)
	if err != nil {
		log.Println(err)
	}
	return blkBts
}

// UnserializeTransaction converts a byte array to a transaction
func UnserializeTransaction(data []byte) Transaction {
	tx := Transaction{}
	if err := proto.Unmarshal(data, &tx); err != nil {
		log.Warn("error while unmarshalling data from stream: ", err)
	}
	return tx
}

// IntToHex converts an int64 to a byte array
func IntToHex(num int64) []byte {
	buff := new(bytes.Buffer)
	err := binary.Write(buff, binary.BigEndian, num)
	if err != nil {
		log.Panic(err)
	}

	return buff.Bytes()
}
