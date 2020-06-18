package node

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"

	log "github.com/sirupsen/logrus"
)

// GetTransactionID gets a hash of a transaction
func GetTransactionID(tx *Transaction) []byte {
	var encoded bytes.Buffer
	var hash [32]byte
	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(tx)
	if err != nil {
		log.Panic(err)
	}
	hash = sha256.Sum256(encoded.Bytes())
	bts := hash[:]
	return bts
}

// SerializeTransaction
func SerializeTransaction(tx Transaction) []byte {
	var encoded bytes.Buffer
	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(&tx)
	if err != nil {
		log.Panic(err)
	}
	return encoded.Bytes()
}

// SerializeTransaction
func UnserializeTransaction(data []byte) Transaction {
	var transaction Transaction

	decoder := gob.NewDecoder(bytes.NewReader(data))
	err := decoder.Decode(&transaction)
	if err != nil {
		log.Panic(err)
	}
	return transaction
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
