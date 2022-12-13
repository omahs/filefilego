package block

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/filefilego/filefilego/internal/common/hexutil"
	ffgcrypto "github.com/filefilego/filefilego/internal/crypto"
	transaction "github.com/filefilego/filefilego/internal/transaction"
	"github.com/libp2p/go-libp2p/core/crypto"
	"google.golang.org/protobuf/proto"
)

const maxBlockDataSizeBytes = 300000

// Block represents a block.
type Block struct {
	Hash      []byte
	Signature []byte

	Timestamp         int64
	Data              []byte
	PreviousBlockHash []byte
	Transactions      []transaction.Transaction
	Number            uint64
}

// GetCoinbaseTransaction gets the coinbase transaction.
// A coinbase transaction is the first transaction and the public key
// of the transaction should match the block signer
func (b Block) GetCoinbaseTransaction() (transaction.Transaction, error) {
	if len(b.Transactions) == 0 {
		return transaction.Transaction{}, errors.New("no transactions in block")
	}

	coinbaseTx := b.Transactions[0]
	pubKey, err := ffgcrypto.PublicKeyFromBytes(coinbaseTx.PublicKey)
	if err != nil {
		return transaction.Transaction{}, fmt.Errorf("failed to derive public key from transaction: %w", err)
	}

	err = b.VerifyWithPublicKey(pubKey)
	if err != nil {
		return transaction.Transaction{}, fmt.Errorf("coinbase transaction signer doesn't match the block signer: %w", err)
	}

	return coinbaseTx, nil
}

// GetTransactionsHash hashes all the transaction's hashes in the block.
func (b Block) GetTransactionsHash() ([]byte, error) {
	if len(b.Transactions) == 0 {
		return nil, errors.New("no transactions to hash")
	}

	txHashes := make([][]byte, len(b.Transactions))
	for i, tx := range b.Transactions {
		data, err := tx.GetTransactionHash()
		if err != nil {
			return nil, fmt.Errorf("failed to get transaction hash in block: %w", err)
		}
		txHashes[i] = data
	}
	txHash := sha256.Sum256(bytes.Join(txHashes, []byte{}))
	return txHash[:], nil
}

// GetBlockHash hashes the block
func (b Block) GetBlockHash() ([]byte, error) {
	blockTxsHash, err := b.GetTransactionsHash()
	if err != nil {
		return nil, fmt.Errorf("failed to get block's transactions hash: %w", err)
	}
	timestampBytes, err := hexutil.IntToHex(b.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("failed to convert int to byte array: %w", err)
	}

	blockNumberBytes, err := hexutil.Uint64ToHex(b.Number)
	if err != nil {
		return nil, fmt.Errorf("failed to convert int to byte array: %w", err)
	}

	data := bytes.Join(
		[][]byte{
			timestampBytes,
			b.Data,
			b.PreviousBlockHash,
			blockTxsHash,
			blockNumberBytes,
		},
		[]byte{},
	)

	hash := sha256.Sum256(data)
	return hash[:], nil
}

// Sign signs a block with a private key.
func (b *Block) Sign(key crypto.PrivKey) error {
	hash, err := b.GetBlockHash()
	if err != nil {
		return fmt.Errorf("failed to get block's hash: %w", err)
	}

	b.Hash = make([]byte, len(hash))
	copy(b.Hash, hash)

	sig, err := key.Sign(b.Hash)
	if err != nil {
		return fmt.Errorf("failed to sign block: %w", err)
	}

	b.Signature = make([]byte, len(sig))
	copy(b.Signature, sig)

	return nil
}

// VerifyWithPublicKey verifies a block with a public key.
func (b Block) VerifyWithPublicKey(key crypto.PubKey) error {
	ok, err := key.Verify(b.Hash, b.Signature)
	if err != nil {
		return fmt.Errorf("failed to verify block: %w", err)
	}
	if !ok {
		return errors.New("failed verification of block")
	}
	return nil
}

// Validate validates a block.
func (b Block) Validate() (bool, error) {
	if len(b.Hash) == 0 || b.Hash == nil {
		return false, errors.New("hash is empty")
	}

	if len(b.PreviousBlockHash) == 0 || b.PreviousBlockHash == nil {
		return false, errors.New("previousBlockHash is empty")
	}

	if b.Timestamp <= 0 {
		return false, errors.New("timestamp is empty")
	}

	if len(b.Transactions) == 0 {
		return false, errors.New("block doesn't contain any transaction")
	}

	if len(b.Data) > maxBlockDataSizeBytes {
		return false, fmt.Errorf("data with size %d is greater than %d bytes", len(b.Data), maxBlockDataSizeBytes)
	}

	coinbase, err := b.GetCoinbaseTransaction()
	if err != nil {
		return false, fmt.Errorf("failed to get coinbase transaction: %w", err)
	}

	pubKey, err := ffgcrypto.PublicKeyFromBytes(coinbase.PublicKey)
	if err != nil {
		return false, fmt.Errorf("failed to derive public key from coinbase transaction: %w", err)
	}

	err = b.VerifyWithPublicKey(pubKey)
	if err != nil {
		return false, fmt.Errorf("failed to verify block: %w", err)
	}

	hash, err := b.GetBlockHash()
	if err != nil {
		return false, errors.New("failed to get block hash")
	}

	if !bytes.Equal(b.Hash, hash) {
		return false, errors.New("block is altered and doesn't match the hash")
	}

	verifierAddr, err := ffgcrypto.RawPublicToAddress(coinbase.PublicKey)
	if err != nil {
		return false, errors.New("failed to get verifier's address")
	}

	if !IsValidVerifier(verifierAddr) {
		return false, errors.New("block was signed by a non-verifier")
	}

	return true, nil
}

// MarshalProtoTransaction serializes a block to a protobuf message.
func MarshalProtoBlock(b *ProtoBlock) ([]byte, error) {
	blockData, err := proto.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal block: %w", err)
	}
	return blockData, nil
}

// UnmarshalProtoBlock unserializes a byte array to a protobuf block.
func UnmarshalProtoBlock(data []byte) (*ProtoBlock, error) {
	block := ProtoBlock{}
	if err := proto.Unmarshal(data, &block); err != nil {
		return nil, fmt.Errorf("failed to unmarshal a block: %w", err)
	}
	return &block, nil
}

// ToProtoBlock returns a proto representation of a block.
func ToProtoBlock(block Block) *ProtoBlock {
	pblock := &ProtoBlock{
		Hash:              make([]byte, len(block.Hash)),
		Signature:         make([]byte, len(block.Signature)),
		Timestamp:         block.Timestamp,
		Data:              make([]byte, len(block.Data)),
		PreviousBlockHash: make([]byte, len(block.PreviousBlockHash)),
		Transactions:      make([]*transaction.ProtoTransaction, 0, len(block.Transactions)),
		Number:            block.Number,
	}

	copy(pblock.Hash, block.Hash)
	copy(pblock.Signature, block.Signature)
	copy(pblock.Data, block.Data)
	copy(pblock.PreviousBlockHash, block.PreviousBlockHash)
	for _, t := range block.Transactions {
		pblock.Transactions = append(pblock.Transactions, transaction.ToProtoTransaction(t))
	}

	return pblock
}

// ProtoBlockToBlock returns a domain block.
func ProtoBlockToBlock(pblock *ProtoBlock) Block {
	block := Block{
		Hash:              make([]byte, len(pblock.Hash)),
		Signature:         make([]byte, len(pblock.Signature)),
		Timestamp:         pblock.Timestamp,
		Data:              make([]byte, len(pblock.Data)),
		PreviousBlockHash: make([]byte, len(pblock.PreviousBlockHash)),
		Transactions:      make([]transaction.Transaction, 0, len(pblock.Transactions)),
		Number:            pblock.Number,
	}

	copy(block.Hash, pblock.Hash)
	copy(block.Signature, pblock.Signature)
	copy(block.Data, pblock.Data)
	copy(block.PreviousBlockHash, pblock.PreviousBlockHash)
	for _, t := range pblock.Transactions {
		block.Transactions = append(block.Transactions, transaction.ProtoTransactionToTransaction(t))
	}

	return block
}
