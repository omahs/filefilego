package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"math/big"
	"os"
	"reflect"
	"sort"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/boltdb/bolt"
	proto "github.com/golang/protobuf/proto"
	"github.com/filefilego/filefilego/common"
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/crypto"
	"github.com/filefilego/filefilego/keystore"
)

const memPool = "mempool"
const blocksBucket = "blocks"
const AccountsBucket = "accounts"
const GenesisBlockHash = "6ed4b64198799637a4c71c25c927d68d81329211af10952f0306b93c16f63ae5"

type TransactionTimestamp struct {
	Transaction   Transaction
	Timestamp     int64
	Timestamp8601 string
}

// Blockchain implements interactions with a DB
type Blockchain struct {
	tip          []byte
	db           *bolt.DB
	FilePath     string
	Key          *keystore.Key
	HeightMux    sync.Mutex
	Height       uint64
	BlockPool    []Block
	BlockPoolMux sync.Mutex
	MemPool      []Transaction
	MemPoolMux   sync.Mutex
	Node         *Node
}

// BlockchainIterator is used to iterate over blockchain blocks
type BlockchainIterator struct {
	currentHash []byte
	db          *bolt.DB
}

// AddressState represents the state of an address
type AddressState struct {
	Balance []byte
	Nounce  []byte
}

// CloseDB closes the db
func (bc *Blockchain) CloseDB() error {
	return bc.db.Close()
}

// AddHeight adds the number to the current hight
func (bc *Blockchain) AddHeight(h uint64) {
	bc.HeightMux.Lock()
	bc.Height += h
	bc.HeightMux.Unlock()
}

// GetHeight gets the height of the blockchain
func (bc *Blockchain) GetHeight() uint64 {
	bc.HeightMux.Lock()
	height := bc.Height
	bc.HeightMux.Unlock()
	return height
}

// GetTransactionByHash
func (bc *Blockchain) GetTransactionByHash(hash string) (tx Transaction, blck Block, index uint64, err error) {
	bci := bc.Iterator()
	index = bc.GetHeight()
	for {
		block := bci.Next()
		for _, t := range block.Transactions {
			if hash == hexutil.Encode(t.Hash) {
				return *t, block, index, nil
			}
		}
		index--
		if len(block.PrevBlockHash) == 0 {
			break
		}
	}
	return tx, blck, 0, errors.New("transaction not found")
}

// GetTransactionByHash
func (bc *Blockchain) GetTransactionsByAddress(address string) (tx []TransactionTimestamp, err error) {
	bci := bc.Iterator()
	total := 0
	for {
		block := bci.Next()
		for _, t := range block.Transactions {
			if address == t.From || address == t.To {
				tmp := TransactionTimestamp{Transaction: *t, Timestamp: block.Timestamp, Timestamp8601: time.Unix(block.Timestamp, 0).Format(time.RFC3339)}
				tx = append(tx, tmp)
				total++
			}
			if total > 10 {
				break
			}

		}

		if total > 10 {
			break
		}

		if len(block.PrevBlockHash) == 0 {
			break
		}
	}
	return tx, nil
}

// GetBlockByHeight gets the block given its number (height)
func (bc *Blockchain) GetBlockByHeight(number uint64) (bb Block, err error) {
	if number < 0 {
		return bb, errors.New("invalid blockno")
	}
	height := bc.GetHeight()
	bci := bc.Iterator()
	for {
		block := bci.Next()
		if number == height {
			return block, nil

		}
		height--
		if len(block.PrevBlockHash) == 0 {
			break
		}
	}
	return bb, errors.New("block was not found")
}

// GetBlocksByRange gets a range of blocks
func (bc *Blockchain) GetBlocksByRange(from uint64, to uint64) ([]*Block, error) {
	if from < 0 {
		return nil, errors.New("invalid from")
	}
	height := bc.GetHeight()
	if to > height {
		return nil, errors.New("range \"to\" is greater than blockchain height")
	}
	bci := bc.Iterator()
	bb := []Block{}
	for {
		block := bci.Next()
		if height <= to && height >= from {
			bb = append(bb, block)

		}
		height--
		if len(block.PrevBlockHash) == 0 {
			break
		}
	}

	reversed := []*Block{}
	for i := range bb {
		n := bb[len(bb)-1-i]
		reversed = append(reversed, &n)
	}

	return reversed, nil
}

// GetBlockByHash gets the block given its hash
func (bc *Blockchain) GetBlockByHash(hash string) (bb Block, err error) {
	bci := bc.Iterator()
	for {
		block := bci.Next()
		if hexutil.Encode(block.Hash) == hash {
			return block, nil
		}

		if len(block.PrevBlockHash) == 0 {
			break
		}
	}
	return bb, errors.New("block was not found")
}

// AddBalanceTo adds balance to address
func (bc *Blockchain) AddBalanceTo(address string, amount *big.Int) error {
	addressData, merror := bc.GetAddressData(address)
	if merror == AddressDecodeError {
		return errors.New("Unable to decode address")
	}

	if merror == NoBalance {
		addressData.Balance = []byte("0x0")
		addressData.Nounce = []byte("0x0")
		merror = NoError
	}

	if merror == NoError {

		currentBalance, err := hexutil.DecodeBig(string(addressData.Balance))
		if err != nil {
			log.Fatal("From balance couldnt be parsed.")
		}
		currentBalance = currentBalance.Add(currentBalance, amount)
		addressData.Balance = []byte(hexutil.EncodeBig(currentBalance))

		var result bytes.Buffer
		encoder := gob.NewEncoder(&result)
		err = encoder.Encode(&addressData)
		if err != nil {
			log.Panic(err)
		}

		err = bc.db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(AccountsBucket))
			bts := result.Bytes()
			err = b.Put([]byte(address), bts)
			if err != nil {
				return err
			}
			return nil
		})

		if err != nil {
			return err
		}
	}

	return nil
}

// SubBalanceOf subtracts amount of address
func (bc *Blockchain) SubBalanceOf(address string, amount *big.Int, nounce string) error {
	addressData, merror := bc.GetAddressData(address)
	if merror == AddressDecodeError {
		return errors.New("Unable to decode address")
	}

	if merror == NoBalance {
		return errors.New("No enough balance")
	}

	if merror == NoError {
		currentBalance, err := hexutil.DecodeBig(string(addressData.Balance))
		if err != nil {
			log.Fatal("From balance couldnt be parsed.")
		}
		currentBalance = currentBalance.Sub(currentBalance, amount)
		addressData.Balance = []byte(hexutil.EncodeBig(currentBalance))
		addressData.Nounce = []byte(nounce)

		var result bytes.Buffer
		encoder := gob.NewEncoder(&result)
		err = encoder.Encode(&addressData)
		if err != nil {
			log.Panic(err)
		}

		err = bc.db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(AccountsBucket))
			bts := result.Bytes()
			err = b.Put([]byte(address), bts)
			if err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// MutateAddressStateFromTransaction mutates the state of an address from a transaction
func (bc *Blockchain) MutateAddressStateFromTransaction(transaction Transaction, isCoinbase bool) (err error) {

	ok := false
	if !isCoinbase {
		ok, err = bc.IsValidTransaction(transaction)
		if err != nil {
			log.Fatal("State Mutation: Transaction is invalid ", hex.EncodeToString(transaction.Hash))
		}
	} else {
		ok = true
	}

	if ok {
		if !isCoinbase {
			// no need to check for errs as it has been done before sealing
			txValue, _ := hexutil.DecodeBig(transaction.Value)
			txFees, _ := hexutil.DecodeBig(transaction.TransactionFees)
			txValue = txValue.Add(txValue, txFees)
			err := bc.SubBalanceOf(transaction.From, txValue, transaction.Nounce)
			if err != nil {
				log.Fatal("Unable to subtract balance ", err)
			}
		}

		// to will always be required
		txValue, _ := hexutil.DecodeBig(transaction.Value)
		txFees, _ := hexutil.DecodeBig(transaction.TransactionFees)

		err := bc.AddBalanceTo(transaction.To, txValue)
		if err != nil {
			log.Fatal("Unable to add balance to address ", err)
		}
		err = bc.AddBalanceTo(GetBlockchainSettings().Verifiers[0].Address, txFees)
		if err != nil {
			log.Fatal("Unable to add balance to verifier ", err)
		}
	}

	return nil
}

// HasThisBalance checks if there is enough balance and returns the current nounce too
func (bc *Blockchain) HasThisBalance(address string, amount *big.Int) (bool, *big.Int, *big.Int, error) {
	addressData, err := bc.GetAddressData(address)
	if err == AddressDecodeError {
		return false, nil, nil, errors.New("Unable to decode address")
	}

	if err == NoBalance {
		return false, nil, nil, errors.New("No enough balance")
	}

	if err == NoError {
		// go on check if there is enough balance

		blncInt, err := hexutil.DecodeBig(string(addressData.Balance))
		nounceInt, err := hexutil.DecodeBig(string(addressData.Nounce))
		if err != nil {
			log.Fatal(err)
			return false, nil, nil, errors.New("Unable unable to convert db byte to hex and big ints")
		}

		cmpRes := blncInt.CmpAbs(amount)
		if cmpRes == -1 {
			return false, nil, nil, errors.New("No enough balance")
		} else {
			return true, blncInt, nounceInt, nil
		}
	}
	return false, nil, nil, errors.New("No enough balance")
}

// SignTransaction signs a transaction with privatekey
func (bc *Blockchain) SignTransaction(transaction Transaction, key *keystore.Key) (Transaction, error) {
	data := bytes.Join(
		[][]byte{
			[]byte(transaction.PubKey),
			[]byte(transaction.Nounce),
			transaction.Data,
			[]byte(transaction.From),
			[]byte(transaction.To),
			[]byte(transaction.Value),
			[]byte(transaction.TransactionFees),
		},
		[]byte{},
	)

	hash := sha256.Sum256(data)
	transaction.Hash = hash[:]

	bts, err := key.Private.Sign(transaction.Hash)
	if err != nil {
		return transaction, err
	}
	transaction.Signature = bts
	return transaction, nil
}

// IsValidTransaction checks if a tx is valid
func (bc *Blockchain) IsValidTransaction(transaction Transaction) (bool, error) {
	zero, _ := new(big.Int).SetString("0", 10)
	if len(transaction.Hash) == 0 || transaction.Hash == nil {
		return false, errors.New("Hash is empty")
	}

	if transaction.From == "" {
		return false, errors.New("From is empty")
	}

	if transaction.Nounce == "" {
		return false, errors.New("Nounce is empty")
	}

	if transaction.PubKey == "" {
		return false, errors.New("PubKey is empty")
	}

	if transaction.To == "" {
		return false, errors.New("To is empty")
	}
	if transaction.TransactionFees == "" {
		return false, errors.New("TransactionFees is empty")
	}

	if transaction.Value == "" {
		return false, errors.New("Value is empty")
	}

	val, err := hexutil.DecodeBig(transaction.Value)
	if err != nil {
		return false, errors.New("Value is malformed")
	}

	if val.Cmp(zero) == -1 {
		return false, errors.New("Value is negative")
	}

	valFees, err := hexutil.DecodeBig(transaction.TransactionFees)
	if valFees.Cmp(zero) == -1 {
		return false, errors.New("Value is negative")
	}

	data := bytes.Join(
		[][]byte{
			[]byte(transaction.PubKey),
			[]byte(transaction.Nounce),
			transaction.Data,
			[]byte(transaction.From),
			[]byte(transaction.To),
			[]byte(transaction.Value),
			[]byte(transaction.TransactionFees),
		},
		[]byte{},
	)

	hash := sha256.Sum256(data)

	if !reflect.DeepEqual(transaction.Hash, hash[:]) {
		return false, errors.New("transaction is altered and doesn't match the hash")
	}

	pubBytesFromHex, _ := hexutil.Decode(transaction.PubKey)
	newPub, _ := crypto.RestorePubKey(pubBytesFromHex)
	ok, err := newPub.Verify(transaction.Hash, transaction.Signature)
	if err != nil {
		return false, err
	}

	pbkbts, err := newPub.Raw()
	if err != nil {
		return false, err
	}
	if transaction.From != "0x"+crypto.PublicToAddress(pbkbts) && transaction.From != "0X"+crypto.PublicToAddress(pbkbts) {
		return false, errors.New("signer and sender mismatch")
	}

	if ok {
		return true, nil
	}
	return false, nil
}

// GetNounceFromMemPool gets the biggest noune from the mempool
func (bc *Blockchain) GetNounceFromMemPool(address string) (string, error) {
	bc.MemPoolMux.Lock()
	defer bc.MemPoolMux.Unlock()

	var tmpInt uint64
	txs := []Transaction{}
	for _, v := range bc.MemPool {
		if v.From == address {
			nounceInt, _ := hexutil.DecodeUint64(v.Nounce)
			if nounceInt > tmpInt {
				tmpInt = nounceInt
			}
			txs = append(txs, v)
		}
	}
	if len(txs) > 0 {
		for _, v := range bc.MemPool {
			if v.From == address {
				nounceInt, _ := hexutil.DecodeUint64(v.Nounce)
				if nounceInt == tmpInt {
					return v.Nounce, nil
				}
			}
		}
	}
	return "", errors.New("No nounce in mempool")
}

// AddBlockPool adds a block to the blockpool and performs db storage + state mutations + mempool cleaning from txs
func (bc *Blockchain) AddBlockPool(block Block) error {
	bc.BlockPoolMux.Lock()
	defer bc.BlockPoolMux.Unlock()
	for _, v := range bc.BlockPool {
		if reflect.DeepEqual(v.Hash, block.Hash) {
			return errors.New("a block with the same hash is already in blockpool")
		}

	}

	// chceck if the block is within the db already
	// blockAlreadyInDb := false
	// bc.TraverseChain(func(blc Block) {
	// 	if reflect.DeepEqual(blc.Hash, block.Hash) {
	// 		blockAlreadyInDb = true
	// 	}
	// })

	// if blockAlreadyInDb {
	// 	return errors.New("a block with the same hash is already in the db")
	// }

	bc.BlockPool = append(bc.BlockPool, block)

	// check the chain and append the one which apply
	// 1. get the last hash from db
	last := []byte{}
	bc.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		v := b.Get([]byte("l"))

		last = make([]byte, len(v))
		copy(last, v)

		if v == nil {
			return errors.New("Value doesn't exists")
		}
		return nil
	})

	// 2. go through all the blocks in pool
	for {
		found := false
		for _, v := range bc.BlockPool {
			// 3. if there is a block which matches the previous hash then insert and start the process again
			if reflect.DeepEqual(v.PrevBlockHash, last) {
				found = true
				err := bc.db.Update(func(tx *bolt.Tx) error {
					b := tx.Bucket([]byte(blocksBucket))
					err := b.Put(v.Hash, Serialize(v))
					if err != nil {
						log.Panic(err)
					}

					err = b.Put([]byte("l"), v.Hash)
					if err != nil {
						log.Panic(err)
					}

					bc.tip = v.Hash

					return nil
				})

				if err != nil {
					log.Fatal("Error while persisting from blockpool to db ", err)
				}

				// mutate the state
				for _, vc := range v.Transactions {
					isCoinbase := vc.From == "" && vc.Nounce == "0x0" && vc.TransactionFees == "0x0"
					err := bc.MutateAddressStateFromTransaction(*vc, isCoinbase)
					if err != nil {
						log.Println("mutation error", err)

					}
					bc.RemoveMemPool(vc)
				}
				bc.AddHeight(1)
				bc.removeBlockPool(&v)
			}
		}

		if !found {
			break
		}
	}

	// if blockPool len > 0, some blocks are missing so trigger a sync here
	if len(bc.BlockPool) > 0 && !bc.Node.IsSyncing() {
		bc.Node.BlockService.Node.SetSyncing(false)
		bc.Node.Sync(context.Background())

	}
	// if len(bc.BlockPool) > 0 {
	// 	bc.Node.BlockService.Node.SetSyncing(false)
	// 	bc.Node.Sync(context.Background())
	// }

	return nil
}

// ClearBlockPool clears the blockpool
func (bc *Blockchain) ClearBlockPool() {
	bc.BlockPoolMux.Lock()
	bc.BlockPool = []Block{}
	bc.BlockPoolMux.Unlock()
}

func (bc *Blockchain) removeBlockPool(block *Block) error {
	for s, v := range bc.BlockPool {
		if reflect.DeepEqual(v.Hash, block.Hash) {
			bc.BlockPool = append(bc.BlockPool[:s], bc.BlockPool[s+1:]...)
			return nil
		}
	}
	return errors.New("Block not in blockpool")
}

// SerializeBlockPool serializes the blockpool to bytes
func (bc *Blockchain) SerializeBlockPool() ([]byte, error) {

	var result bytes.Buffer
	encoder := gob.NewEncoder(&result)

	err := encoder.Encode(bc.BlockPool)
	if err != nil {
		return nil, err
	}

	return result.Bytes(), nil
}

// PersistMemPoolToDB persists all transactions to the db
func (bc *Blockchain) PersistBlockPoolToDB() error {
	bc.BlockPoolMux.Lock()
	defer bc.BlockPoolMux.Unlock()
	if len(bc.BlockPool) > 0 {
		err := bc.db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(memPool))
			serialized, err := bc.SerializeBlockPool()
			if err != nil {
				return err
			}
			err = b.Put([]byte("blocks"), serialized)
			if err != nil {
				return err
			}
			log.Printf("Persisted %d bytes from blockpool to the database ", len(serialized))
			return nil
		})
		return err
	}

	return nil
}

// AddMemPool adds a transaction to the mempool
func (bc *Blockchain) AddMemPool(transaction Transaction) error {
	bc.MemPoolMux.Lock()
	// order matters otherwise deadlock
	defer bc.PersistMemPoolToDB()
	defer bc.MemPoolMux.Unlock()

	for idx, v := range bc.MemPool {
		if reflect.DeepEqual(v.Hash, transaction.Hash) {
			return errors.New("a transaction with the same hash is already in mempool")
		}
		if v.Nounce == transaction.Nounce && v.From == transaction.From {
			// we already have a transaction in mempool with this nounce
			// pick the one with higher fee
			txFees, err := hexutil.DecodeBig(transaction.TransactionFees)
			if err == nil {
				txFeesInMempool, inerr := hexutil.DecodeBig(v.TransactionFees)
				if inerr != nil {
					return errors.New("a transaction with the same nounce is already in mempool")
				}

				if txFees.Cmp(txFeesInMempool) == 1 {
					bc.MemPool[idx] = transaction
					return nil
				}

			}
			return errors.New("a transaction with the same nounce is already in mempool")
		}
	}
	bc.MemPool = append(bc.MemPool, transaction)

	return nil
}

// RemoveMemPool removes a transaction from mempool
func (bc *Blockchain) RemoveMemPool(transaction *Transaction) error {
	for s, v := range bc.MemPool {
		if reflect.DeepEqual(v.Hash, transaction.Hash) {
			bc.MemPool = append(bc.MemPool[:s], bc.MemPool[s+1:]...)
			return nil
		}
	}
	return errors.New("Transaction not in mempool")
}

// SerializeMemPool serializes the mempool txs to bytes
func (bc *Blockchain) SerializeMemPool() ([]byte, error) {

	var result bytes.Buffer
	encoder := gob.NewEncoder(&result)

	err := encoder.Encode(bc.MemPool)
	if err != nil {
		return nil, err
	}

	return result.Bytes(), nil
}

// PersistMemPoolToDB persists all transactions to the db
func (bc *Blockchain) PersistMemPoolToDB() error {
	bc.MemPoolMux.Lock()
	defer bc.MemPoolMux.Unlock()
	if len(bc.MemPool) > 0 {
		err := bc.db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(memPool))
			serialized, err := bc.SerializeMemPool()
			if err != nil {
				return err
			}
			err = b.Put([]byte("txs"), serialized)
			if err != nil {
				return err
			}
			log.Printf("Persisted %d bytes from mempool to the database ", len(serialized))
			return nil
		})
		return err
	}

	return nil
}

// LoadToMemPoolFromDB loads txs to mempool from db
func (bc *Blockchain) LoadToMemPoolFromDB() {
	bc.MemPoolMux.Lock()
	defer bc.MemPoolMux.Unlock()

	var transactions []Transaction
	var transactionsBytes []byte
	err := bc.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(memPool))
		v := b.Get([]byte("txs"))
		transactionsBytes = make([]byte, len(v))
		copy(transactionsBytes, v)

		if transactionsBytes == nil {
			return errors.New("Value doesn't exists")
		}
		return nil
	})

	if err == nil {
		decoder := gob.NewDecoder(bytes.NewReader(transactionsBytes))
		err := decoder.Decode(&transactions)
		if err != nil {
			return
		}
		bc.MemPool = transactions
	}
}

// MineBlock mines a new block with the provided transactions
func (bc *Blockchain) MineBlock(transactions []*Transaction) Block {

	var lastHash []byte

	err := bc.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		v := b.Get([]byte("l"))
		lastHash = make([]byte, len(v))
		copy(lastHash, v)

		return nil
	})

	if err != nil {
		log.Panic(err)
	}

	newBlock := NewBlock(transactions, lastHash, []byte{}, time.Now().Unix(), bc.Key)
	err = bc.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		err := b.Put(newBlock.Hash, Serialize(newBlock))
		if err != nil {
			log.Panic(err)
		}

		err = b.Put([]byte("l"), newBlock.Hash)
		if err != nil {
			log.Panic(err)
		}

		return nil
	})
	bc.tip = newBlock.Hash
	return newBlock
}

// Iterator returns a BlockchainIterat
func (bc *Blockchain) Iterator() *BlockchainIterator {
	bci := &BlockchainIterator{bc.tip, bc.db}

	return bci
}

type AddressDataResult int

const (
	// NoBalance
	NoBalance AddressDataResult = iota
	// AddressDecodeError
	AddressDecodeError
	// NoError
	NoError
)

// GetAddressData gets the state of an address
func (bc *Blockchain) GetAddressData(address string) (ads AddressState, merr AddressDataResult) {
	if !hexutil.Has0xPrefix(address) {
		address = "0x" + address
	}

	addrbytes := []byte(address)

	tmpError := NoError
	bc.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(AccountsBucket))

		addressData := b.Get(addrbytes)

		if addressData == nil || len(addressData) == 0 {
			tmpError = NoBalance
			return errors.New("No address state found")
		}

		decoder := gob.NewDecoder(bytes.NewReader(addressData))
		err := decoder.Decode(&ads)

		if err != nil {
			tmpError = AddressDecodeError
			return err
		}
		return nil
	})

	return ads, tmpError
}

type transform func(Block)

// TraverseChain goes through all the blocks
func (bc *Blockchain) TraverseChain(fn transform) {
	bci := bc.Iterator()
	for {
		block := bci.Next()
		fn(block)
		if len(block.PrevBlockHash) == 0 {
			break
		}
	}
}

// this was needed as the ordering of the bc.MemPool was buggy
type TxNounce struct {
	Hash        string
	Nounce      string
	Transaction Transaction
}

// PreparePoolBlocksForMining gets txs from mempool and prepares them
func (bc *Blockchain) PreparePoolBlocksForMining() []*Transaction {
	// 1. check if a tx is valid structure (hash, sig, etc.)
	// 2. check if the nounce is the next one of the current db nounce
	// 3. check if address has enough balance
	bc.MemPoolMux.Lock()
	defer bc.MemPoolMux.Unlock()
	log.Println("Preparing block for mining")
	log.Println("MemPool size ", len(bc.MemPool))

	txNounces := []TxNounce{}
	zeroBig, _ := hexutil.DecodeBig("0x0")
	// first remove any tx with invalid nounce and values + txfees
	for _, v := range bc.MemPool {
		vNounce, err := hexutil.DecodeBig(v.Nounce)
		vVal, err1 := hexutil.DecodeBig(v.Value)
		vTxFees, err2 := hexutil.DecodeBig(v.TransactionFees)
		if vNounce.Cmp(zeroBig) == -1 || vVal.Cmp(zeroBig) == -1 || vTxFees.Cmp(zeroBig) == -1 || err != nil || err1 != nil || err2 != nil {
			log.Println("Invalid transaction nounce found at stage one ", hexutil.Encode(v.Hash))
			bc.RemoveMemPool(&v)
			continue
		}

		txNounces = append(txNounces, TxNounce{Hash: hexutil.Encode(v.Hash), Nounce: v.Nounce, Transaction: v})
	}

	//sort the trasactions by address and nounce
	sort.Slice(txNounces, func(i, j int) bool {
		num1, _ := hexutil.DecodeBig(bc.MemPool[i].Nounce)
		num2, _ := hexutil.DecodeBig(bc.MemPool[j].Nounce)
		return num1.Cmp(num2) == -1
	})

	verifiedTxs := []*Transaction{}
	vbalances := make(map[string]*big.Int)
	for _, t := range txNounces {

		v := t.Transaction

		val, err := hexutil.DecodeBig(v.Value)
		if err != nil {
			log.Println("Invalid transaction value found: ", hexutil.Encode(v.Hash))
			bc.RemoveMemPool(&v)
			continue
		}

		txf, err := hexutil.DecodeBig(v.TransactionFees)
		if err != nil {
			log.Println("Invalid transaction fee found: ", hexutil.Encode(v.Hash))
			bc.RemoveMemPool(&v)
			continue
		}

		hasBalance, currentBalance, currentNounce, err := bc.HasThisBalance(v.From, val.Add(val, txf))
		if err != nil {
			log.Println("Invalid balanace found: ", hexutil.Encode(v.Hash))
			bc.RemoveMemPool(&v)
			continue
		}

		if !hasBalance {
			log.Println("Invalid balanace found: ", hexutil.Encode(v.Hash))
			bc.RemoveMemPool(&v)
			continue
		}

		// check the validity of the signatures
		ok, err := bc.IsValidTransaction(v)
		if err != nil || !ok {
			log.Println("Transaction is invalid: ", hexutil.Encode(v.Hash))
			bc.RemoveMemPool(&v)
			continue
		}

		var oneBig, _ = new(big.Int).SetString("1", 10)
		var newNouncePlusOne, _ = new(big.Int).SetString("0", 10)
		newNouncePlusOne = newNouncePlusOne.Add(currentNounce, oneBig)
		txNounceBigInt, err := hexutil.DecodeBig(v.Nounce)

		// if txnounce is smaller than what is in the db then discard it
		if txNounceBigInt.Cmp(currentNounce) < 1 {
			log.Println("Invalid nounce found: ", hexutil.Encode(v.Hash))
			bc.RemoveMemPool(&v)
			continue
		}

		// if tx nounce is greater than the currentdbnounce+1 AND is not in verifiedTx(biggest by addr) then continue we save it for future
		if txNounceBigInt.Cmp(newNouncePlusOne) > 0 {
			isFutureTx := true
			for _, vtx := range verifiedTxs {
				if vtx.From == v.From {
					indxVtxNounce, _ := hexutil.DecodeBig(vtx.Nounce)
					indxVtxNounce = indxVtxNounce.Add(indxVtxNounce, oneBig)
					if indxVtxNounce.Cmp(txNounceBigInt) == 0 {
						// we found the next nounce now check in virtual balances and not db
						isFutureTx = false
						break
					}
				}
			}
			if isFutureTx {
				continue
			}
		}

		isInVerified := false
		for _, hh := range verifiedTxs {
			if hexutil.Encode(hh.Hash) == hexutil.Encode(v.Hash) {
				isInVerified = true
				break
			}
		}

		if !isInVerified {
			abalance, ok := vbalances[v.From]
			if !ok {
				txVal, _ := hexutil.DecodeBig(v.Value)
				txFees, _ := hexutil.DecodeBig(v.TransactionFees)
				txVal = txVal.Add(txVal, txFees)
				if currentBalance.Cmp(txVal) < 0 {
					bc.RemoveMemPool(&v)
					continue
				}

				remainingBalance := currentBalance.Sub(currentBalance, txVal)
				vbalances[v.From] = remainingBalance
			} else {
				// already found in verified array
				// subtract from there and not db account balanace
				txVal, _ := hexutil.DecodeBig(v.Value)
				txFees, _ := hexutil.DecodeBig(v.TransactionFees)
				txVal = txVal.Add(txVal, txFees)

				if abalance.Cmp(txVal) < 0 {
					log.Warn("Not enough balance")
					bc.RemoveMemPool(&v)
					continue
				}

				remainingBalance := abalance.Sub(abalance, txVal)
				vbalances[v.From] = remainingBalance
			}
			verifiedTxs = append(verifiedTxs, &v)
		}
		bc.RemoveMemPool(&v)
	}
	return verifiedTxs
}

// CalculateReward calculates the reward for each block given the begining of the genesis timestamp
func (bc *Blockchain) CalculateReward() string {
	var blockReward, _ = new(big.Int).SetString(GetBlockchainSettings().InitialBlockReward, 10)
	return hexutil.EncodeBig(blockReward)
}

// MineScheduler starts the mining process every x seconds
func (bc *Blockchain) MineScheduler() {
	for {
		<-time.After(time.Duration(GetBlockchainSettings().BlockTimeSeconds) * time.Second)

		txs := bc.PreparePoolBlocksForMining()

		for _, v := range txs {
			log.Info("prepareing to seal tx ", hexutil.Encode(v.Hash), " with nounce: ", v.Nounce)
		}
		cbtx := Transaction{
			From:            "",
			To:              GetBlockchainSettings().Verifiers[0].Address,
			Data:            []byte(""),
			Value:           bc.CalculateReward(),
			PubKey:          GetBlockchainSettings().Verifiers[0].PublicKey,
			TransactionFees: "0x0",
			Nounce:          "0x0",
		}

		cbtx, err := bc.SignTransaction(cbtx, bc.Key)
		if err != nil {
			log.Fatal("Unable to sign coinbase transaction")
		}

		blockTxs := []*Transaction{}
		blockTxs = append(blockTxs, &cbtx)
		blockTxs = append(blockTxs, txs...)
		minedBlock := bc.MineBlock(blockTxs)
		minedBlockData := Serialize(minedBlock)
		for _, v := range minedBlock.Transactions {
			isCoinbase := v.From == "" && v.Nounce == "0x0" && v.TransactionFees == "0x0"
			err := bc.MutateAddressStateFromTransaction(*v, isCoinbase)
			if err != nil {
				log.Println("mutation error", err, isCoinbase)
			}
		}
		bc.AddHeight(1)
		// minedBlock.LogDetails()

		// broadcast the block
		blk := GossipPayload{
			Type:    GossipPayload_BLOCK,
			Payload: minedBlockData,
		}

		log.Println("Broadcasting nodes: ", bc.Node.Peers().Len())
		blkBts, err := proto.Marshal(&blk)
		if err != nil {
			log.Warn("Error while marshaling block to protobuff: ", err)
		} else {
			// if bc.Node.Peers().Len() > 1 {
			go bc.Node.Gossip.Broadcast(blkBts)
			// }
		}

	}
}

// Next returns next block starting from the tip
func (i *BlockchainIterator) Next() Block {
	var blckDt []byte
	err := i.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		v := b.Get(i.currentHash)
		blckDt = make([]byte, len(v))
		copy(blckDt, v)
		return nil
	})

	block, _ := DeserializeBlock(blckDt)

	if err != nil {
		log.Panic(err)
	}

	i.currentHash = block.PrevBlockHash
	return block
}

func dbExists(filePath string) bool {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return false
	}
	return true
}

// CreateOrLoadBlockchain creates a new blockchain DB
func CreateOrLoadBlockchain(n *Node, dataDir string, mineKeypath string, mineKeyPass string) *Blockchain {
	filePath := dataDir + "/db/blockchain.db"
	if !common.FileExists(filePath) {
		os.MkdirAll(dataDir+"/db/", os.ModePerm)
	}
	var tip []byte
	db, err := bolt.Open(filePath, 0600, nil)
	if err != nil {
		log.Panic(err)
	}

	bc := Blockchain{
		tip:      tip,
		db:       db,
		FilePath: filePath,
		Key: &keystore.Key{
			KeyPair: &crypto.KeyPair{
				Address: "",
				Private: nil,
			},
		},
		Height:       0,
		Node:         n,
		BlockPoolMux: sync.Mutex{},
		MemPoolMux:   sync.Mutex{},
		HeightMux:    sync.Mutex{},
	}

	if mineKeypath != "" {
		bts, err := ioutil.ReadFile(mineKeypath)
		if err != nil {
			log.Fatal("Unable to read the node identity file")
		}
		key, err := keystore.UnmarshalKey(bts, mineKeyPass)

		if err != nil {
			log.Fatal(err)
		}

		bc.Key = key
		keyAddr := "0x" + bc.Key.Address
		foundKey := false
		for _, v := range GetBlockchainSettings().Verifiers {
			if v.Address == keyAddr {
				foundKey = true
			}
		}

		if !foundKey {
			log.Fatal("Verification can be done by the genesis verifiers only")
		}
	}

	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		if b == nil {

			var txVal, _ = new(big.Int).SetString(GetBlockchainSettings().Verifiers[0].InitialBalance, 10)

			cbtx := Transaction{
				From:  "",
				To:    GetBlockchainSettings().Verifiers[0].Address,
				Data:  []byte("Whoever would overthrow the liberty of a nation must begin by subduing the freeness of speech"),
				Value: hexutil.EncodeBig(txVal),
			}

			cbtx.Hash = GetTransactionID(&cbtx)

			var genesisTimestamp int64
			genesisTimestamp = 1257894000

			block := Block{Timestamp: genesisTimestamp, Data: []byte("Whoever would overthrow the liberty of a nation must begin by subduing the freeness of speech"), PrevBlockHash: []byte{}, Hash: []byte{}, Signature: []byte{}, Transactions: []*Transaction{&cbtx}}

			data := bytes.Join(
				[][]byte{
					IntToHex(block.Timestamp),
					block.Data,
					block.PrevBlockHash,
					block.HashTransactions(),
				},
				[]byte{},
			)

			hash := sha256.Sum256(data)
			block.Hash = hash[:]
			log.Println("Genesis block hash ", hex.EncodeToString(block.Hash))

			// create the buckets
			accBucket, err := tx.CreateBucket([]byte(AccountsBucket))
			if err != nil {
				log.Panic(err)
			}

			var nounceVal, _ = new(big.Int).SetString("1", 10)

			adState := &AddressState{
				Balance: []byte(hexutil.EncodeBig(txVal)),
				Nounce:  []byte(hexutil.EncodeBig(nounceVal)),
			}

			var result bytes.Buffer
			encoder := gob.NewEncoder(&result)

			err = encoder.Encode(adState)
			if err != nil {
				log.Panic(err)
			}

			err = accBucket.Put([]byte(GetBlockchainSettings().Verifiers[0].Address), result.Bytes())

			tx.CreateBucket([]byte(memPool))

			b, err := tx.CreateBucket([]byte(blocksBucket))
			if err != nil {
				log.Panic(err)
			}

			err = b.Put(block.Hash, Serialize(block))
			if err != nil {
				log.Panic(err)
			}

			err = b.Put([]byte("l"), block.Hash)
			if err != nil {
				log.Panic(err)
			}
			tip = block.Hash
			bc.tip = make([]byte, len(tip))
			copy(bc.tip, tip)

		} else {
			tip = b.Get([]byte("l"))
			bc.tip = make([]byte, len(tip))
			copy(bc.tip, tip)

		}

		return nil
	})

	if err != nil {
		log.Panic(err)
	}

	log.Println("Verifying blocks")
	bc.TraverseChain(func(blc Block) {
		bc.Height += 1
		if hex.EncodeToString(blc.Hash) != GenesisBlockHash {
			if !ValidateBlock(blc) {
				log.Fatal("Block" + hex.EncodeToString(blc.Hash) + " couldn't be verified")
			}
		}
	})

	log.Println("Finished verifying blocks")

	if bc.Key.Address != "" {
		go bc.MineScheduler()
	}

	return &bc
}
