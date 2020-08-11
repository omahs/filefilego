package keystore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/pborman/uuid"
	"github.com/filefilego/filefilego/crypto"
	"golang.org/x/crypto/scrypt"
)

var (
	nameKDF      = "scrypt"
	scryptKeyLen = 32
	scryptN      = 1 << 18
	scryptR      = 8
	scryptP      = 1
	ksVersion    = 3
	ksCipher     = "aes-128-ctr"
)

// Key
type Key struct {
	*crypto.KeyPair
	ID uuid.UUID
}

func WriteDataToFile(data []byte, filePath string) (string, error) {

	const dirPerm = 0770
	if err := os.MkdirAll(filepath.Dir(filePath), dirPerm); err != nil {
		return "", err
	}
	file, err := os.Create(filePath)
	if err != nil {
		return "nil", err
	}
	defer file.Close()
	file.Write(data)
	return filePath, nil
}

// NewKey new Key
func NewKey() *Key {
	keypair, err := crypto.GenerateKeyPair()
	if err != nil {
		log.Fatal("Unable to create keypair")
	}

	return &Key{
		ID:      uuid.NewRandom(),
		KeyPair: &keypair,
	}
}

// NewKeyAndStoreToFile
func NewKeyAndStoreToFile(passphrase string, keyDir string) (*Key, string) {
	key := NewKey()
	keyDataJSON, err := key.MarshalJSON(passphrase)
	if err != nil {
		log.Fatalf("Error encrypting: %v", err)
	}
	fileName, err := WriteDataToFile(keyDataJSON, filepath.Join(keyDir, createFileName(key.KeyPair.Address)))
	if err != nil {
		log.Fatalf("Error writing keystore file: %v", err)
	}
	return key, fileName
}

// MarshalJSON
func (key *Key) MarshalJSON(passphrase string) ([]byte, error) {
	salt, err := crypto.RandomEntropy(32)
	if err != nil {
		return nil, err
	}
	dk, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return nil, err
	}
	iv, err := crypto.RandomEntropy(aes.BlockSize)
	if err != nil {
		return nil, err
	}
	enckey := dk[:16]

	privateKeyBytes, err := key.KeyPair.Private.Bytes()
	privateKeyBytes = privateKeyBytes[4:]
	if err != nil {
		return nil, err
	}
	aesBlock, err := aes.NewCipher(enckey)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(aesBlock, iv)
	cipherText := make([]byte, len(privateKeyBytes))
	stream.XORKeyStream(cipherText, privateKeyBytes)

	mac := crypto.Keccak256(dk[16:32], cipherText)
	cipherParamsJSON := cipherparamsJSON{
		IV: hex.EncodeToString(iv),
	}

	sp := ScryptParams{
		N:          scryptN,
		R:          scryptR,
		P:          scryptP,
		DKeyLength: scryptKeyLen,
		Salt:       hex.EncodeToString(salt),
	}

	keyjson := cryptoJSON{
		Cipher:       ksCipher,
		CipherText:   hex.EncodeToString(cipherText),
		CipherParams: cipherParamsJSON,
		KDF:          nameKDF,
		KDFParams:    sp,
		MAC:          hex.EncodeToString(mac),
	}

	encjson := encryptedKeyJSON{
		Address: key.KeyPair.Address,
		Crypto:  keyjson,
		ID:      key.ID.String(),
		Version: ksVersion,
	}
	data, err := json.MarshalIndent(&encjson, "", "  ")
	if err != nil {
		return nil, err
	}
	return data, nil
}

func createFileName(address string) string {
	ts := time.Now().UTC()
	return fmt.Sprintf("UTC--%s--%s.json", toISO8601(ts), "0x"+address)
}

func toISO8601(t time.Time) string {
	var tz string
	name, offset := t.Zone()
	if name == "UTC" {
		tz = "Z"
	} else {
		tz = fmt.Sprintf("%03d00", offset/3600)
	}
	return fmt.Sprintf("%04d-%02d-%02dT%02d-%02d-%02d.%09d%s", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), tz)
}

// UnmarshalKey decrypts the private key
func UnmarshalKey(data []byte, passphrase string) (*Key, error) {
	encjson := encryptedKeyJSON{}
	err := json.Unmarshal(data, &encjson)
	if err != nil {
		return &Key{}, err
	}
	if encjson.Version != ksVersion {
		return &Key{}, errors.New("Version Mismatch")
	}
	if encjson.Crypto.Cipher != ksCipher {
		return &Key{}, errors.New("Cipher Mismatch")
	}
	mac, err := hex.DecodeString(encjson.Crypto.MAC)
	iv, err := hex.DecodeString(encjson.Crypto.CipherParams.IV)
	salt, err := hex.DecodeString(encjson.Crypto.KDFParams.Salt)
	ciphertext, err := hex.DecodeString(encjson.Crypto.CipherText)
	dk, err := scrypt.Key([]byte(passphrase), salt, encjson.Crypto.KDFParams.N, encjson.Crypto.KDFParams.R, encjson.Crypto.KDFParams.P, encjson.Crypto.KDFParams.DKeyLength)
	if err != nil {
		return &Key{}, err
	}
	hash := crypto.Keccak256(dk[16:32], ciphertext)
	if !bytes.Equal(hash, mac) {
		return &Key{}, errors.New("Mac Mismatch")
	}
	aesBlock, err := aes.NewCipher(dk[:16])
	if err != nil {
		return &Key{}, err
	}
	stream := cipher.NewCTR(aesBlock, iv)
	outputkey := make([]byte, len(ciphertext))
	stream.XORKeyStream(outputkey, ciphertext)
	privKey, err := crypto.RestorePrivateKey(outputkey)

	return &Key{
		ID: uuid.UUID(encjson.ID),
		KeyPair: &crypto.KeyPair{
			Private: privKey,
			Address: encjson.Address,
		},
	}, nil
}
