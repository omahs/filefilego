package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"os"

	log "github.com/sirupsen/logrus"

	crypto "github.com/libp2p/go-libp2p-core/crypto"
	sha3 "golang.org/x/crypto/sha3"
)

// KeyPair
type KeyPair struct {
	Private crypto.PrivKey
	Address string
}

// GenerateKeyPair returns a new keypair
func GenerateKeyPair() (KeyPair, error) {
	priv, pub, err := crypto.GenerateKeyPair(crypto.Secp256k1, 256)
	if err != nil {
		return KeyPair{}, err
	}
	publicBytes, err := pub.Raw()
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{Private: priv, Address: PublicToAddress(publicBytes)}, nil
}

// RestorePrivateKey unmarshals the privateKey
func RestorePrivateKey(privateKey []byte) (crypto.PrivKey, error) {
	return crypto.UnmarshalSecp256k1PrivateKey(privateKey)
}

// RestorePubKey unmarshals the pubKey
func RestorePubKey(pubKey []byte) (crypto.PubKey, error) {
	return crypto.UnmarshalSecp256k1PublicKey(pubKey)
}

// RestorePrivateToKeyPair unmarshals the privateKey and returns a the priv as well the pub keys
func RestorePrivateToKeyPair(privateKey []byte) (crypto.PrivKey, crypto.PubKey, error) {
	priv, err := RestorePrivateKey(privateKey)
	pub := priv.GetPublic()
	if err != nil {
		return priv, pub, err
	}
	return priv, pub, nil
}

// PublicToAddress returns the address of a public key
func PublicToAddress(data []byte) string {
	return hex.EncodeToString(Keccak256(data)[12:])
}

//Keccak256 return sha3 of a given byte array
func Keccak256(data ...[]byte) []byte {
	d := sha3.NewLegacyKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}

// Sha256Hash hashes data with the sha256
func Sha256Hash(data []byte) hash.Hash {
	d := sha3.New256()
	d.Write(data)
	return d
}

// HashFile hashes the file with the sha256
func HashFile(file io.Reader) []byte {
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		log.Fatal(err)
	}
	return h.Sum(nil)
}

// HashFilePath hashes the file that exists in the filePath with the sha256
func HashFilePath(filePath string) ([]byte, error) {
	if file, err := os.Open(filePath); err == nil {
		defer file.Close()
		return HashFile(file), nil
	} else {
		return nil, err
	}
}
