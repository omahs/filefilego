package keystore

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// UnlockedAccount
type UnlockedAccount struct {
	Key *Key
	JWT string
}

// KeyStore
type KeyStore struct {
	keyDir              string
	UnlockedAccounts    map[string]UnlockedAccount
	UnlockedAccountsMux sync.Mutex
}

// NewKeyStore
func NewKeyStore(keyDir string) *KeyStore {
	const dirPerm = 0777
	if err := os.MkdirAll(keyDir, dirPerm); err != nil {
		return nil
	}
	return &KeyStore{
		keyDir:           keyDir,
		UnlockedAccounts: make(map[string]UnlockedAccount),
	}
}

// NewAccount
func (ks *KeyStore) NewAccount(passphrase string) string {
	_, filename := NewKeyAndStoreToFile(passphrase, ks.keyDir)
	return filename
}

// LockAccount removes the account from unlocks
func (ks *KeyStore) LockAccount(address string, jwt string) (string, error) {
	ks.UnlockedAccountsMux.Lock()
	defer ks.UnlockedAccountsMux.Unlock()
	acc, ok := ks.UnlockedAccounts[address]
	if ok && acc.JWT == jwt {
		delete(ks.UnlockedAccounts, address)
		return "success", nil
	}
	return "", errors.New("Account not found")
}

// Authorized checks if a token is authorized and valid
func (ks *KeyStore) Authorized(tok string) (bool, string, *UnlockedAccount, error) {
	// encrypt/decrypt the jwts using the node identity file
	unlockedAcc := &UnlockedAccount{}
	nodeIdBts, err := ioutil.ReadFile(ks.keyDir + "/node_identity.json")
	if err != nil {
		return false, "", unlockedAcc, err
	}

	token, err := jwt.Parse(tok, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return nodeIdBts, nil
	})

	if err != nil {
		return false, "", unlockedAcc, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	var address string
	if ok && token.Valid {
		addr, okk := claims["address"].(string)
		address = addr
		if !okk {
			return false, "", unlockedAcc, errors.New("couldn't extract address from jwt")
		}

		unlc, found := ks.UnlockedAccounts[address]
		if !found {
			return false, "", unlockedAcc, errors.New("address is not unlocked")
		}

		unlockedAcc = &unlc
	}

	return true, address, unlockedAcc, nil
}

// UnlockAccount unlocks an account by address
func (ks *KeyStore) UnlockAccount(address string, passphrase string) (string, error) {
	ks.UnlockedAccountsMux.Lock()
	defer ks.UnlockedAccountsMux.Unlock()

	nodeIdBts, err := ioutil.ReadFile(ks.keyDir + "/node_identity.json")
	if err != nil {
		return "", err
	}

	files, err := ioutil.ReadDir(ks.keyDir)
	if err != nil {
		return "", err
	}

	for _, file := range files {
		if strings.Contains(file.Name(), address) {
			bts, err := ioutil.ReadFile(ks.keyDir + "/" + file.Name())
			if err != nil {
				return "", err
			}
			key, err := UnmarshalKey(bts, passphrase)
			if err != nil {
				return "", err
			}

			atClaims := jwt.MapClaims{}
			atClaims["address"] = address
			// 90 days
			atClaims["exp"] = time.Now().Add(time.Hour * 2160).Unix()
			at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
			token, err := at.SignedString(nodeIdBts)
			if err != nil {
				return "", err
			}
			ks.UnlockedAccounts[address] = UnlockedAccount{
				Key: key,
				JWT: token,
			}
			return token, nil
		}
	}

	return "", errors.New("Address not available within this node")
}

// ListAccounts
func (ks *KeyStore) ListAccounts() []string {
	var files []string
	err := filepath.Walk(ks.keyDir, func(path string, info os.FileInfo, err error) error {
		if strings.Contains(path, "UTC") {
			prts := strings.Split(path, "--")
			files = append(files, prts[2])
		}
		return nil
	})

	if err != nil {
		panic(err)
	}
	return files
}
