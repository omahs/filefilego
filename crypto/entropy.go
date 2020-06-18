package crypto

import (
	"crypto/rand"
	"errors"
	"io"
)

// RandomEntropy bytes from rand.Reader
func RandomEntropy(length int) ([]byte, error) {
	buf := make([]byte, length)
	n, err := io.ReadFull(rand.Reader, buf)
	if err != nil || n != length {
		return nil, errors.New("Cant read random bytes")
	}
	return buf, nil
}
