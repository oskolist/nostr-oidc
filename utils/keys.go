package utils

import (
	"crypto/rand"
	"fmt"
)

// GenerateRandomKey generates a cryptographically random 32-byte key.
// The key is returned as a byte slice.
func GenerateRandomKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}
	return key, nil
}
