package utils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/nbd-wtf/go-nostr/nip19"
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

func GetBtcPrivateKeyFromNsec(nsec string) (*btcec.PrivateKey, error) {
	// Try to decode as NIP19 bech32 format first
	prefix, decodedValue, err := nip19.Decode(nsec)
	if err != nil {
		return nil, fmt.Errorf("invalid nip19 npub format: %w", err)
	}
	if prefix != "nsec" {
		return nil, fmt.Errorf("npub is not valid: %w", err)
	}

	privKeyStr, ok := decodedValue.(string)
	if !ok {
		return nil, fmt.Errorf("nip19 decode returned unexpected type: %T", decodedValue)
	}
	keyBytes, err := hex.DecodeString(privKeyStr)
	if err != nil {
		return nil, fmt.Errorf("hex.DecodeString(privKey): %T", decodedValue)
	}

	privkey, _ := btcec.PrivKeyFromBytes(keyBytes)

	return privkey, nil
}
