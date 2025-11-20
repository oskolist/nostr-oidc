package libsecret

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/zalando/go-keyring"
)

const Service = "nostr-oidc"

var (
	ErrNotFound = errors.New("Could not found value in keystore")
)

func SetSecret(id []byte, secret []byte) error {
	return keyring.Set(Service, hex.EncodeToString(id), hex.EncodeToString(secret))
}

func GetSecret(id string) (string, error) {
	val, err := keyring.Get(Service, id)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", errors.Join(fmt.Errorf("keyring.Get(Service, id). %w", err), ErrNotFound)
		}
		return "", fmt.Errorf("keyring.Get(Service, id). %w", err)
	}
	if val == "" {
		return "", ErrNotFound
	}
	return val, nil
}
