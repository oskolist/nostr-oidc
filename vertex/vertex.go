package vertex

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

const vertexRelay = "wss://relay.vertexlab.io"

type VertexChecker struct {
	nsec  *btcec.PrivateKey
	relay *nostr.Relay
}

var ErrInvalidNsec = errors.New("Invalid nsec")
var RelayError = errors.New("vertex lab error")

func NewVertexChecker(nsec string) (*VertexChecker, error) {
	relay, err := nostr.RelayConnect(context.Background(), vertexRelay)
	if err != nil {
		return nil, fmt.Errorf("nostr.RelayConnect(ctx, vertexRelay). %w", err)
	}

	prefix, value, err := nip19.Decode(nsec)
	if err != nil {
		return nil, errors.Join(ErrInvalidNsec, fmt.Errorf("nip19.Decode(nsec). %w", err))
	}

	if prefix != "nsec" {
		return nil, fmt.Errorf("nsec is no correct %w", ErrInvalidNsec)
	}

	hexPrivKey := value.(string)
	pkBytes, err := hex.DecodeString(hexPrivKey)
	if err != nil {
		return nil, errors.Join(ErrInvalidNsec, fmt.Errorf("hex.DecodeString(hexPrivKey). %w", err))
	}

	privKey, _ := btcec.PrivKeyFromBytes(pkBytes)

	vertexChecker := VertexChecker{
		nsec:  privKey,
		relay: relay,
	}

	return &vertexChecker, nil
}

type VertexResult struct {
	Npub string  `json:"npub"`
	Rank float64 `json:"rank"`
}

func (v *VertexChecker) NpubHasEnoughReputation(ctx context.Context, npub *btcec.PublicKey) (bool, error) {
	if !v.relay.IsConnected() {
		err := v.relay.Connect(context.Background())
		if err != nil {
			return false, fmt.Errorf("v.relay.Connect(context.Background()).  %w", err)
		}
	}

	event := nostr.Event{
		Kind: 5312,
		Tags: nostr.Tags{
			nostr.Tag{
				"param", "target", hex.EncodeToString(schnorr.SerializePubKey(npub)),
			},
			nostr.Tag{
				"param", "limit", "1",
			},
		},
	}

	err := event.Sign(hex.EncodeToString(v.nsec.Serialize()))
	if err != nil {
		return false, fmt.Errorf("event.Sign(hex.EncodeToString(v.nsec.Serialize())).  %w", err)
	}

	// nostr.signer
	filter := nostr.Filter{
		Tags: nostr.TagMap{
			"e": []string{event.ID},
		},
		Kinds: []int{6312, 7000},
	}

	err = v.relay.Publish(ctx, event)
	if err != nil {
		return false, fmt.Errorf("v.relay.Publish(ctx, event).  %w", err)
	}

	responses, err := v.relay.QueryEvents(ctx, filter)
	if err != nil {
		return false, fmt.Errorf("v.relay.QueryEvents(ctx, filter).  %w", err)
	}

	// extract the first response
	response := <-responses

	if response.Kind == 7000 {
		return false, fmt.Errorf("%w, event: %s", RelayError, response.String())
	}

	var vertexEvents []VertexResult
	err = json.Unmarshal([]byte(response.Content), &vertexEvents)
	if err != nil {
		return false, errors.Join(RelayError, fmt.Errorf("json.Unmarshal([]byte(response.Content), &vertexEvents).  %w", err))
	}

	if len(vertexEvents) == 0 {
		return false, errors.Join(RelayError, fmt.Errorf("Vertex context are empty"))
	}

	return vertexEvents[0].Rank >= 0.000015, nil
}
