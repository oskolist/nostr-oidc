package vertex

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

const vertexRelay = "wss://relay.vertexlab.io"

type VertexChecker struct {
	nsec  *btcec.PrivateKey
	relay *nostr.Relay
}

func NewVertexChecker(nsec string) (*VertexChecker, error) {
	relay, err := nostr.RelayConnect(context.Background(), vertexRelay)
	if err != nil {
		return nil, fmt.Errorf("nostr.RelayConnect(ctx, vertexRelay). %w", err)
	}

	prefix, value, err := nip19.Decode(nsec)
	if err != nil {
		return nil, fmt.Errorf("nip19.Decode(nsec). %w", err)
	}

	if prefix != "nsec" {
		return nil, fmt.Errorf("nsec is no correct %w", err)
	}

	hexPrivKey := value.(string)
	pkBytes, err := hex.DecodeString(hexPrivKey)
	if err != nil {
		return nil, fmt.Errorf("hex.DecodeString(hexPrivKey). %w", err)
	}

	privKey, _ := btcec.PrivKeyFromBytes(pkBytes)

	vertexChecker := &VertexChecker{
		nsec:  privKey,
		relay: relay,
	}

	return vertexChecker, nil
}

func (v *VertexChecker) npubHasEnoughReputation(npub btcec.PublicKey) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
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
				"target", hex.EncodeToString(npub.SerializeCompressed()),
			},
			nostr.Tag{
				"limit", "5",
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

	events, err := v.relay.QuerySync(ctx, filter)
	if err != nil {
		return false, fmt.Errorf("v.relay.Subscribe(ctx, nostr.Filters{filter}).  %w", err)
	}

	log.Printf("\n events: %+v", events)
	return false, nil
}
