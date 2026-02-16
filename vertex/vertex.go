package vertex

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lescuer97/nostr-oicd/libsecret"
	"github.com/nbd-wtf/go-nostr"
)

const vertexRelay = "wss://relay.vertexlab.io"

type VertexChecker struct {
	relay *nostr.Relay
}

var ErrInvalidNsec = errors.New("Invalid nsec")
var RelayError = errors.New("vertex lab error")

func NewVertexChecker() (*VertexChecker, error) {
	relay, err := nostr.RelayConnect(context.Background(), vertexRelay)
	if err != nil {
		return nil, fmt.Errorf("nostr.RelayConnect(ctx, vertexRelay). %w", err)
	}
	vertexChecker := VertexChecker{
		relay: relay,
	}

	return &vertexChecker, nil
}

type VertexResult struct {
	Npub string  `json:"npub"`
	Rank float64 `json:"rank"`
}

func (v *VertexChecker) getNsecFromStore() ([]byte, error) {
	secret, err := libsecret.GetSecret(libsecret.VertexNsec)
	if err != nil {
		return nil, fmt.Errorf("libsecret.GetSecret(libsecret.VertexNsec).  %w", err)
	}
	defer func() {
		secret = ""
	}()

	nsecBytes, err := hex.DecodeString(secret)
	if err != nil {
		return nil, fmt.Errorf("hex.DecodeString(secret).  %w", err)
	}
	return nsecBytes, nil
}

func (v *VertexChecker) NpubHasEnoughReputation(ctx context.Context, npub *btcec.PublicKey, vertexRange bool, rangeValue *uint64) (bool, error) {
	if v.relay == nil {
		return false, fmt.Errorf("VERTEX Relay connection is not spinned up at the moment")
	}
	if vertexRange && rangeValue == nil {
		return false, fmt.Errorf("Vertex range setup but no range value set")
	}
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

	nsec, err := v.getNsecFromStore()
	if err != nil {
		return false, fmt.Errorf("v.getNsecFromStore().  %w", err)
	}
	defer func() {
		nsec = nil
	}()

	err = event.Sign(hex.EncodeToString(nsec))
	if err != nil {
		return false, fmt.Errorf("event.Sign(hex.EncodeToString(nsec)).  %w", err)
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
	nodesTag := response.Tags.Find("nodes")
	if len(nodesTag) < 2 {
		return false, fmt.Errorf("no nodes tag available")
	}

	nodesValue, err := strconv.ParseFloat(nodesTag[1], 64)
	if err != nil {
		return false, fmt.Errorf("Node value is not a floating point")
	}

	var vertexEvents []VertexResult
	err = json.Unmarshal([]byte(response.Content), &vertexEvents)
	if err != nil {
		return false, errors.Join(RelayError, fmt.Errorf("json.Unmarshal([]byte(response.Content), &vertexEvents).  %w", err))
	}

	if len(vertexEvents) == 0 {
		return false, errors.Join(RelayError, fmt.Errorf("Vertex context are empty"))
	}

	if vertexRange {
		if *rangeValue == 0 || *rangeValue > 100 {
			return false, fmt.Errorf("range value must be between 1 and 100")
		}
		percentage := float64(*rangeValue) / 100
		threshold := pagerankPercentile(percentage, nodesValue)
		return vertexEvents[0].Rank >= threshold, nil
	}

	return vertexEvents[0].Rank >= 0.000015, nil
}

func pagerankPercentile(percentage float64, nodes float64) float64 {
	exponent := 0.76
	return (1 - exponent) * math.Pow(percentage, -exponent) * (1 / nodes)
}
