package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"slices"

	"loopable.party/server/internal/protocol/accounts"
	"loopable.party/server/internal/protocol/events"
)

// buildAccountIndex replays an account's device-authorization events in causal
// order and returns the derived authorization index, plus whether the account
// has been deleted. The production derivation lives in
// internal/protocol/authorization; this mirrors it for server-side lookups and
// device-key resolution.
func buildAccountIndex(stored []StoredEvent) (*accounts.AuthorizationIndex, bool, error) {
	byID := make(map[string]events.Event, len(stored))
	foundGenesis := false
	for _, item := range stored {
		event := item.Event
		if event.EventType == 0 {
			if foundGenesis {
				return nil, false, errors.New("account has multiple genesis events")
			}
			foundGenesis = true
		}
		byID[string(event.EventID)] = event
	}
	if !foundGenesis {
		return nil, false, ErrEventNotFound
	}

	order := make([]events.Event, 0, len(byID))
	seen := make(map[string]bool, len(byID))
	var visit func(eventID []byte)
	visit = func(eventID []byte) {
		key := string(eventID)
		if seen[key] {
			return
		}
		seen[key] = true
		event, ok := byID[key]
		if !ok {
			return
		}
		for _, parentID := range event.Predecessors {
			visit(parentID)
		}
		order = append(order, event)
	}
	keys := make([]string, 0, len(byID))
	for key := range byID {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		visit([]byte(key))
	}

	index := accounts.NewAuthorizationIndex()
	deleted := false
	for _, event := range order {
		switch event.EventType {
		case 0:
			state, err := firstDeviceState(event)
			if err != nil {
				return nil, false, err
			}
			if err := index.SeedFirstDevice(state); err != nil {
				return nil, false, err
			}
		case 1:
			state, err := authorizedDeviceState(event)
			if err != nil {
				return nil, false, err
			}
			if err := index.Authorize(state); err != nil {
				return nil, false, err
			}
		case 2:
			deviceID, err := eventBodyBytes(event.Body, 0)
			if err != nil {
				return nil, false, err
			}
			if err := index.Revoke(deviceID); err != nil {
				return nil, false, err
			}
		case 3:
			deviceID, err := eventBodyBytes(event.Body, 0)
			if err != nil {
				return nil, false, err
			}
			if err := index.TransferTrust(deviceID); err != nil {
				return nil, false, err
			}
		case 5:
			deleted = true
		}
	}
	return index, deleted, nil
}

func firstDeviceState(event events.Event) (accounts.DeviceState, error) {
	value, ok := event.Body[3]
	if !ok {
		return accounts.DeviceState{}, errors.New("genesis has no first-device authorization")
	}
	record, err := accounts.ParseFirstDeviceAuthorization(value)
	if err != nil {
		return accounts.DeviceState{}, err
	}
	return accounts.DeviceState{
		ID:            record.DeviceID,
		SigningKey:    record.DeviceSigningPublicKey,
		EncryptionKey: record.DeviceEncryptionPublicKey,
		Kind:          record.DeviceKind,
	}, nil
}

func authorizedDeviceState(event events.Event) (accounts.DeviceState, error) {
	deviceID, err := eventBodyBytes(event.Body, 0)
	if err != nil {
		return accounts.DeviceState{}, err
	}
	signingKey, err := eventBodyBytes(event.Body, 1)
	if err != nil {
		return accounts.DeviceState{}, err
	}
	encryptionKey, err := eventBodyBytes(event.Body, 2)
	if err != nil {
		return accounts.DeviceState{}, err
	}
	kind, err := eventBodyUint(event.Body, 3)
	if err != nil {
		return accounts.DeviceState{}, err
	}
	return accounts.DeviceState{ID: deviceID, SigningKey: signingKey, EncryptionKey: encryptionKey, Kind: kind}, nil
}

func eventBodyBytes(body map[uint64]any, key uint64) ([]byte, error) {
	value, ok := body[key]
	if !ok {
		return nil, errors.New("missing event body field")
	}
	switch buffer := value.(type) {
	case []byte:
		return buffer, nil
	default:
		return nil, errors.New("event body field is not bytes")
	}
}

func eventBodyUint(body map[uint64]any, key uint64) (uint64, error) {
	value, ok := body[key]
	if !ok {
		return 0, errors.New("missing event body field")
	}
	integer, ok := value.(uint64)
	if !ok {
		return 0, errors.New("event body field is not an unsigned integer")
	}
	return integer, nil
}

// deriveKeyID returns the key id of a public signing key (61.9): the first 16
// bytes of SHA-256 of the key.
func deriveKeyID(publicKey []byte) []byte {
	digest := sha256.Sum256(publicKey)
	return digest[:16]
}

// deriveMembership reports whether accountID is a member of groupID by
// replaying the group's stored events in sequence order. GROUP_CREATED makes
// its author a member; GROUP_MEMBER_ADDED/REMOVED name the account in body 2;
// GROUP_JOINED/LEFT name it as the event's account.
func deriveMembership(stored []StoredEvent, groupID, accountID []byte) (bool, error) {
	group := string(groupID)
	account := string(accountID)
	var order []uint64
	for _, item := range stored {
		order = append(order, item.Seq)
	}
	slices.Sort(order)

	members := make(map[string]bool)
	for _, seq := range order {
		item, ok := storedBySeq(stored, seq)
		if !ok || item.Event.EventType < 17 || item.Event.EventType > 23 {
			continue
		}
		event := item.Event
		eventGroup, err := eventBodyBytes(event.Body, 0)
		if err != nil || string(eventGroup) != group {
			continue
		}
		switch event.EventType {
		case 17:
			members[account] = true
		case 19:
			member, err := eventBodyBytes(event.Body, 2)
			if err != nil {
				continue
			}
			members[string(member)] = true
		case 20:
			member, err := eventBodyBytes(event.Body, 2)
			if err != nil {
				continue
			}
			delete(members, string(member))
		case 21:
			members[string(event.AccountID)] = true
		case 22:
			delete(members, string(event.AccountID))
		}
	}
	return members[account], nil
}

func storedBySeq(stored []StoredEvent, seq uint64) (StoredEvent, bool) {
	for _, item := range stored {
		if item.Seq == seq {
			return item, true
		}
	}
	return StoredEvent{}, false
}

// deviceSummaries renders the bounded device summary of 60.8 from an index.
func deviceSummaries(index *accounts.AuthorizationIndex) []any {
	ids := make([]string, 0, len(index.Devices))
	for id := range index.Devices {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	summary := make([]any, 0, len(index.Devices))
	for _, id := range ids {
		device := index.Devices[id]
		if device.Status != accounts.DeviceAuthorized {
			continue
		}
		summary = append(summary, map[uint64]any{
			0: device.ID,
			1: bytes.Equal(device.ID, index.TrustedDevice),
			2: device.Kind,
		})
	}
	return summary
}

// resolveDeviceSigningKey returns the authorized device's signing key by key
// id, or ErrEventNotFound-like failure when the key is not currently active.
func resolveDeviceSigningKey(stored []StoredEvent, accountID, keyID []byte) (ed25519.PublicKey, error) {
	index, _, err := buildAccountIndex(stored)
	if err != nil {
		return nil, err
	}
	for _, device := range index.Devices {
		if device.Status != accounts.DeviceAuthorized {
			continue
		}
		if bytes.Equal(deriveKeyID(device.SigningKey), keyID) {
			return ed25519.PublicKey(device.SigningKey), nil
		}
	}
	return nil, errors.New("no authorized device has the presented key id")
}
