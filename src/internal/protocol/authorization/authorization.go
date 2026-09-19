// Package authorization validates that an event's signing device was
// authorized for the event's auth level at the event's causal point.
//
// The rules correspond to protospec/spec/42-identity-and-authorization.md.
package authorization

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"

	"loopable.party/server/internal/protocol/accounts"
	"loopable.party/server/internal/protocol/dag"
	"loopable.party/server/internal/protocol/events"
	"loopable.party/server/internal/protocol/identifiers"
	"loopable.party/server/internal/protocol/signatures"
)

var (
	ErrUnauthorizedDevice = errors.New("device is not authorized for the event type")
	ErrFirstDeviceInvalid = errors.New("first-device authorization is invalid")
	ErrTrustConflict      = errors.New("trusted-device state is ambiguous")
	ErrSignatureInvalid   = errors.New("event signature is invalid")
	ErrMemberRequired     = errors.New("group membership is required")
)

// MemberFunc reports whether accountID is currently a member of groupID.
// Membership is a property of the group's own event DAG, not of the account.
type MemberFunc func(groupID, accountID []byte) (bool, error)

// Validate checks whether event is authorized against already known events.
// The known map is keyed by the raw 16-byte event ID converted to string.
//
// memberOf is required for MEMBER-level events and may be nil otherwise; when
// it is nil or reports non-membership, a MEMBER-level event is rejected.
func Validate(event events.Event, known map[string]events.Event, memberOf MemberFunc) error {
	if err := dag.Validate(event, known); err != nil {
		return err
	}
	if event.EventType == 0 {
		if err := validateGenesis(event, known); err != nil {
			return err
		}
		return validateBodySchema(event)
	}
	closure, err := causalClosure(event, known)
	if err != nil {
		return err
	}
	if err := checkTransferAmbiguity(closure); err != nil {
		return err
	}
	index, deleted, err := buildIndex(closure)
	if err != nil {
		return err
	}
	if deleted {
		return ErrUnauthorizedDevice
	}
	device, ok := index.Devices[string(event.DeviceID)]
	if !ok || device.Status != accounts.DeviceAuthorized {
		return ErrUnauthorizedDevice
	}
	if err := event.Verify(device.SigningKey); err != nil {
		return ErrSignatureInvalid
	}
	definition, err := events.LookupType(event.EventType)
	if err != nil {
		return err
	}
	switch definition.Authorization {
	case events.Trusted:
		if !bytes.Equal(index.TrustedDevice, event.DeviceID) {
			return ErrUnauthorizedDevice
		}
	case events.Member:
		return checkMembership(event, memberOf)
	}
	if err := applyTransition(index, event); err != nil {
		return err
	}
	return validateBodySchema(event)
}

// applyTransition re-applies an event's own state transition onto the index
// derived from its causal predecessors, per 42.5 step 7. A transition that
// cannot be applied (raw transfer, trusted-device revocation, conflicting
// binding) is a trust-state integrity error, per 34.4 through 34.6 and 41.4.
func applyTransition(index *accounts.AuthorizationIndex, event events.Event) error {
	switch event.EventType {
	case 1:
		state, err := deviceStateFromAuthorized(event)
		if err != nil {
			return err
		}
		if err := index.Authorize(state); err != nil {
			return fmt.Errorf("%v: %w", err, ErrTrustConflict)
		}
	case 2:
		deviceID, err := fieldBytes(event.Body, 0)
		if err != nil {
			return err
		}
		if err := index.Revoke(deviceID); err != nil {
			return fmt.Errorf("%v: %w", err, ErrTrustConflict)
		}
	case 3:
		deviceID, err := fieldBytes(event.Body, 0)
		if err != nil {
			return err
		}
		if err := index.TransferTrust(deviceID); err != nil {
			return fmt.Errorf("%v: %w", err, ErrTrustConflict)
		}
	}
	return nil
}

// validateGenesis checks ACCOUNT_CREATED per 34.3: the event must be the
// account's only genesis, signed by the account identity key, and it must
// carry a FirstDeviceAuthorization binding the first trusted device.
func validateGenesis(event events.Event, known map[string]events.Event) error {
	if len(event.Predecessors) != 0 {
		return dag.ErrUnrooted
	}
	for _, existing := range known {
		if existing.EventType == 0 && bytes.Equal(existing.AccountID, event.AccountID) {
			return ErrTrustConflict
		}
	}
	identityKey, err := fieldBytes(event.Body, 0)
	if err != nil || len(identityKey) != ed25519.PublicKeySize {
		return ErrFirstDeviceInvalid
	}
	derived, err := identifiers.DeriveAccountID(identityKey)
	if err != nil || !bytes.Equal(derived, event.AccountID) {
		return ErrFirstDeviceInvalid
	}
	value, ok := event.Body[3]
	if !ok {
		return ErrFirstDeviceInvalid
	}
	record, err := accounts.ParseFirstDeviceAuthorization(value)
	if err != nil {
		return ErrFirstDeviceInvalid
	}
	if err := record.Validate(identityKey); err != nil {
		if errors.Is(err, signatures.ErrInvalidSignature) || errors.Is(err, signatures.ErrInvalidPublicKey) {
			return ErrSignatureInvalid
		}
		return ErrFirstDeviceInvalid
	}
	if err := event.Verify(identityKey); err != nil {
		return ErrSignatureInvalid
	}
	return nil
}

// causalClosure returns the set of every transitive predecessor of event that
// is present in known. A missing predecessor is a dag.ErrMissing, per 42.5 step 2.
func causalClosure(event events.Event, known map[string]events.Event) (map[string]events.Event, error) {
	closure := make(map[string]events.Event)
	var visit func([]byte) error
	visit = func(eventID []byte) error {
		key := string(eventID)
		if _, ok := closure[key]; ok {
			return nil
		}
		predecessor, ok := known[key]
		if !ok {
			return fmt.Errorf("%x: %w", eventID, dag.ErrMissing)
		}
		closure[key] = predecessor
		for _, parentID := range predecessor.Predecessors {
			if err := visit(parentID); err != nil {
				return err
			}
		}
		return nil
	}
	for _, predecessorID := range event.Predecessors {
		if err := visit(predecessorID); err != nil {
			return nil, err
		}
	}
	return closure, nil
}

// topoOrder returns the events of closure ordered so that every event appears
// after all of its transitive predecessors.
func topoOrder(closure map[string]events.Event) []events.Event {
	order := make([]events.Event, 0, len(closure))
	seen := make(map[string]bool, len(closure))
	var visit func(eventID []byte)
	visit = func(eventID []byte) {
		key := string(eventID)
		if seen[key] {
			return
		}
		seen[key] = true
		event := closure[key]
		for _, parentID := range event.Predecessors {
			if _, ok := closure[string(parentID)]; ok {
				visit(parentID)
			}
		}
		order = append(order, event)
	}
	keys := make([]string, 0, len(closure))
	for key := range closure {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		visit([]byte(key))
	}
	return order
}

// checkTransferAmbiguity rejects an event when two different
// TRUSTED_DEVICE_TRANSFERRED events both causally precede it and neither is an
// ancestor of the other, per 42.3.
func checkTransferAmbiguity(closure map[string]events.Event) error {
	transfers := make([]events.Event, 0)
	for _, event := range closure {
		if event.EventType == 3 {
			transfers = append(transfers, event)
		}
	}
	for i := range transfers {
		for j := i + 1; j < len(transfers); j++ {
			a, b := transfers[i], transfers[j]
			if !isAncestor(a, b, closure) && !isAncestor(b, a, closure) {
				return fmt.Errorf("%x and %x: %w", a.EventID, b.EventID, ErrTrustConflict)
			}
		}
	}
	return nil
}

// isAncestor reports whether ancestor is a transitive predecessor of
// descendant within closure.
func isAncestor(ancestor, descendant events.Event, closure map[string]events.Event) bool {
	visited := make(map[string]bool)
	var walk func(eventID []byte) bool
	walk = func(eventID []byte) bool {
		key := string(eventID)
		if visited[key] {
			return false
		}
		visited[key] = true
		event := closure[key]
		for _, parentID := range event.Predecessors {
			if bytes.Equal(parentID, ancestor.EventID) {
				return true
			}
			if _, ok := closure[string(parentID)]; ok && walk(parentID) {
				return true
			}
		}
		return false
	}
	return walk(descendant.EventID)
}

// buildIndex replays the authorization-relevant events of closure in causal
// order onto a fresh AuthorizationIndex, per 42.2. It returns whether the
// account was deleted within the closure.
func buildIndex(closure map[string]events.Event) (*accounts.AuthorizationIndex, bool, error) {
	index := accounts.NewAuthorizationIndex()
	deleted := false
	for _, event := range topoOrder(closure) {
		switch event.EventType {
		case 0:
			state, err := deviceStateFromFirstDevice(event)
			if err != nil {
				return nil, false, err
			}
			if err := index.SeedFirstDevice(state); err != nil {
				return nil, false, fmt.Errorf("seed first device: %w", err)
			}
		case 1:
			state, err := deviceStateFromAuthorized(event)
			if err != nil {
				return nil, false, err
			}
			if err := index.Authorize(state); err != nil {
				return nil, false, fmt.Errorf("%v: %w", err, ErrTrustConflict)
			}
		case 2:
			deviceID, err := fieldBytes(event.Body, 0)
			if err != nil {
				return nil, false, err
			}
			if err := index.Revoke(deviceID); err != nil {
				return nil, false, fmt.Errorf("%v: %w", err, ErrTrustConflict)
			}
		case 3:
			deviceID, err := fieldBytes(event.Body, 0)
			if err != nil {
				return nil, false, err
			}
			if err := index.TransferTrust(deviceID); err != nil {
				return nil, false, fmt.Errorf("%v: %w", err, ErrTrustConflict)
			}
		case 5:
			deleted = true
		}
	}
	return index, deleted, nil
}

func deviceStateFromFirstDevice(event events.Event) (accounts.DeviceState, error) {
	value, ok := event.Body[3]
	if !ok {
		return accounts.DeviceState{}, ErrFirstDeviceInvalid
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

func deviceStateFromAuthorized(event events.Event) (accounts.DeviceState, error) {
	deviceID, err := fieldBytes(event.Body, 0)
	if err != nil {
		return accounts.DeviceState{}, err
	}
	signingKey, err := fieldBytes(event.Body, 1)
	if err != nil {
		return accounts.DeviceState{}, err
	}
	encryptionKey, err := fieldBytes(event.Body, 2)
	if err != nil {
		return accounts.DeviceState{}, err
	}
	kind, err := fieldUint(event.Body, 3)
	if err != nil {
		return accounts.DeviceState{}, err
	}
	return accounts.DeviceState{ID: deviceID, SigningKey: signingKey, EncryptionKey: encryptionKey, Kind: kind}, nil
}

func checkMembership(event events.Event, memberOf MemberFunc) error {
	if memberOf == nil {
		return ErrMemberRequired
	}
	groupID, err := fieldBytes(event.Body, 0)
	if err != nil {
		return err
	}
	member, err := memberOf(groupID, event.AccountID)
	if err != nil {
		return err
	}
	if !member {
		return ErrMemberRequired
	}
	return nil
}

func fieldBytes(body map[uint64]any, key uint64) ([]byte, error) {
	value, ok := body[key]
	if !ok {
		return nil, fmt.Errorf("missing body field %d", key)
	}
	switch buffer := value.(type) {
	case []byte:
		return buffer, nil
	case ed25519.PublicKey:
		return []byte(buffer), nil
	default:
		return nil, fmt.Errorf("body field %d is not bytes", key)
	}
}

func fieldUint(body map[uint64]any, key uint64) (uint64, error) {
	value, ok := body[key]
	if !ok {
		return 0, fmt.Errorf("missing body field %d", key)
	}
	number, ok := value.(uint64)
	if !ok {
		return 0, fmt.Errorf("body field %d is not an unsigned integer", key)
	}
	return number, nil
}
