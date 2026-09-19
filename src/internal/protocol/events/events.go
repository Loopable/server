// Package events implements Loopable event envelopes and their signed bytes.
//
// The envelope rules correspond to protospec/spec/32-event-envelope.md.
package events

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sort"

	"loopable.party/server/internal/protocol/encoding"
	"loopable.party/server/internal/protocol/identifiers"
	"loopable.party/server/internal/protocol/signatures"
)

const ProtocolVersion = "0.1"

type ObjectReference struct {
	ObjectID  []byte
	VersionID []byte
}

type Event struct {
	EventID          []byte
	EventType        uint64
	AccountID        []byte
	DeviceID         []byte
	CreatedAt        uint64
	Predecessors     [][]byte
	ObjectReferences []ObjectReference
	Body             map[uint64]any
	Signature        []byte
}

func NewEventID() ([]byte, error) { return identifiers.Random(identifiers.EventID) }

func (e Event) unsigned() map[uint64]any {
	value := map[uint64]any{0: ProtocolVersion, 1: e.EventID, 2: e.EventType, 3: e.AccountID, 4: e.DeviceID, 5: e.CreatedAt, 6: e.Predecessors, 7: objectReferences(e.ObjectReferences), 8: e.Body}
	return value
}

// Sign validates envelope structure and signs the map without field 9.
func (e *Event) Sign(privateKey ed25519.PrivateKey) error {
	if err := e.Validate(); err != nil {
		return err
	}
	signature, err := signatures.Sign(privateKey, signatures.EventDomain, e.unsigned())
	if err != nil {
		return err
	}
	e.Signature = signature
	return nil
}

// Verify validates structure and the event signature. Authorization is separate.
func (e Event) Verify(publicKey ed25519.PublicKey) error {
	if err := e.Validate(); err != nil {
		return err
	}
	return signatures.Verify(publicKey, signatures.EventDomain, e.unsigned(), e.Signature)
}

func (e Event) Validate() error {
	if _, err := LookupType(e.EventType); err != nil {
		return err
	}
	if len(e.EventID) != identifiers.ShortLength || len(e.AccountID) != identifiers.LongLength || e.EventType != 0 && len(e.DeviceID) != identifiers.ShortLength || e.EventType == 0 && len(e.DeviceID) != 0 {
		return errors.New("invalid event identifier lengths")
	}
	if e.Body == nil {
		return errors.New("event body is required")
	}
	previous := make([][]byte, len(e.Predecessors))
	copy(previous, e.Predecessors)
	if !sort.SliceIsSorted(previous, func(i, j int) bool { return bytes.Compare(previous[i], previous[j]) < 0 }) {
		return errors.New("event predecessors are not sorted")
	}
	for i, predecessor := range e.Predecessors {
		if len(predecessor) != identifiers.ShortLength {
			return fmt.Errorf("predecessor %d has invalid length", i)
		}
		if bytes.Equal(predecessor, e.EventID) {
			return errors.New("event cannot depend on itself")
		}
		if i > 0 && bytes.Equal(predecessor, e.Predecessors[i-1]) {
			return errors.New("event predecessors contain duplicates")
		}
	}
	for i, reference := range e.ObjectReferences {
		if len(reference.ObjectID) != identifiers.LongLength || reference.VersionID != nil && len(reference.VersionID) != identifiers.LongLength {
			return fmt.Errorf("object reference %d has invalid lengths", i)
		}
	}
	return nil
}

// Wire returns the complete event map, including its signature.
func (e Event) Wire() map[uint64]any {
	value := e.unsigned()
	value[9] = e.Signature
	return value
}

// CanonicalBytes returns the immutable bytes used for event storage and collision checks.
func (e Event) CanonicalBytes() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return encoding.Encode(e.Wire())
}

func objectReferences(references []ObjectReference) []any {
	value := make([]any, len(references))
	for i, reference := range references {
		item := map[uint64]any{0: reference.ObjectID}
		if reference.VersionID != nil {
			item[1] = reference.VersionID
		}
		value[i] = item
	}
	return value
}
