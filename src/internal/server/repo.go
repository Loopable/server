package server

import (
	"context"
	"crypto/ed25519"

	"loopable.party/server/internal/protocol/events"
	"loopable.party/server/internal/protocol/instance"
)

// StoredEvent is an event with its monotonic publish sequence.
type StoredEvent struct {
	Seq   uint64
	Event events.Event
}

// EventRepository is the event-facing data layer. Implementations are
// persistent stores (internal/store on PostgreSQL) or in-memory stores for
// tests. Events stored by PutEvent are canonical, valid, and authorized.
type EventRepository interface {
	// PutEvent stores an event immutably. Re-submitting identical bytes is
	// idempotent; distinct bytes under the same event ID yield ErrEventCollision.
	// Submissions are classified (duplicate vs collision) by submitEvent before
	// acceptance; PutEvent guards concurrent inserts.
	PutEvent(ctx context.Context, event events.Event) (uint64, error)
	// GetEvent returns the stored event by ID, or ErrEventNotFound.
	GetEvent(ctx context.Context, eventID []byte) (events.Event, error)
	// HasEvent reports whether an event is already stored.
	HasEvent(ctx context.Context, eventID []byte) (bool, error)
	// EventsAfter returns up to limit stored events with sequence greater than
	// afterSeq, oldest first, optionally filtered to the given event types.
	// The boolean reports whether more events remain beyond the page.
	EventsAfter(ctx context.Context, afterSeq uint64, eventTypes []uint64, limit int) ([]StoredEvent, bool, error)
	// LatestSeq returns the highest published watermark.
	LatestSeq(ctx context.Context) (uint64, error)
	// EventsForAccount returns every stored event of an account, in any order.
	EventsForAccount(ctx context.Context, accountID []byte) ([]StoredEvent, error)
	// EventsForGroup returns the stored group-scope events of a group, in any order.
	EventsForGroup(ctx context.Context, groupID []byte) ([]StoredEvent, error)
}

// ObjectRecord is a registered object envelope. Wire holds the canonical
// envelope bytes; for BlobBacked objects the ciphertext bytes live in the
// object store backend and Wire carries the envelope with ciphertext zeroed
// and the true length recorded in CiphertextLength.
type ObjectRecord struct {
	Seq              uint64
	ObjectID         []byte
	ObjectType       uint64
	EncryptionSuite  uint64
	VersionID        []byte
	BlobBacked       bool
	CiphertextLength int64
	Wire             []byte
}

// ObjectRepository is the object-envelope registry. Blob bytes (ciphertext)
// are handled separately by the object store backend.
type ObjectRepository interface {
	// PutObject registers an envelope. Re-submitting identical bytes for the
	// same (object_id, version_id) is idempotent; distinct bytes yield
	// ErrObjectCollision.
	PutObject(ctx context.Context, record ObjectRecord) (uint64, error)
	// GetObject returns the registered envelope; a nil versionID selects the
	// most recently stored version, or ErrObjectNotFound.
	GetObject(ctx context.Context, objectID, versionID []byte) (ObjectRecord, error)
	// HasObject reports whether an object version is registered; a nil
	// versionID reports whether any version exists.
	HasObject(ctx context.Context, objectID, versionID []byte) (bool, error)
	// ListObjectVersions returns all registered versions, newest first.
	ListObjectVersions(ctx context.Context, objectID []byte) ([]ObjectRecord, error)
}

// InstanceResolver resolves a peer instance document from its instance ID.
type InstanceResolver interface {
	Resolve(ctx context.Context, instanceID []byte) (*instance.Document, error)
}

// DeviceResolver resolves an account device's current signing public key from
// its key id (the first 16 bytes of SHA-256 of the public key), per 61.9.
type DeviceResolver interface {
	DeviceSigningKey(ctx context.Context, accountID, keyID []byte) (ed25519.PublicKey, error)
}

// MembershipResolver derives group membership from the group's stored events.
type MembershipResolver interface {
	MemberOf(ctx context.Context, groupID, accountID []byte) (bool, error)
}
