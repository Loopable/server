package server

import (
	"context"
	"crypto/ed25519"
	"errors"

	"loopable.party/server/internal/protocol/events"
	"loopable.party/server/internal/protocol/instance"
	storepkg "loopable.party/server/internal/store"
)

// StoreAdapter bridges the persistent store (internal/store on PostgreSQL) to
// the server's repository interfaces.
type StoreAdapter struct {
	store *storepkg.Store
}

func NewStoreAdapter(store *storepkg.Store) *StoreAdapter {
	return &StoreAdapter{store: store}
}

func (a *StoreAdapter) PutEvent(ctx context.Context, event events.Event) (uint64, error) {
	stored, err := a.store.PutEvent(ctx, event)
	if err != nil {
		return 0, err
	}
	return stored.Seq, nil
}

func (a *StoreAdapter) GetEvent(ctx context.Context, eventID []byte) (events.Event, error) {
	event, err := a.store.GetEvent(ctx, eventID)
	if errors.Is(err, storepkg.ErrEventNotFound) {
		return events.Event{}, ErrEventNotFound
	}
	return event, err
}

func (a *StoreAdapter) HasEvent(ctx context.Context, eventID []byte) (bool, error) {
	return a.store.HasEvent(ctx, eventID)
}

func (a *StoreAdapter) EventsAfter(ctx context.Context, afterSeq uint64, eventTypes []uint64, limit int) ([]StoredEvent, bool, error) {
	stored, more, err := a.store.EventsAfter(ctx, afterSeq, eventTypes, limit)
	if err != nil {
		return nil, false, err
	}
	page := make([]StoredEvent, len(stored))
	for i, item := range stored {
		page[i] = StoredEvent{Seq: item.Seq, Event: item.Event}
	}
	return page, more, nil
}

func (a *StoreAdapter) LatestSeq(ctx context.Context) (uint64, error) {
	return a.store.LatestSeq(ctx)
}

func (a *StoreAdapter) EventsForAccount(ctx context.Context, accountID []byte) ([]StoredEvent, error) {
	stored, err := a.store.EventsForAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}
	page := make([]StoredEvent, len(stored))
	for i, item := range stored {
		page[i] = StoredEvent{Seq: item.Seq, Event: item.Event}
	}
	return page, nil
}

func (a *StoreAdapter) EventsForGroup(ctx context.Context, groupID []byte) ([]StoredEvent, error) {
	stored, err := a.store.EventsForGroup(ctx, groupID)
	if err != nil {
		return nil, err
	}
	page := make([]StoredEvent, len(stored))
	for i, item := range stored {
		page[i] = StoredEvent{Seq: item.Seq, Event: item.Event}
	}
	return page, nil
}

func (a *StoreAdapter) PutObject(ctx context.Context, record ObjectRecord) (uint64, error) {
	seq, err := a.store.PutObject(ctx, storepkg.StoredObject{
		ObjectID:         record.ObjectID,
		ObjectType:       record.ObjectType,
		EncryptionSuite:  record.EncryptionSuite,
		VersionID:        record.VersionID,
		BlobBacked:       record.BlobBacked,
		CiphertextLength: record.CiphertextLength,
		Wire:             record.Wire,
	})
	if errors.Is(err, storepkg.ErrObjectCollision) {
		return 0, ErrObjectCollision
	}
	return seq, err
}

func (a *StoreAdapter) GetObject(ctx context.Context, objectID, versionID []byte) (ObjectRecord, error) {
	stored, err := a.store.GetObject(ctx, objectID, versionID)
	if errors.Is(err, storepkg.ErrObjectNotFound) {
		return ObjectRecord{}, ErrObjectNotFound
	}
	if err != nil {
		return ObjectRecord{}, err
	}
	return serverObject(stored), nil
}

func (a *StoreAdapter) HasObject(ctx context.Context, objectID, versionID []byte) (bool, error) {
	return a.store.HasObject(ctx, objectID, versionID)
}

func (a *StoreAdapter) ListObjectVersions(ctx context.Context, objectID []byte) ([]ObjectRecord, error) {
	stored, err := a.store.ListObjectVersions(ctx, objectID)
	if err != nil {
		return nil, err
	}
	records := make([]ObjectRecord, len(stored))
	for i, item := range stored {
		records[i] = serverObject(item)
	}
	return records, nil
}

func serverObject(stored storepkg.StoredObject) ObjectRecord {
	return ObjectRecord{
		Seq:              stored.Seq,
		ObjectID:         stored.ObjectID,
		ObjectType:       stored.ObjectType,
		EncryptionSuite:  stored.EncryptionSuite,
		VersionID:        stored.VersionID,
		BlobBacked:       stored.BlobBacked,
		CiphertextLength: stored.CiphertextLength,
		Wire:             stored.Wire,
	}
}

func (a *StoreAdapter) DeviceSigningKey(ctx context.Context, accountID, keyID []byte) (ed25519.PublicKey, error) {
	stored, err := a.store.EventsForAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}
	page := make([]StoredEvent, len(stored))
	for i, item := range stored {
		page[i] = StoredEvent{Seq: item.Seq, Event: item.Event}
	}
	return resolveDeviceSigningKey(page, accountID, keyID)
}

func (a *StoreAdapter) MemberOf(ctx context.Context, groupID, accountID []byte) (bool, error) {
	stored, err := a.store.EventsForGroup(ctx, groupID)
	if err != nil {
		return false, err
	}
	page := make([]StoredEvent, len(stored))
	for i, item := range stored {
		page[i] = StoredEvent{Seq: item.Seq, Event: item.Event}
	}
	return deriveMembership(page, groupID, accountID)
}

func (a *StoreAdapter) Resolve(ctx context.Context, instanceID []byte) (*instance.Document, error) {
	return nil, errors.New("peer instance documents are not persisted")
}
