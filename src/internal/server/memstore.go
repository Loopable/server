package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"sort"
	"sync"

	"loopable.party/server/internal/protocol/events"
	"loopable.party/server/internal/protocol/instance"
)

// InMemoryStorage is a concurrency-safe in-memory implementation of the server
// repositories. It replays account and group state exactly like the persistent
// store adapter, so server handlers run against it in tests.
type InMemoryStorage struct {
	mu          sync.Mutex
	events      []StoredEvent
	byID        map[string]storedRow
	seq         uint64
	objects     []ObjectRecord
	objectByKey map[string]ObjectRecord
	objectSeq   uint64
	peers       map[string]*instance.Document
}

type storedRow struct {
	seq   uint64
	event events.Event
}

func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{
		byID:        make(map[string]storedRow),
		objectByKey: make(map[string]ObjectRecord),
		peers:       make(map[string]*instance.Document),
	}
}

// SeedInstance registers a peer instance document for Resolve.
func (m *InMemoryStorage) SeedInstance(document *instance.Document) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peers[string(document.InstanceID)] = document
}

func (m *InMemoryStorage) PutEvent(ctx context.Context, event events.Event) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.byID[string(event.EventID)]; ok {
		encoded, err := event.CanonicalBytes()
		if err != nil {
			return 0, err
		}
		existingEncoded, err := existing.event.CanonicalBytes()
		if err != nil {
			return 0, err
		}
		if !bytes.Equal(encoded, existingEncoded) {
			return 0, ErrEventCollision
		}
		return existing.seq, nil
	}
	m.seq++
	row := storedRow{seq: m.seq, event: event}
	m.byID[string(event.EventID)] = row
	m.events = append(m.events, StoredEvent{Seq: m.seq, Event: event})
	return m.seq, nil
}

func (m *InMemoryStorage) GetEvent(ctx context.Context, eventID []byte) (events.Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	row, ok := m.byID[string(eventID)]
	if !ok {
		return events.Event{}, ErrEventNotFound
	}
	return row.event, nil
}

func (m *InMemoryStorage) HasEvent(ctx context.Context, eventID []byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.byID[string(eventID)]
	return ok, nil
}

func (m *InMemoryStorage) EventsAfter(ctx context.Context, afterSeq uint64, eventTypes []uint64, limit int) ([]StoredEvent, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	page := make([]StoredEvent, 0)
	for _, item := range m.events {
		if item.Seq <= afterSeq {
			continue
		}
		if len(eventTypes) != 0 && !containsUint(eventTypes, item.Event.EventType) {
			continue
		}
		page = append(page, item)
	}
	more := len(page) > limit
	if more {
		page = page[:limit]
	}
	return page, more, nil
}

func (m *InMemoryStorage) LatestSeq(ctx context.Context) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.seq, nil
}

func (m *InMemoryStorage) EventsForAccount(ctx context.Context, accountID []byte) ([]StoredEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	events := make([]StoredEvent, 0)
	for _, item := range m.events {
		if bytes.Equal(item.Event.AccountID, accountID) {
			events = append(events, item)
		}
	}
	return events, nil
}

func (m *InMemoryStorage) EventsForGroup(ctx context.Context, groupID []byte) ([]StoredEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	events := make([]StoredEvent, 0)
	for _, item := range m.events {
		if groupEventID(item.Event) != nil && bytes.Equal(groupEventID(item.Event), groupID) {
			events = append(events, item)
		}
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Seq < events[j].Seq })
	return events, nil
}

// groupEventID mirrors the store's group_id derivation for group-scope events.
func groupEventID(event events.Event) []byte {
	switch event.EventType {
	case 17, 18, 19, 20, 21, 22, 23:
		if value, ok := event.Body[0].([]byte); ok {
			return value
		}
	}
	return nil
}

func (m *InMemoryStorage) PutObject(ctx context.Context, record ObjectRecord) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := string(record.ObjectID) + "\x00" + string(record.VersionID)
	if existing, ok := m.objectByKey[key]; ok {
		if !bytes.Equal(existing.Wire, record.Wire) {
			return 0, ErrObjectCollision
		}
		return existing.Seq, nil
	}
	m.objectSeq++
	record.Seq = m.objectSeq
	m.objectByKey[key] = record
	m.objects = append(m.objects, record)
	return record.Seq, nil
}

func (m *InMemoryStorage) GetObject(ctx context.Context, objectID, versionID []byte) (ObjectRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(versionID) != 0 {
		record, ok := m.objectByKey[string(objectID)+"\x00"+string(versionID)]
		if !ok {
			return ObjectRecord{}, ErrObjectNotFound
		}
		return record, nil
	}
	var latest *ObjectRecord
	for i := range m.objects {
		record := m.objects[i]
		if bytes.Equal(record.ObjectID, objectID) && (latest == nil || record.Seq > latest.Seq) {
			recordCopy := record
			latest = &recordCopy
		}
	}
	if latest == nil {
		return ObjectRecord{}, ErrObjectNotFound
	}
	return *latest, nil
}

func (m *InMemoryStorage) HasObject(ctx context.Context, objectID, versionID []byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(versionID) != 0 {
		_, ok := m.objectByKey[string(objectID)+"\x00"+string(versionID)]
		return ok, nil
	}
	for _, record := range m.objects {
		if bytes.Equal(record.ObjectID, objectID) {
			return true, nil
		}
	}
	return false, nil
}

func (m *InMemoryStorage) ListObjectVersions(ctx context.Context, objectID []byte) ([]ObjectRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	versions := make([]ObjectRecord, 0)
	for _, record := range m.objects {
		if bytes.Equal(record.ObjectID, objectID) {
			versions = append(versions, record)
		}
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i].Seq > versions[j].Seq })
	return versions, nil
}

func (m *InMemoryStorage) DeviceSigningKey(ctx context.Context, accountID, keyID []byte) (ed25519.PublicKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	stored := make([]StoredEvent, 0)
	for _, item := range m.events {
		if bytes.Equal(item.Event.AccountID, accountID) {
			stored = append(stored, item)
		}
	}
	return resolveDeviceSigningKey(stored, accountID, keyID)
}

func (m *InMemoryStorage) MemberOf(ctx context.Context, groupID, accountID []byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	stored := make([]StoredEvent, 0)
	for _, item := range m.events {
		if groupEventID(item.Event) != nil && bytes.Equal(groupEventID(item.Event), groupID) {
			stored = append(stored, item)
		}
	}
	return deriveMembership(stored, groupID, accountID)
}

func (m *InMemoryStorage) Resolve(ctx context.Context, instanceID []byte) (*instance.Document, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if document, ok := m.peers[string(instanceID)]; ok {
		documentCopy := *document
		return &documentCopy, nil
	}
	return nil, errors.New("unknown peer instance")
}

func containsUint(list []uint64, value uint64) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}
