package authorization

import (
	"bytes"
	"testing"

	"loopable.party/server/internal/protocol/accounts"
	"loopable.party/server/internal/protocol/events"
	"loopable.party/server/internal/protocol/identifiers"
)

func TestSchemaRejectsSelfTargetRelationship(t *testing.T) {
	accountID := bytes.Repeat([]byte{1}, identifiers.LongLength)
	event := events.Event{
		EventID:   bytes.Repeat([]byte{2}, identifiers.ShortLength),
		EventType: 6,
		AccountID: accountID,
		DeviceID:  bytes.Repeat([]byte{3}, identifiers.ShortLength),
		Body:      map[uint64]any{0: accountID},
	}
	if err := validateBodySchema(event); err == nil {
		t.Fatal("relationship targeting the account itself accepted")
	}
}

func TestSchemaRequiresObjectReferenceForPost(t *testing.T) {
	event := events.Event{
		EventID:   bytes.Repeat([]byte{2}, identifiers.ShortLength),
		EventType: 13,
		AccountID: bytes.Repeat([]byte{1}, identifiers.LongLength),
		DeviceID:  bytes.Repeat([]byte{3}, identifiers.ShortLength),
		Body:      map[uint64]any{},
	}
	if err := validateBodySchema(event); err == nil {
		t.Fatal("POST_CREATED without an object reference accepted")
	}
	event.ObjectReferences = []events.ObjectReference{{ObjectID: bytes.Repeat([]byte{4}, identifiers.LongLength)}}
	if err := validateBodySchema(event); err == nil {
		t.Fatal("POST_CREATED with a versionless reference accepted")
	}
}

func TestSchemaRejectsUnexpectedBodyField(t *testing.T) {
	event := events.Event{
		EventID:   bytes.Repeat([]byte{2}, identifiers.ShortLength),
		EventType: 5,
		AccountID: bytes.Repeat([]byte{1}, identifiers.LongLength),
		DeviceID:  bytes.Repeat([]byte{3}, identifiers.ShortLength),
		Body:      map[uint64]any{7: "extra"},
	}
	if err := validateBodySchema(event); err == nil {
		t.Fatal("ACCOUNT_DELETED with an unexpected field accepted")
	}
}

func TestSchemaRejectsUnknownDeviceKind(t *testing.T) {
	event := events.Event{
		EventID:   bytes.Repeat([]byte{2}, identifiers.ShortLength),
		EventType: 1,
		AccountID: bytes.Repeat([]byte{1}, identifiers.LongLength),
		DeviceID:  bytes.Repeat([]byte{3}, identifiers.ShortLength),
		Body: map[uint64]any{
			0: bytes.Repeat([]byte{4}, identifiers.ShortLength),
			1: bytes.Repeat([]byte{5}, 32),
			2: bytes.Repeat([]byte{6}, 32),
			3: uint64(9),
		},
	}
	if err := validateBodySchema(event); err == nil {
		t.Fatal("DEVICE_AUTHORIZED with unknown device_kind accepted")
	}
}

func TestSchemaRejectsMalformedParentReference(t *testing.T) {
	event := events.Event{
		EventID:   bytes.Repeat([]byte{2}, identifiers.ShortLength),
		EventType: 16,
		AccountID: bytes.Repeat([]byte{1}, identifiers.LongLength),
		DeviceID:  bytes.Repeat([]byte{3}, identifiers.ShortLength),
		Body:      map[uint64]any{0: "not-a-map"},
		ObjectReferences: []events.ObjectReference{{
			ObjectID:  bytes.Repeat([]byte{4}, identifiers.LongLength),
			VersionID: bytes.Repeat([]byte{5}, identifiers.LongLength),
		}},
	}
	if err := validateBodySchema(event); err == nil {
		t.Fatal("REPLY_CREATED with a malformed parent reference accepted")
	}
}

func TestSchemaRejectsNonBooleanVisibility(t *testing.T) {
	event := events.Event{
		EventID:   bytes.Repeat([]byte{2}, identifiers.ShortLength),
		EventType: 25,
		AccountID: bytes.Repeat([]byte{1}, identifiers.LongLength),
		DeviceID:  bytes.Repeat([]byte{3}, identifiers.ShortLength),
		Body:      map[uint64]any{0: "yes"},
	}
	if err := validateBodySchema(event); err == nil {
		t.Fatal("PROFILE_VISIBILITY_SET with non-boolean value accepted")
	}
}

func TestSchemaRejectsMemberChangeWithoutEpoch(t *testing.T) {
	event := events.Event{
		EventID:   bytes.Repeat([]byte{2}, identifiers.ShortLength),
		EventType: 19,
		AccountID: bytes.Repeat([]byte{1}, identifiers.LongLength),
		DeviceID:  bytes.Repeat([]byte{3}, identifiers.ShortLength),
		Body: map[uint64]any{
			0: bytes.Repeat([]byte{4}, identifiers.ShortLength),
			2: bytes.Repeat([]byte{1}, identifiers.LongLength),
		},
	}
	if err := validateBodySchema(event); err == nil {
		t.Fatal("GROUP_MEMBER_ADDED without an epoch accepted")
	}
}

func TestSchemaAcceptsValidGroupEvents(t *testing.T) {
	groupID := bytes.Repeat([]byte{4}, identifiers.ShortLength)
	name := map[uint64]any{0: bytes.Repeat([]byte{5}, identifiers.LongLength), 1: bytes.Repeat([]byte{6}, identifiers.LongLength)}
	create := events.Event{
		EventID:   bytes.Repeat([]byte{2}, identifiers.ShortLength),
		EventType: 17,
		AccountID: bytes.Repeat([]byte{1}, identifiers.LongLength),
		DeviceID:  bytes.Repeat([]byte{3}, identifiers.ShortLength),
		Body:      map[uint64]any{0: groupID, 1: name},
	}
	if err := validateBodySchema(create); err != nil {
		t.Fatalf("GROUP_CREATED rejected: %v", err)
	}
	add := events.Event{
		EventID:   bytes.Repeat([]byte{7}, identifiers.ShortLength),
		EventType: 19,
		AccountID: bytes.Repeat([]byte{1}, identifiers.LongLength),
		DeviceID:  bytes.Repeat([]byte{3}, identifiers.ShortLength),
		Body: map[uint64]any{
			0: groupID,
			1: uint64(1),
			2: bytes.Repeat([]byte{1}, identifiers.LongLength),
			3: bytes.Repeat([]byte{8}, identifiers.ShortLength),
		},
	}
	if err := validateBodySchema(add); err != nil {
		t.Fatalf("GROUP_MEMBER_ADDED rejected: %v", err)
	}
	leave := events.Event{
		EventID:   bytes.Repeat([]byte{9}, identifiers.ShortLength),
		EventType: 22,
		AccountID: bytes.Repeat([]byte{1}, identifiers.LongLength),
		DeviceID:  bytes.Repeat([]byte{3}, identifiers.ShortLength),
		Body:      map[uint64]any{0: groupID, 1: uint64(2)},
	}
	if err := validateBodySchema(leave); err != nil {
		t.Fatalf("GROUP_LEFT rejected: %v", err)
	}
}

func TestSchemaAcceptsValidDeviceAuthorized(t *testing.T) {
	for _, kind := range []uint64{accounts.DeviceKindClient, accounts.DeviceKindBackup, accounts.DeviceKindService} {
		event := events.Event{
			EventID:   bytes.Repeat([]byte{2}, identifiers.ShortLength),
			EventType: 1,
			AccountID: bytes.Repeat([]byte{1}, identifiers.LongLength),
			DeviceID:  bytes.Repeat([]byte{3}, identifiers.ShortLength),
			Body: map[uint64]any{
				0: bytes.Repeat([]byte{4}, identifiers.ShortLength),
				1: bytes.Repeat([]byte{5}, 32),
				2: bytes.Repeat([]byte{6}, 32),
				3: kind,
				4: "primary",
			},
		}
		if err := validateBodySchema(event); err != nil {
			t.Fatalf("DEVICE_AUTHORIZED kind %d rejected: %v", kind, err)
		}
	}
}
