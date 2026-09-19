package authorization

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"loopable.party/server/internal/protocol/accounts"
	"loopable.party/server/internal/protocol/dag"
	"loopable.party/server/internal/protocol/events"
	"loopable.party/server/internal/protocol/identifiers"
	"loopable.party/server/internal/protocol/signatures"
	"loopable.party/server/internal/protocol/x25519"
)

type deviceFixture struct {
	id      []byte
	signing ed25519.PublicKey
	private ed25519.PrivateKey
	encrypt []byte
	kind    uint64
}

type accountFixture struct {
	identityPriv ed25519.PrivateKey
	accountID    []byte
	first        deviceFixture
	genesis      events.Event
	known        map[string]events.Event
}

func newAccountFixture(t *testing.T) *accountFixture {
	t.Helper()
	identityPub, identityPriv, err := signatures.Generate()
	if err != nil {
		t.Fatal(err)
	}
	accountID, err := identifiers.DeriveAccountID(identityPub)
	if err != nil {
		t.Fatal(err)
	}
	homeInstance := bytes.Repeat([]byte{0xaa}, identifiers.LongLength)
	signingPub, signingPriv, err := signatures.Generate()
	if err != nil {
		t.Fatal(err)
	}
	encryption, err := x25519.Generate()
	if err != nil {
		t.Fatal(err)
	}
	first := deviceFixture{
		id:      bytes.Repeat([]byte{0x01}, identifiers.ShortLength),
		signing: signingPub,
		private: signingPriv,
		encrypt: encryption.PublicKey(),
		kind:    accounts.DeviceKindClient,
	}
	authorization := accounts.FirstDeviceAuthorization{
		AccountID:                 accountID,
		DeviceID:                  first.id,
		DeviceSigningPublicKey:    first.signing,
		DeviceEncryptionPublicKey: first.encrypt,
		DeviceKind:                first.kind,
	}
	if err := authorization.Sign(identityPriv); err != nil {
		t.Fatal(err)
	}
	genesis := events.Event{
		EventID:   bytes.Repeat([]byte{0xb1}, identifiers.ShortLength),
		EventType: 0,
		AccountID: accountID,
		CreatedAt: 1,
		Body: map[uint64]any{
			0: identityPub,
			1: "alice",
			2: homeInstance,
			3: authorization.Wire(),
		},
	}
	if err := genesis.Sign(identityPriv); err != nil {
		t.Fatal(err)
	}
	return &accountFixture{
		identityPriv: identityPriv,
		accountID:    accountID,
		first:        first,
		genesis:      genesis,
		known:        map[string]events.Event{string(genesis.EventID): genesis},
	}
}

func newDeviceFixture(t *testing.T, idSeed uint8, kind uint64) deviceFixture {
	t.Helper()
	signing, private, err := signatures.Generate()
	if err != nil {
		t.Fatal(err)
	}
	encryption, err := x25519.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return deviceFixture{
		id:      bytes.Repeat([]byte{idSeed}, identifiers.ShortLength),
		signing: signing,
		private: private,
		encrypt: encryption.PublicKey(),
		kind:    kind,
	}
}

// authorizeEvent builds a DEVICE_AUTHORIZED event signed by the account's
// first (trusted) device, referencing the given predecessor. Event IDs are
// unique within each test by using a dedicated seed.
func (a *accountFixture) authorizeEvent(t *testing.T, device deviceFixture, predecessor []byte, eventSeed uint8) events.Event {
	t.Helper()
	event := events.Event{
		EventID:      bytes.Repeat([]byte{eventSeed}, identifiers.ShortLength),
		EventType:    1,
		AccountID:    a.accountID,
		DeviceID:     a.first.id,
		CreatedAt:    2,
		Predecessors: [][]byte{predecessor},
		Body: map[uint64]any{
			0: device.id,
			1: device.signing,
			2: device.encrypt,
			3: device.kind,
		},
	}
	if err := event.Sign(a.first.private); err != nil {
		t.Fatal(err)
	}
	return event
}

func TestGenesisAccepted(t *testing.T) {
	fixture := newAccountFixture(t)
	if err := Validate(fixture.genesis, nil, nil); err != nil {
		t.Fatalf("genesis rejected: %v", err)
	}
}

func TestGenesisRejectsSecondGenesis(t *testing.T) {
	fixture := newAccountFixture(t)
	second := fixture.genesis
	second.EventID = bytes.Repeat([]byte{0xc2}, identifiers.ShortLength)
	if err := second.Sign(fixture.identityPriv); err != nil {
		t.Fatal(err)
	}
	if err := Validate(second, fixture.known, nil); !errors.Is(err, ErrTrustConflict) {
		t.Fatalf("second genesis: got %v, want ErrTrustConflict", err)
	}
}

func TestGenesisRejectsBrokenFirstDeviceRecord(t *testing.T) {
	fixture := newAccountFixture(t)
	value := fixture.genesis.Body[3]
	record, err := accounts.ParseFirstDeviceAuthorization(value)
	if err != nil {
		t.Fatal(err)
	}
	record.IdentitySignature = bytes.Repeat([]byte{0x00}, ed25519.SignatureSize)
	broken := fixture.genesis
	broken.Body = make(map[uint64]any, len(fixture.genesis.Body))
	for key, val := range fixture.genesis.Body {
		broken.Body[key] = val
	}
	broken.Body[3] = record.Wire()
	if err := broken.Sign(fixture.identityPriv); err != nil {
		t.Fatal(err)
	}
	if err := Validate(broken, nil, nil); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("broken first-device record: got %v, want ErrSignatureInvalid", err)
	}
}

func TestGenesisRejectsMismatchedAccountID(t *testing.T) {
	fixture := newAccountFixture(t)
	broken := fixture.genesis
	broken.AccountID = bytes.Repeat([]byte{0x00}, identifiers.LongLength)
	if err := broken.Sign(fixture.identityPriv); err != nil {
		t.Fatal(err)
	}
	if err := Validate(broken, nil, nil); !errors.Is(err, ErrFirstDeviceInvalid) {
		t.Fatalf("mismatched account id: got %v, want ErrFirstDeviceInvalid", err)
	}
}

func TestAuthorizedDeviceSignsContentEvent(t *testing.T) {
	fixture := newAccountFixture(t)
	authorized := newDeviceFixture(t, 0x03, accounts.DeviceKindClient)
	deviceAuthorized := fixture.authorizeEvent(t, authorized, fixture.genesis.EventID, 0xd2)
	if err := Validate(deviceAuthorized, fixture.known, nil); err != nil {
		t.Fatalf("device authorized rejected: %v", err)
	}
	fixture.known[string(deviceAuthorized.EventID)] = deviceAuthorized

	post := events.Event{
		EventID:      bytes.Repeat([]byte{0xd3}, identifiers.ShortLength),
		EventType:    13,
		AccountID:    fixture.accountID,
		DeviceID:     authorized.id,
		CreatedAt:    3,
		Predecessors: [][]byte{deviceAuthorized.EventID},
		Body:         map[uint64]any{},
	}
	if err := post.Sign(authorized.private); err != nil {
		t.Fatal(err)
	}
	if err := Validate(post, fixture.known, nil); err != nil {
		t.Fatalf("post rejected: %v", err)
	}
}

func TestNonTrustedDeviceRejectsTrustedEvent(t *testing.T) {
	fixture := newAccountFixture(t)
	authorized := newDeviceFixture(t, 0x04, accounts.DeviceKindClient)
	deviceAuthorized := fixture.authorizeEvent(t, authorized, fixture.genesis.EventID, 0xd4)
	if err := Validate(deviceAuthorized, fixture.known, nil); err != nil {
		t.Fatal(err)
	}
	fixture.known[string(deviceAuthorized.EventID)] = deviceAuthorized

	target := newDeviceFixture(t, 0x05, accounts.DeviceKindClient)
	event := events.Event{
		EventID:      bytes.Repeat([]byte{0xd5}, identifiers.ShortLength),
		EventType:    1,
		AccountID:    fixture.accountID,
		DeviceID:     authorized.id,
		CreatedAt:    4,
		Predecessors: [][]byte{deviceAuthorized.EventID},
		Body: map[uint64]any{
			0: target.id,
			1: target.signing,
			2: target.encrypt,
			3: target.kind,
		},
	}
	if err := event.Sign(authorized.private); err != nil {
		t.Fatal(err)
	}
	if err := Validate(event, fixture.known, nil); !errors.Is(err, ErrUnauthorizedDevice) {
		t.Fatalf("authorized device signing trusted event: got %v, want ErrUnauthorizedDevice", err)
	}
}

func TestRevokedDeviceRejectsNewEvent(t *testing.T) {
	fixture := newAccountFixture(t)
	authorized := newDeviceFixture(t, 0x06, accounts.DeviceKindClient)
	deviceAuthorized := fixture.authorizeEvent(t, authorized, fixture.genesis.EventID, 0xd6)
	if err := Validate(deviceAuthorized, fixture.known, nil); err != nil {
		t.Fatal(err)
	}
	fixture.known[string(deviceAuthorized.EventID)] = deviceAuthorized

	revoked := events.Event{
		EventID:      bytes.Repeat([]byte{0xd7}, identifiers.ShortLength),
		EventType:    2,
		AccountID:    fixture.accountID,
		DeviceID:     fixture.first.id,
		CreatedAt:    5,
		Predecessors: [][]byte{deviceAuthorized.EventID},
		Body:         map[uint64]any{0: authorized.id},
	}
	if err := revoked.Sign(fixture.first.private); err != nil {
		t.Fatal(err)
	}
	if err := Validate(revoked, fixture.known, nil); err != nil {
		t.Fatalf("revoke event rejected: %v", err)
	}
	fixture.known[string(revoked.EventID)] = revoked

	post := events.Event{
		EventID:      bytes.Repeat([]byte{0xd8}, identifiers.ShortLength),
		EventType:    13,
		AccountID:    fixture.accountID,
		DeviceID:     authorized.id,
		CreatedAt:    6,
		Predecessors: [][]byte{revoked.EventID},
		Body:         map[uint64]any{},
	}
	if err := post.Sign(authorized.private); err != nil {
		t.Fatal(err)
	}
	if err := Validate(post, fixture.known, nil); !errors.Is(err, ErrUnauthorizedDevice) {
		t.Fatalf("revoked device event: got %v, want ErrUnauthorizedDevice", err)
	}
}

func TestTrustedDeviceTransfer(t *testing.T) {
	fixture := newAccountFixture(t)
	replacement := newDeviceFixture(t, 0x07, accounts.DeviceKindClient)
	deviceAuthorized := fixture.authorizeEvent(t, replacement, fixture.genesis.EventID, 0xd9)
	if err := Validate(deviceAuthorized, fixture.known, nil); err != nil {
		t.Fatal(err)
	}
	fixture.known[string(deviceAuthorized.EventID)] = deviceAuthorized

	transfer := events.Event{
		EventID:      bytes.Repeat([]byte{0xda}, identifiers.ShortLength),
		EventType:    3,
		AccountID:    fixture.accountID,
		DeviceID:     fixture.first.id,
		CreatedAt:    7,
		Predecessors: [][]byte{deviceAuthorized.EventID},
		Body:         map[uint64]any{0: replacement.id},
	}
	if err := transfer.Sign(fixture.first.private); err != nil {
		t.Fatal(err)
	}
	if err := Validate(transfer, fixture.known, nil); err != nil {
		t.Fatalf("transfer rejected: %v", err)
	}
	fixture.known[string(transfer.EventID)] = transfer

	post := events.Event{
		EventID:      bytes.Repeat([]byte{0xdb}, identifiers.ShortLength),
		EventType:    13,
		AccountID:    fixture.accountID,
		DeviceID:     replacement.id,
		CreatedAt:    8,
		Predecessors: [][]byte{transfer.EventID},
		Body:         map[uint64]any{},
	}
	if err := post.Sign(replacement.private); err != nil {
		t.Fatal(err)
	}
	if err := Validate(post, fixture.known, nil); err != nil {
		t.Fatalf("replacement device event rejected: %v", err)
	}
}

func TestSupersededDeviceRejectsNewEvent(t *testing.T) {
	fixture := newAccountFixture(t)
	replacement := newDeviceFixture(t, 0x08, accounts.DeviceKindClient)
	deviceAuthorized := fixture.authorizeEvent(t, replacement, fixture.genesis.EventID, 0xd6)
	if err := Validate(deviceAuthorized, fixture.known, nil); err != nil {
		t.Fatal(err)
	}
	fixture.known[string(deviceAuthorized.EventID)] = deviceAuthorized
	transfer := events.Event{
		EventID:      bytes.Repeat([]byte{0xdc}, identifiers.ShortLength),
		EventType:    3,
		AccountID:    fixture.accountID,
		DeviceID:     fixture.first.id,
		CreatedAt:    9,
		Predecessors: [][]byte{deviceAuthorized.EventID},
		Body:         map[uint64]any{0: replacement.id},
	}
	if err := transfer.Sign(fixture.first.private); err != nil {
		t.Fatal(err)
	}
	if err := Validate(transfer, fixture.known, nil); err != nil {
		t.Fatal(err)
	}
	fixture.known[string(transfer.EventID)] = transfer

	post := events.Event{
		EventID:      bytes.Repeat([]byte{0xdd}, identifiers.ShortLength),
		EventType:    13,
		AccountID:    fixture.accountID,
		DeviceID:     fixture.first.id,
		CreatedAt:    10,
		Predecessors: [][]byte{transfer.EventID},
		Body:         map[uint64]any{},
	}
	if err := post.Sign(fixture.first.private); err != nil {
		t.Fatal(err)
	}
	if err := Validate(post, fixture.known, nil); !errors.Is(err, ErrUnauthorizedDevice) {
		t.Fatalf("superseded device event: got %v, want ErrUnauthorizedDevice", err)
	}
}

func TestTransferAmbiguityRejected(t *testing.T) {
	fixture := newAccountFixture(t)
	deviceA := newDeviceFixture(t, 0x09, accounts.DeviceKindClient)
	deviceB := newDeviceFixture(t, 0x0a, accounts.DeviceKindClient)
	authA := fixture.authorizeEvent(t, deviceA, fixture.genesis.EventID, 0xd6)
	if err := Validate(authA, fixture.known, nil); err != nil {
		t.Fatal(err)
	}
	fixture.known[string(authA.EventID)] = authA
	authB := fixture.authorizeEvent(t, deviceB, fixture.genesis.EventID, 0xd7)
	if err := Validate(authB, fixture.known, nil); err != nil {
		t.Fatal(err)
	}
	fixture.known[string(authB.EventID)] = authB

	transferA := events.Event{
		EventID:      bytes.Repeat([]byte{0xde}, identifiers.ShortLength),
		EventType:    3,
		AccountID:    fixture.accountID,
		DeviceID:     fixture.first.id,
		CreatedAt:    11,
		Predecessors: [][]byte{authA.EventID},
		Body:         map[uint64]any{0: deviceA.id},
	}
	if err := transferA.Sign(fixture.first.private); err != nil {
		t.Fatal(err)
	}
	transferB := events.Event{
		EventID:      bytes.Repeat([]byte{0xdf}, identifiers.ShortLength),
		EventType:    3,
		AccountID:    fixture.accountID,
		DeviceID:     fixture.first.id,
		CreatedAt:    12,
		Predecessors: [][]byte{authB.EventID},
		Body:         map[uint64]any{0: deviceB.id},
	}
	if err := transferB.Sign(fixture.first.private); err != nil {
		t.Fatal(err)
	}
	fixture.known[string(transferA.EventID)] = transferA
	fixture.known[string(transferB.EventID)] = transferB

	post := events.Event{
		EventID:      bytes.Repeat([]byte{0xe1}, identifiers.ShortLength),
		EventType:    13,
		AccountID:    fixture.accountID,
		DeviceID:     fixture.first.id,
		CreatedAt:    13,
		Predecessors: [][]byte{transferA.EventID, transferB.EventID},
		Body:         map[uint64]any{},
	}
	if err := post.Sign(fixture.first.private); err != nil {
		t.Fatal(err)
	}
	if err := Validate(post, fixture.known, nil); !errors.Is(err, ErrTrustConflict) {
		t.Fatalf("ambiguous transfer: got %v, want ErrTrustConflict", err)
	}
}

func TestMissingDependency(t *testing.T) {
	fixture := newAccountFixture(t)
	missing := bytes.Repeat([]byte{0xef}, identifiers.ShortLength)
	post := events.Event{
		EventID:      bytes.Repeat([]byte{0xe2}, identifiers.ShortLength),
		EventType:    13,
		AccountID:    fixture.accountID,
		DeviceID:     fixture.first.id,
		CreatedAt:    14,
		Predecessors: [][]byte{missing},
		Body:         map[uint64]any{},
	}
	if err := post.Sign(fixture.first.private); err != nil {
		t.Fatal(err)
	}
	if err := Validate(post, fixture.known, nil); !errors.Is(err, dag.ErrMissing) {
		t.Fatalf("missing dependency: got %v, want dag.ErrMissing", err)
	}
}

func TestUnknownSignerDevice(t *testing.T) {
	fixture := newAccountFixture(t)
	unknown := newDeviceFixture(t, 0x0b, accounts.DeviceKindClient)
	post := events.Event{
		EventID:      bytes.Repeat([]byte{0xe3}, identifiers.ShortLength),
		EventType:    13,
		AccountID:    fixture.accountID,
		DeviceID:     unknown.id,
		CreatedAt:    15,
		Predecessors: [][]byte{fixture.genesis.EventID},
		Body:         map[uint64]any{},
	}
	if err := post.Sign(unknown.private); err != nil {
		t.Fatal(err)
	}
	if err := Validate(post, fixture.known, nil); !errors.Is(err, ErrUnauthorizedDevice) {
		t.Fatalf("unknown device: got %v, want ErrUnauthorizedDevice", err)
	}
}

func TestMemberEventRequiresMembership(t *testing.T) {
	fixture := newAccountFixture(t)
	groupID := bytes.Repeat([]byte{0x0c}, identifiers.ShortLength)
	group := events.Event{
		EventID:      bytes.Repeat([]byte{0xe4}, identifiers.ShortLength),
		EventType:    17,
		AccountID:    fixture.accountID,
		DeviceID:     fixture.first.id,
		CreatedAt:    16,
		Predecessors: [][]byte{fixture.genesis.EventID},
		Body:         map[uint64]any{0: groupID},
	}
	if err := group.Sign(fixture.first.private); err != nil {
		t.Fatal(err)
	}
	fixture.known[string(group.EventID)] = group

	add := events.Event{
		EventID:      bytes.Repeat([]byte{0xe5}, identifiers.ShortLength),
		EventType:    19,
		AccountID:    fixture.accountID,
		DeviceID:     fixture.first.id,
		CreatedAt:    17,
		Predecessors: [][]byte{group.EventID},
		Body: map[uint64]any{
			0: groupID,
			1: uint64(2),
			2: fixture.accountID,
		},
	}
	if err := add.Sign(fixture.first.private); err != nil {
		t.Fatal(err)
	}
	if err := Validate(add, fixture.known, nil); !errors.Is(err, ErrMemberRequired) {
		t.Fatalf("member event without resolver: got %v, want ErrMemberRequired", err)
	}
	if err := Validate(add, fixture.known, func(groupID, accountID []byte) (bool, error) { return false, nil }); !errors.Is(err, ErrMemberRequired) {
		t.Fatalf("non-member account: got %v, want ErrMemberRequired", err)
	}
	member := MemberFunc(func(groupID, accountID []byte) (bool, error) { return true, nil })
	if err := Validate(add, fixture.known, member); err != nil {
		t.Fatalf("member account rejected: %v", err)
	}
}

func TestBackupDeviceCannotBecomeTrusted(t *testing.T) {
	fixture := newAccountFixture(t)
	backup := newDeviceFixture(t, 0x0d, accounts.DeviceKindBackup)
	deviceAuthorized := fixture.authorizeEvent(t, backup, fixture.genesis.EventID, 0xd6)
	if err := Validate(deviceAuthorized, fixture.known, nil); err != nil {
		t.Fatal(err)
	}
	fixture.known[string(deviceAuthorized.EventID)] = deviceAuthorized

	transfer := events.Event{
		EventID:      bytes.Repeat([]byte{0xe6}, identifiers.ShortLength),
		EventType:    3,
		AccountID:    fixture.accountID,
		DeviceID:     fixture.first.id,
		CreatedAt:    18,
		Predecessors: [][]byte{deviceAuthorized.EventID},
		Body:         map[uint64]any{0: backup.id},
	}
	if err := transfer.Sign(fixture.first.private); err != nil {
		t.Fatal(err)
	}
	if err := Validate(transfer, fixture.known, nil); !errors.Is(err, ErrTrustConflict) {
		t.Fatalf("backup trusted transfer: got %v, want ErrTrustConflict", err)
	}
}
