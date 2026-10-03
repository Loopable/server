package accounts

import (
	"bytes"
	"testing"
	"time"

	"loopable.party/server/internal/protocol/events"
)

var (
	localInstance  = bytes.Repeat([]byte{0x01}, 32)
	remoteInstance = bytes.Repeat([]byte{0x02}, 32)
	accountOne     = bytes.Repeat([]byte{0x11}, 32)
	accountTwo     = bytes.Repeat([]byte{0x22}, 32)
)

// changeAt is a fixed effective time, well inside the 90-day window.
const changeAt = 1_700_000_000

func genesisFor(accountID []byte, username string, home []byte) events.Event {
	return events.Event{
		EventType: 0,
		AccountID: accountID,
		CreatedAt: 1,
		Body: map[uint64]any{
			0: bytes.Repeat([]byte{0x0a}, 32),
			1: username,
			2: home,
			3: map[uint64]any{},
		},
	}
}

func changeFor(accountID []byte, previous, current string, createdAt uint64) events.Event {
	return events.Event{
		EventType: 4,
		AccountID: accountID,
		CreatedAt: createdAt,
		Body:      map[uint64]any{0: previous, 1: current},
	}
}

func deletionFor(accountID []byte, createdAt uint64) events.Event {
	return events.Event{
		EventType: 5,
		AccountID: accountID,
		CreatedAt: createdAt,
		Body:      map[uint64]any{},
	}
}

func reservedAt(createdAt uint64) time.Time {
	return time.Unix(int64(createdAt), 0).UTC().Add(ReservationPeriod)
}

func TestDeriveUsernameClaimsHoldsTheGenesisName(t *testing.T) {
	stored := []events.Event{genesisFor(accountOne, "Alice", localInstance)}
	claims, err := DeriveUsernameClaims(stored, localInstance)
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) != 1 {
		t.Fatalf("claims %#v, want one held name", claims)
	}
	if claims[0].Username != "alice" || !claims[0].Held || !bytes.Equal(claims[0].AccountID, accountOne) {
		t.Fatalf("claim %#v, want alice held by the account", claims[0])
	}
}

func TestDeriveUsernameClaimsReservesTheReleasedName(t *testing.T) {
	stored := []events.Event{
		genesisFor(accountOne, "alice", localInstance),
		changeFor(accountOne, "alice", "alicia", changeAt),
	}
	claims, err := DeriveUsernameClaims(stored, localInstance)
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) != 2 {
		t.Fatalf("claims %#v, want one held and one reserved name", claims)
	}
	// Sorted by username, so the released name comes first.
	if claims[0].Username != "alice" || claims[0].Held || !claims[0].ReservedUntil.Equal(reservedAt(changeAt)) {
		t.Fatalf("claim %#v, want alice reserved for 90 days", claims[0])
	}
	if claims[1].Username != "alicia" || !claims[1].Held {
		t.Fatalf("claim %#v, want alicia held", claims[1])
	}
}

func TestDeriveUsernameClaimsReservesTheDeletedName(t *testing.T) {
	stored := []events.Event{
		genesisFor(accountOne, "alice", localInstance),
		deletionFor(accountOne, changeAt),
	}
	claims, err := DeriveUsernameClaims(stored, localInstance)
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) != 1 {
		t.Fatalf("claims %#v, want the deleted account's name reserved", claims)
	}
	if claims[0].Username != "alice" || claims[0].Held || !claims[0].ReservedUntil.Equal(reservedAt(changeAt)) {
		t.Fatalf("claim %#v, want alice reserved after deletion", claims[0])
	}
}

func TestDeriveUsernameClaimsIgnoresAccountsHomedElsewhere(t *testing.T) {
	stored := []events.Event{
		genesisFor(accountOne, "alice", localInstance),
		genesisFor(accountTwo, "alice", remoteInstance),
	}
	claims, err := DeriveUsernameClaims(stored, localInstance)
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) != 1 || !bytes.Equal(claims[0].AccountID, accountOne) {
		t.Fatalf("claims %#v, want only the locally hosted account", claims)
	}
}

func TestDeriveUsernameClaimsKeepsAnInconsistentReleaseReserved(t *testing.T) {
	stored := []events.Event{
		genesisFor(accountOne, "alice", localInstance),
		genesisFor(accountTwo, "brian", localInstance),
		// A history that releases a name the account does not hold cannot
		// arise through acceptance, which refuses it per 34.7. Existing data may
		// still contain one, and it must not free brian for a third account.
		changeFor(accountOne, "brian", "alicia", changeAt),
	}
	claims, err := DeriveUsernameClaims(stored, localInstance)
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) != 3 {
		t.Fatalf("claims %#v, want two held names and one reservation", claims)
	}
	reserved := false
	for _, claim := range claims {
		if claim.Username == "brian" && claim.AccountID[0] == accountOne[0] &&
			!claim.Held && claim.ReservedUntil.Equal(reservedAt(changeAt)) {
			reserved = true
		}
	}
	if !reserved {
		t.Fatalf("claims %#v, want brian reserved by the account that released it", claims)
	}
}

func TestDeriveAccountUsernames(t *testing.T) {
	stored := []events.Event{
		genesisFor(accountOne, "alice", localInstance),
		changeFor(accountOne, "alice", "alicia", changeAt),
	}
	state, err := DeriveAccountUsernames(stored)
	if err != nil {
		t.Fatal(err)
	}
	if state.Current != "alicia" {
		t.Fatalf("current username %q, want alicia", state.Current)
	}
	if until, ok := state.Reserved["alice"]; !ok || !until.Equal(reservedAt(changeAt)) {
		t.Fatalf("reserved %#v, want alice reserved for 90 days", state.Reserved)
	}

	deleted, err := DeriveAccountUsernames(append(stored, deletionFor(accountOne, changeAt)))
	if err != nil {
		t.Fatal(err)
	}
	if deleted.Current != "" {
		t.Fatalf("current username %q, want none after deletion", deleted.Current)
	}
	if until, ok := deleted.Reserved["alicia"]; !ok || !until.Equal(reservedAt(changeAt)) {
		t.Fatalf("reserved %#v, want alicia reserved after deletion", deleted.Reserved)
	}
}

func TestUsernameAvailable(t *testing.T) {
	stored := []events.Event{
		genesisFor(accountOne, "alice", localInstance),
		changeFor(accountOne, "alice", "alicia", changeAt),
	}
	claims, err := DeriveUsernameClaims(stored, localInstance)
	if err != nil {
		t.Fatal(err)
	}
	insideReservation := time.Unix(changeAt, 0).UTC().Add(ReservationPeriod - time.Hour)
	afterReservation := reservedAt(changeAt).Add(time.Hour)

	for _, testCase := range []struct {
		username string
		account  []byte
		now      time.Time
		want     bool
	}{
		{"alicia", accountTwo, insideReservation, false},
		{"alice", accountTwo, insideReservation, false},
		{"alice", accountTwo, afterReservation, true},
		{"alice", accountOne, insideReservation, true},
		{"alicia", accountOne, insideReservation, true},
		{"ALICE", accountTwo, insideReservation, false},
		{"unused", accountTwo, insideReservation, true},
	} {
		got := UsernameAvailable(claims, testCase.username, testCase.account, testCase.now)
		if got != testCase.want {
			t.Errorf("UsernameAvailable(%q, %x, %v) = %t, want %t",
				testCase.username, testCase.account[0], testCase.now, got, testCase.want)
		}
	}
}
