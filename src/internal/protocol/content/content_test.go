package content

import (
	"bytes"
	"errors"
	"testing"

	"loopable.party/server/internal/protocol/identifiers"
)

func TestValidateMembershipValid(t *testing.T) {
	body := map[uint64]any{
		0: bytes.Repeat([]byte{1}, identifiers.LongLength),
	}
	if err := ValidateMembership(body); err != nil {
		t.Fatalf("valid membership rejected: %v", err)
	}
	body[1] = RoleOwner
	if err := ValidateMembership(body); err != nil {
		t.Fatalf("owned membership rejected: %v", err)
	}
	delete(body, 1)
	body[1] = uint64(9)
	if err := ValidateMembership(body); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}
}

func TestValidateMembershipRejectsInvalid(t *testing.T) {
	if err := ValidateMembership(map[uint64]any{}); !errors.Is(err, ErrEmpty) {
		t.Fatalf("empty: got %v, want ErrEmpty", err)
	}
	if err := ValidateMembership(map[uint64]any{0: "short"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("short account id: got %v, want ErrInvalid", err)
	}
	if err := ValidateMembership(map[uint64]any{0: bytes.Repeat([]byte{1}, identifiers.LongLength), 2: "x"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unexpected field: got %v, want ErrInvalid", err)
	}
}

func TestValidateGroupMetadata(t *testing.T) {
	if err := ValidateGroupMetadata(map[uint64]any{0: "Family"}); err != nil {
		t.Fatalf("valid metadata rejected: %v", err)
	}
	if err := ValidateGroupMetadata(map[uint64]any{0: "Family", 1: "extra"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("extra field: got %v, want ErrInvalid", err)
	}
	if err := ValidateGroupMetadata(map[uint64]any{0: uint64(7)}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-text name: got %v, want ErrInvalid", err)
	}
}

func TestValidatePost(t *testing.T) {
	valid := map[uint64]any{0: ""}
	if err := ValidatePost(valid); err != nil {
		t.Fatalf("empty text post rejected: %v", err)
	}
	valid = map[uint64]any{0: "hello", 2: "en-US"}
	if err := ValidatePost(valid); err != nil {
		t.Fatalf("localized post rejected: %v", err)
	}
	attachments := []any{map[uint64]any{0: bytes.Repeat([]byte{2}, identifiers.LongLength)}}
	if err := ValidatePost(map[uint64]any{0: "hi", 1: attachments}); err != nil {
		t.Fatalf("post with attachments rejected: %v", err)
	}
	if err := ValidatePost(map[uint64]any{}); !errors.Is(err, ErrEmpty) {
		t.Fatalf("empty post: got %v, want ErrEmpty", err)
	}
	if err := ValidatePost(map[uint64]any{1: "wrong"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-array attachments: got %v, want ErrInvalid", err)
	}
}

func TestValidateReply(t *testing.T) {
	parent := map[uint64]any{0: bytes.Repeat([]byte{3}, identifiers.LongLength)}
	valid := map[uint64]any{0: parent, 1: "agree"}
	if err := ValidateReply(valid); err != nil {
		t.Fatalf("valid reply rejected: %v", err)
	}
	parent[1] = bytes.Repeat([]byte{4}, identifiers.LongLength)
	if err := ValidateReply(valid); err != nil {
		t.Fatalf("versioned reply rejected: %v", err)
	}
	if err := ValidateReply(map[uint64]any{0: parent}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing text: got %v, want ErrInvalid", err)
	}
	if err := ValidateReply(map[uint64]any{1: "no parent"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing parent: got %v, want ErrInvalid", err)
	}
	if err := ValidateReply(map[uint64]any{0: "not-a-map", 1: "x"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("malformed parent: got %v, want ErrInvalid", err)
	}
}
