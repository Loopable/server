package accounts

import (
	"errors"
	"testing"
)

func TestCanonicalUsername(t *testing.T) {
	for _, value := range []string{"alice", "12cool", "AlicE"} {
		canonical, err := CanonicalUsername(value)
		if err != nil {
			t.Errorf("CanonicalUsername(%q): %v", value, err)
		}
		if canonical != "alice" && canonical != "12cool" {
			t.Errorf("CanonicalUsername(%q) = %q", value, canonical)
		}
	}
	for _, value := range []string{"____", "1234", "ab", "abcdefghijklmno", "_alice", "alice_", "a-bc"} {
		if _, err := CanonicalUsername(value); !errors.Is(err, ErrInvalidUsername) {
			t.Errorf("CanonicalUsername(%q) error = %v", value, err)
		}
	}
}
