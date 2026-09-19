package identifiers

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestStringAndParseRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		kind Type
		wire []byte
		want string
	}{
		{
			name: "short",
			kind: EventID,
			wire: bytes.Repeat([]byte{0}, ShortLength),
			want: "aaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		{
			name: "long",
			kind: ObjectID,
			wire: bytes.Repeat([]byte{0xff}, LongLength),
			want: "777777777777777777777777777777777777777777777777777a",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			text, err := String(test.kind, test.wire)
			if err != nil {
				t.Fatal(err)
			}
			if text != test.want {
				t.Fatalf("String() = %q, want %q", text, test.want)
			}

			decoded, err := Parse(test.kind, text)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(decoded, test.wire) {
				t.Fatalf("Parse() = %x, want %x", decoded, test.wire)
			}
		})
	}
}

func TestParseAcceptsUppercase(t *testing.T) {
	wire := bytes.Repeat([]byte{0x12}, ShortLength)
	text, err := String(DeviceID, wire)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Parse(DeviceID, upper(text))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, wire) {
		t.Fatalf("Parse() = %x, want %x", decoded, wire)
	}
}

func TestParseRejectsPaddingAndWrongLength(t *testing.T) {
	for _, text := range []string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaa=",
		"aaaaaaaaaaaaaaaaaaaaaaaaa",
		"aaaaaaaaaaaaaaaaaaaaaaaaa0",
	} {
		if _, err := Parse(EventID, text); err == nil {
			t.Fatalf("Parse(%q) succeeded, want error", text)
		}
	}
}

func TestDeriveIDs(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)

	account, err := DeriveAccountID(key)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := DeriveInstanceID(key)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(account, instance) {
		t.Fatal("account and instance IDs must use different domains")
	}

	if got := hex.EncodeToString(account); got != "e3c74e0c100a3cdf5ff0aa3a4f5a91dcb0b8115290418fec456657d31c0cd7b0" {
		t.Fatalf("account ID = %s", got)
	}
	if got := hex.EncodeToString(instance); got != "5082967611d4ae30b89ef9e49075069cf8a0f33b9e234177d558542476d4dfaf" {
		t.Fatalf("instance ID = %s", got)
	}
}

func TestDeriveRejectsWrongKeyLength(t *testing.T) {
	if _, err := DeriveAccountID(make([]byte, 31)); err == nil {
		t.Fatal("DeriveAccountID succeeded with a short key")
	}
}

func upper(value string) string {
	result := []byte(value)
	for index, character := range result {
		if character >= 'a' && character <= 'z' {
			result[index] = character - ('a' - 'A')
		}
	}
	return string(result)
}
