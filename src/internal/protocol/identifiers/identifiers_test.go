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
			want: "777777777777777777777777777777777777777777777777777q",
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

	if got := hex.EncodeToString(account); got != "b60ffe62eb4e4031d113dcdf97d5dc28141001365caa07ed7b4eaf5222676975" {
		t.Fatalf("account ID = %s", got)
	}
	if got := hex.EncodeToString(instance); got != "0d0e36963c4cac56a5520e10ce3c335c667b36bd48bf8a6e0f44c7bb2e421293" {
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
