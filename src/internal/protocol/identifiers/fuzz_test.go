package identifiers

import (
	"bytes"
	"testing"
)

// FuzzParse feeds arbitrary text to Parse for every identifier kind; Parse must
// never panic, and String must round-trip any accepted value.
func FuzzParse(f *testing.F) {
	canonical := func(kind Type, fill byte) string {
		raw := bytes.Repeat([]byte{fill}, kind.length())
		s, err := String(kind, raw)
		if err != nil {
			f.Fatal(err)
		}
		return s
	}
	f.Add("")
	f.Add("z")
	f.Add(canonical(EventID, 0x2a))
	f.Add(canonical(ObjectID, 0x2b))
	f.Fuzz(func(t *testing.T, text string) {
		for _, kind := range []Type{EventID, ObjectID, AccountID, InstanceID, DeviceID, RequestID, KeyID, RecipientKeyID, VersionID, GroupID} {
			raw, err := Parse(kind, text)
			if err != nil {
				continue
			}
			back, err := String(kind, raw)
			if err != nil {
				t.Fatalf("String(%v, %x): %v", kind, raw, err)
			}
			if back != text {
				t.Fatalf("round trip %q -> %q", text, back)
			}
		}
	})
}
