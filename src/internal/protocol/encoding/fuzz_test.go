package encoding

import (
	"bytes"
	"testing"
)

// FuzzDecode exercises strict canonical CBOR decoding. The decoder must never
// panic, and any accepted value must re-encode to its exact input bytes.
func FuzzDecode(f *testing.F) {
	f.Add([]byte{0xa0})
	f.Add([]byte{0x80})
	f.Add([]byte{0x00})
	f.Add([]byte{0x64, 'l', 'o', 'o', 'p'})
	f.Fuzz(func(t *testing.T, data []byte) {
		var value any
		if err := Decode(data, &value); err != nil {
			return
		}
		canonical, err := Encode(value)
		if err != nil {
			t.Fatalf("re-encode accepted value: %v", err)
		}
		if !bytes.Equal(canonical, data) {
			t.Fatalf("accepted input is not canonical")
		}
	})
}
