package events

import (
	"testing"

	"loopable.party/server/internal/protocol/encoding"
)

// FuzzParseWire decodes arbitrary wire bytes and runs envelope parsing; Parse
// must never panic, including on structurally hostile inputs.
func FuzzParseWire(f *testing.F) {
	f.Add([]byte{0xa1, 0x00, 0x00})
	f.Add([]byte{0xa7, 0x00, 0x64, 'v', '0', '.', '1'})
	f.Fuzz(func(t *testing.T, data []byte) {
		var value any
		if err := encoding.Decode(data, &value); err != nil {
			return
		}
		_, _ = Parse(value)
	})
}
