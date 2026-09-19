package objects

import (
	"testing"

	"loopable.party/server/internal/protocol/encoding"
)

// FuzzEnvelope decodes arbitrary wire bytes and runs object-envelope parsing;
// Parse must never panic on hostile inputs.
func FuzzEnvelope(f *testing.F) {
	f.Add([]byte{0xa1, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		var value any
		if err := encoding.Decode(data, &value); err != nil {
			return
		}
		_, _ = Parse(value)
	})
}
