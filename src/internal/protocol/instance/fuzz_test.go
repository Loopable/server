package instance

import (
	"testing"

	"loopable.party/server/internal/protocol/encoding"
)

// FuzzParseDocument decodes arbitrary wire bytes and runs instance-document
// parsing; Parse must never panic on hostile inputs.
func FuzzParseDocument(f *testing.F) {
	f.Add([]byte{0xa1, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		var value any
		if err := encoding.Decode(data, &value); err != nil {
			return
		}
		_, _ = Parse(value)
	})
}
