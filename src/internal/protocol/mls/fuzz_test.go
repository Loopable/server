package mls

import (
	"testing"

	"loopable.party/server/internal/protocol/encoding"
)

// FuzzCredentials decodes arbitrary wire bytes and runs credential parsing;
// Parse must never panic on hostile inputs.
func FuzzCredentials(f *testing.F) {
	f.Add([]byte{0x64, 't', 'e', 's', 't'})
	f.Add([]byte{0xa0})
	f.Fuzz(func(t *testing.T, data []byte) {
		var value any
		if err := encoding.Decode(data, &value); err != nil {
			return
		}
		_, _ = Parse(value)
	})
}
