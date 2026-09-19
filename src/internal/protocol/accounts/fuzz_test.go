package accounts

import (
	"testing"

	"loopable.party/server/internal/protocol/encoding"
)

// FuzzFirstDevice decodes arbitrary wire bytes and runs first-device
// authorization parsing; ParseFirstDeviceAuthorization must never panic.
func FuzzFirstDevice(f *testing.F) {
	f.Add([]byte{0xa0})
	f.Fuzz(func(t *testing.T, data []byte) {
		var value any
		if err := encoding.Decode(data, &value); err != nil {
			return
		}
		_, _ = ParseFirstDeviceAuthorization(value)
	})
}
