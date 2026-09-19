package sync

import (
	"testing"
)

// FuzzParseRequest feeds arbitrary bytes to synchronize-request parsing.
func FuzzParseRequest(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xa1, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseRequest(data)
	})
}

// FuzzParsePage feeds arbitrary bytes to sync-page parsing.
func FuzzParsePage(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xa1, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParsePage(data)
	})
}
