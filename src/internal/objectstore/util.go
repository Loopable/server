package objectstore

import (
	"bytes"
	"io"
	"slices"

	"loopable.party/server/internal/protocol/identifiers"
)

// sortVersions orders versions newest-first by creation time.
func sortVersions(versions []Version) {
	slices.SortFunc(versions, func(a, b Version) int {
		if !a.CreatedAt.Equal(b.CreatedAt) {
			if a.CreatedAt.Before(b.CreatedAt) {
				return 1
			}
			return -1
		}
		return bytes.Compare(a.VersionID, b.VersionID)
	})
}

// parseVersionText decodes the base32lower text form of a version ID.
func parseVersionText(text string) ([]byte, error) {
	return identifiers.Parse(identifiers.VersionID, text)
}

var _ = io.Discard
