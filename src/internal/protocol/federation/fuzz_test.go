package federation

import (
	"testing"
)

// FuzzAuthorization exercises authorization-header parsing; ParseAuthorization
// must never panic on arbitrary input.
func FuzzAuthorization(f *testing.F) {
	f.Add("")
	f.Add("LoopableInstance ")
	f.Add("LoopableInstance dGVzdA==:x")
	f.Fuzz(func(t *testing.T, value string) {
		_, _ = ParseAuthorization(value)
	})
}

// FuzzCanonical verifies that canonical path/query normalization is
// idempotent: accepted inputs re-normalize to the identical value.
func FuzzCanonical(f *testing.F) {
	f.Add("/")
	f.Add("/a/../b")
	f.Add("/x?q=1")
	f.Add("//etc")
	f.Fuzz(func(t *testing.T, value string) {
		path, err := CanonicalPath(value)
		if err == nil {
			again, inErr := CanonicalPath(path)
			if inErr != nil || again != path {
				t.Fatalf("path canonicalization not idempotent: %q -> %q (%v)", value, path, inErr)
			}
		}
		query, err := CanonicalQuery(value)
		if err == nil {
			again, inErr := CanonicalQuery(query)
			if inErr != nil || again != query {
				t.Fatalf("query canonicalization not idempotent: %q -> %q (%v)", value, query, inErr)
			}
		}
	})
}
