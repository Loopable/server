package accounts

import "testing"

func TestHandleBuildsCanonicalForm(t *testing.T) {
	for _, testCase := range []struct {
		username string
		domain   string
		want     string
	}{
		{"alice", "home.example", "@alice:home.example"},
		{"AlicE", "home.example", "@alice:home.example"},
		{"12cool", "home.example", "@12cool:home.example"},
		{"a-b-c-d", "xn--bcher-kva.example", "@a-b-c-d:xn--bcher-kva.example"},
	} {
		if got := Handle(testCase.username, testCase.domain); got != testCase.want {
			t.Errorf("Handle(%q, %q) = %q, want %q", testCase.username, testCase.domain, got, testCase.want)
		}
	}
}
