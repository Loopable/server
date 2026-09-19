package federation

import "testing"

func TestCanonicalPath(t *testing.T) {
	tests := map[string]string{"/a/%2F/": "/a/%2f/", "/a/%7E": "/a/~", "/a b": "/a%20b", "/": "/"}
	for input, want := range tests {
		got, err := CanonicalPath(input)
		if err != nil {
			t.Fatalf("CanonicalPath(%q): %v", input, err)
		}
		if got != want {
			t.Errorf("CanonicalPath(%q) = %q, want %q", input, got, want)
		}
	}
	for _, input := range []string{"a", "/a/./b", "/a/%2e%2e/b", "/a/%zz"} {
		if _, err := CanonicalPath(input); err == nil {
			t.Errorf("CanonicalPath(%q) accepted invalid path", input)
		}
	}
}

func TestCanonicalQuery(t *testing.T) {
	got, err := CanonicalQuery("b=2&a&a=1")
	if err != nil {
		t.Fatal(err)
	}
	if got != "a=&a=1&b=2" {
		t.Fatalf("CanonicalQuery() = %q", got)
	}
	got, err = CanonicalQuery("x=hello+world&x=%7e&x=%2F")
	if err != nil {
		t.Fatal(err)
	}
	if got != "x=%2f&x=hello%2bworld&x=~" {
		t.Fatalf("CanonicalQuery() = %q", got)
	}
}
