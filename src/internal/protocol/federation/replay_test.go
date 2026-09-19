package federation

import (
	"errors"
	"testing"
	"time"
)

func TestReplayCacheWindow(t *testing.T) {
	cache := NewReplayCache()
	now := time.Unix(1_000, 0)
	if err := cache.Observe([]byte("sender"), []byte("request"), now); err != nil {
		t.Fatal(err)
	}
	if err := cache.Observe([]byte("sender"), []byte("request"), now.Add(299*time.Second)); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay error = %v", err)
	}
	if err := cache.Observe([]byte("sender"), []byte("request"), now.Add(300*time.Second)); err != nil {
		t.Fatal(err)
	}
	if cache.Len() != 1 {
		t.Fatalf("cache length = %d, want 1", cache.Len())
	}
}

func TestReplayCacheScopesBySender(t *testing.T) {
	cache := NewReplayCache()
	now := time.Unix(1_000, 0)
	if err := cache.Observe([]byte("one"), []byte("request"), now); err != nil {
		t.Fatal(err)
	}
	if err := cache.Observe([]byte("two"), []byte("request"), now); err != nil {
		t.Fatal(err)
	}
}
