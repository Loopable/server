package federation

import (
	"errors"
	"sync"
	"time"
)

const ReplayWindow = 300 * time.Second

var ErrReplay = errors.New("request ID replayed within the replay window")

// ReplayCache retains sender/request pairs for the federation replay window.
type ReplayCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

func NewReplayCache() *ReplayCache { return &ReplayCache{entries: make(map[string]time.Time)} }

// Observe records a request and returns ErrReplay when the pair was seen recently.
func (c *ReplayCache) Observe(senderID, requestID []byte, now time.Time) error {
	if len(senderID) == 0 || len(requestID) == 0 {
		return errors.New("sender and request IDs are required")
	}
	key := string(senderID) + string(requestID)
	c.mu.Lock()
	defer c.mu.Unlock()
	for storedKey, expires := range c.entries {
		if !now.Before(expires) {
			delete(c.entries, storedKey)
		}
	}
	if expires, ok := c.entries[key]; ok && now.Before(expires) {
		return ErrReplay
	}
	c.entries[key] = now.Add(ReplayWindow)
	return nil
}

func (c *ReplayCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
