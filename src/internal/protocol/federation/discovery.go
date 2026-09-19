package federation

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"loopable.party/server/internal/protocol/instance"
)

// VerifyInstanceRequest authenticates a federation request against a claimed
// instance, per 61.5 steps 5 through 8: the claimed operational key must be
// listed in the document and time-valid for the request timestamp, and the
// request signature and freshness must validate.
func VerifyInstanceRequest(document instance.Document, keyID []byte, request RequestAuthentication, signature []byte, now time.Time) error {
	key, ok := document.OperationalKey(keyID)
	if !ok {
		return errors.New("operational key is not listed in the instance document")
	}
	if request.Timestamp < key.NotBefore || request.Timestamp > key.NotAfter {
		return errors.New("operational key is not valid for the request timestamp")
	}
	return VerifyRequest(key.PublicKey, request, signature, now)
}

// Fetcher retrieves and returns a peer's unsigned-valid instance document, for
// example by calling GET /v1/instance and decoding the signed document. The
// returned document is validated before it is cached.
type Fetcher func(instanceID []byte) (instance.Document, error)

// DocumentCache caches verified peer instance documents, per 61.2. It fetches
// on first contact, when the cached document is stale, and refuses to serve a
// document on or after the earliest not_after of its operational keys.
type DocumentCache struct {
	mu        sync.Mutex
	fetch     Fetcher
	freshness time.Duration
	docs      map[string]cachedDocument
}

type cachedDocument struct {
	document  instance.Document
	expiresAt time.Time
}

// NewDocumentCache creates a cache with the configured freshness interval.
func NewDocumentCache(fetch Fetcher, freshness time.Duration) *DocumentCache {
	if freshness <= 0 {
		freshness = 24 * time.Hour
	}
	return &DocumentCache{fetch: fetch, freshness: freshness, docs: make(map[string]cachedDocument)}
}

// Document returns the verified instance document for instanceID, fetching a
// fresh copy when needed. It validates the document signature and the
// derivable instance_id each time it fetches, per 61.2 steps 2 and 3.
func (c *DocumentCache) Document(instanceID []byte) (instance.Document, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cached, ok := c.docs[string(instanceID)]; ok && c.fresh(cached) {
		return cached.document, nil
	}
	document, err := c.fetch(instanceID)
	if err != nil {
		return instance.Document{}, fmt.Errorf("fetch instance document: %w", err)
	}
	if string(document.InstanceID) != string(instanceID) {
		return instance.Document{}, errors.New("instance document does not identify the claimed instance")
	}
	if err := document.Verify(); err != nil {
		return instance.Document{}, fmt.Errorf("verify instance document: %w", err)
	}
	cached := cachedDocument{document: document, expiresAt: time.Now().Add(c.freshness)}
	c.docs[string(instanceID)] = cached
	return document, nil
}

// fresh reports whether the document may be served without a refetch, per
// 61.2: not yet past the freshness interval and not on or after the earliest
// operational-key not_after.
func (c *DocumentCache) fresh(cached cachedDocument) bool {
	now := time.Now()
	if !now.Before(cached.expiresAt) {
		return false
	}
	for _, key := range cached.document.OperationalKeys {
		if now.Unix() >= int64(key.NotAfter) {
			return false
		}
	}
	return true
}

// Forget removes the cached document, forcing a refetch on the next request.
func (c *DocumentCache) Forget(instanceID []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.docs, string(instanceID))
}
