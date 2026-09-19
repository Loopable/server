package server

import (
	"context"
	"sync"

	"loopable.party/server/internal/protocol/instance"
)

// PeerRegistry is a thread-safe collection of known peer instance documents
// shared across requests. It is an InstanceResolver.
type PeerRegistry struct {
	mu   sync.RWMutex
	docs map[string]*instance.Document
}

func NewPeerRegistry() *PeerRegistry {
	return &PeerRegistry{docs: make(map[string]*instance.Document)}
}

// Register adds an instance document; re-registering an existing instance ID
// replaces the document.
func (p *PeerRegistry) Register(document *instance.Document) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	copyOf := *document
	p.docs[string(copyOf.InstanceID)] = &copyOf
	return nil
}

func (p *PeerRegistry) Resolve(ctx context.Context, instanceID []byte) (*instance.Document, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if document, ok := p.docs[string(instanceID)]; ok {
		copyOf := *document
		return &copyOf, nil
	}
	return nil, ErrUnknownPeerInstance
}
