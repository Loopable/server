// Package capabilities implements Loopable protocol capability negotiation.
package capabilities

import (
	"errors"
	"fmt"
	"strings"
)

type Capability struct {
	ID        string
	Version   string
	Mandatory bool
}

var Registered = []Capability{
	{ID: "events", Version: "0.1", Mandatory: true},
	{ID: "objects", Version: "0.1", Mandatory: true},
	{ID: "account-lookup", Version: "0.1", Mandatory: true},
	{ID: "sync-v1", Version: "0.1", Mandatory: true},
	{ID: "mls-1.0", Version: "1.0", Mandatory: true},
	{ID: "webpush", Version: "0.1", Mandatory: false},
}

func (c Capability) Wire() map[uint64]any {
	return map[uint64]any{0: c.ID, 1: c.Version, 2: c.Mandatory}
}

func (c Capability) Validate() error {
	if c.ID == "" || strings.ContainsAny(c.ID, " \t\r\n") || !validVersion(c.Version) {
		return errors.New("invalid capability")
	}
	return nil
}

// Negotiate returns the mutually supported capabilities and rejects mandatory gaps.
func Negotiate(local, remote []Capability) ([]Capability, error) {
	localByID := make(map[string]Capability, len(local))
	for _, capability := range local {
		if err := capability.Validate(); err != nil {
			return nil, err
		}
		localByID[capability.ID] = capability
	}
	remoteByID := make(map[string]Capability, len(remote))
	for _, capability := range remote {
		if err := capability.Validate(); err != nil {
			return nil, err
		}
		remoteByID[capability.ID] = capability
	}
	result := make([]Capability, 0)
	for _, capability := range local {
		peer, ok := remoteByID[capability.ID]
		if !ok || peer.Version != capability.Version {
			if capability.Mandatory {
				return nil, fmt.Errorf("mandatory capability %q unsupported", capability.ID)
			}
			continue
		}
		result = append(result, capability)
	}
	for _, capability := range remote {
		if capability.Mandatory {
			if localCapability, ok := localByID[capability.ID]; !ok || localCapability.Version != capability.Version {
				return nil, fmt.Errorf("peer requires unsupported capability %q", capability.ID)
			}
		}
	}
	return result, nil
}

func validVersion(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	for _, part := range parts {
		for i := 0; i < len(part); i++ {
			if part[i] < '0' || part[i] > '9' {
				return false
			}
		}
	}
	return true
}
