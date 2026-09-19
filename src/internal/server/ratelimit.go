package server

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"loopable.party/server/internal/protocol/identifiers"
)

// rateLimiter is a fixed-window limiter keyed by rate group and identity
// (account, instance, or client IP). Identities and groups come from 61 and
// 82.4; zero or absent group rates disable limiting for that group.
type rateLimiter struct {
	mu      sync.Mutex
	groups  map[string]float64
	now     func() time.Time
	windows map[string]*rateWindow
}

type rateWindow struct {
	count  int
	resets time.Time
}

func newRateLimiter(groups map[string]float64) *rateLimiter {
	return &rateLimiter{
		groups:  groups,
		now:     time.Now,
		windows: make(map[string]*rateWindow),
	}
}

// allow accounts one request and reports whether it fits the group window.
// The returned retryAfter is the seconds until the window resets when !ok.
func (l *rateLimiter) allow(identity, group string) (bool, uint64) {
	if l == nil || len(l.groups) == 0 {
		return true, 0
	}
	rps, ok := l.groups[group]
	if !ok || rps <= 0 {
		return true, 0
	}
	capacity := int(rps * 60)
	if capacity < 1 {
		capacity = 1
	}
	key := group + "|" + identity
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	window, ok := l.windows[key]
	if !ok || !now.Before(window.resets) {
		window = &rateWindow{count: 0, resets: now.Add(time.Minute)}
		l.windows[key] = window
	}
	window.count++
	if window.count <= capacity {
		return true, 0
	}
	retry := uint64(window.resets.Sub(now).Seconds()) + 1
	return false, retry
}

// identity classifies the requester for rate limiting.
func (l *rateLimiter) identity(r *http.Request) string {
	auth := requestAuth(r)
	if auth != nil {
		kind := identifiers.AccountID
		topic := auth.Account
		if len(topic) == 0 {
			kind = identifiers.InstanceID
			topic = auth.Instance
		}
		if len(topic) != 0 {
			text, err := identifiers.String(kind, topic)
			if err == nil {
				if kind == identifiers.AccountID {
					return "acc:" + text
				}
				return "inst:" + text
			}
		}
	}
	host, _, err := cutHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return "ip:" + host
	}
	return "ip:unknown"
}

// limit runs fn under the rate group window of 82.4, rejecting with
// E_RATE_LIMITED and a Retry-After hint when exhausted.
func (s *Server) limit(w http.ResponseWriter, r *http.Request, group string, fn func()) {
	if s.limiter == nil {
		fn()
		return
	}
	if ok, retry := s.limiter.allow(s.limiter.identity(r), group); !ok {
		fail(w, "E_RATE_LIMITED", requestContextID(r), map[uint64]any{0: retry}, errors.New("rate limit exceeded"))
		return
	}
	fn()
}

func cutHostPort(address string) (string, string, error) {
	if address == "" {
		return "", "", errors.New("empty address")
	}
	for i := 0; i < len(address); i++ {
		if address[i] == ':' {
			return address[:i], address[i+1:], nil
		}
	}
	return address, "", nil
}
