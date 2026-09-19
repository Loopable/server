package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"loopable.party/server/internal/protocol/federation"
	"loopable.party/server/internal/protocol/instance"
)

// authContext carries the authenticated identity of the verified caller.
type authContext struct {
	Presented bool
	// Instance is the verifying peer instance ID (61.5) when set.
	Instance []byte
	// Account is the verifying account ID (61.9) when set.
	Account   []byte
	KeyID     []byte
	RequestID []byte
	Timestamp uint64
}

// verify authenticates the request per 61.3 through 61.9 and records it in
// the replay cache (61.7).
func (s *Server) verify(r *http.Request, body []byte) (*authContext, error) {
	value := r.Header.Get("Authorization")
	authorization, err := federation.ParseAuthorization(value)
	if err != nil {
		return nil, authInvalid{err: err}
	}
	request, err := s.requestAuthentication(r, body, authorization)
	if err != nil {
		return nil, err
	}
	now := s.cfg.Now()
	if len(authorization.AccountID) != 0 {
		return s.verifyAccount(r.Context(), authorization, request, now)
	}
	return s.verifyInstance(r.Context(), authorization, request, now)
}

// requestAuthentication reconstructs the signed request target per 61.6.
func (s *Server) requestAuthentication(r *http.Request, body []byte, authorization federation.Authorization) (federation.RequestAuthentication, error) {
	host, err := s.receivedHost(r)
	if err != nil {
		return federation.RequestAuthentication{}, err
	}
	path, err := federation.CanonicalPath(r.URL.Path)
	if err != nil {
		return federation.RequestAuthentication{}, authInvalid{err: err}
	}
	query, err := federation.CanonicalQuery(r.URL.RawQuery)
	if err != nil {
		return federation.RequestAuthentication{}, authInvalid{err: err}
	}
	return federation.RequestAuthentication{
		Method:    r.Method,
		Host:      host,
		Path:      path,
		Query:     query,
		RequestID: authorization.RequestID,
		Timestamp: authorization.Timestamp,
		BodyHash:  federation.HashBody(body),
		AccountID: authorization.AccountID,
	}, nil
}

// receivedHost normalizes the request target host and requires it to match
// this instance's canonical domain.
func (s *Server) receivedHost(r *http.Request) (string, error) {
	host := r.Host
	if hostname, _, ok := cutPort(host); ok {
		host = hostname
	}
	canonical, err := instance.CanonicalHostname(host)
	if err != nil {
		return "", authInvalid{err: err}
	}
	if canonical != s.cfg.Domain {
		return "", authInvalid{err: errors.New("request target host does not match this instance")}
	}
	return canonical, nil
}

// verifyAccount authenticates a client account request per 61.9 using the
// account's currently authorized device key. The key id identifies the current
// signing key; resolution replays the account's authorization events.
func (s *Server) verifyAccount(ctx context.Context, authorization federation.Authorization, request federation.RequestAuthentication, now time.Time) (*authContext, error) {
	publicKey, err := s.cfg.Devices.DeviceSigningKey(ctx, authorization.AccountID, authorization.KeyID)
	if err != nil {
		return nil, authInvalid{err: err}
	}
	if err := federation.VerifyRequest(publicKey, request, authorization.Signature, now); err != nil {
		return nil, authInvalid{err: err}
	}
	if err := s.replay.Observe(authorization.AccountID, authorization.RequestID, now); err != nil {
		return nil, err
	}
	return &authContext{
		Presented: true,
		Account:   authorization.AccountID,
		KeyID:     authorization.KeyID,
		RequestID: authorization.RequestID,
		Timestamp: authorization.Timestamp,
	}, nil
}

// verifyInstance authenticates a peer instance request per 61.5 using the
// peer's currently valid operational key from its fetched document.
func (s *Server) verifyInstance(ctx context.Context, authorization federation.Authorization, request federation.RequestAuthentication, now time.Time) (*authContext, error) {
	document, err := s.cfg.Peers.Resolve(ctx, authorization.InstanceID)
	if err != nil {
		return nil, authInvalid{err: err}
	}
	operationalKey, ok := document.OperationalKey(authorization.KeyID)
	if !ok {
		return nil, authInvalid{err: errors.New("unknown instance operational key")}
	}
	nowUnix := uint64(now.Unix())
	if nowUnix < operationalKey.NotBefore || nowUnix > operationalKey.NotAfter {
		return nil, authInvalid{err: errors.New("instance operational key is not currently valid")}
	}
	if err := federation.VerifyRequest(operationalKey.PublicKey, request, authorization.Signature, now); err != nil {
		return nil, authInvalid{err: err}
	}
	if err := s.replay.Observe(authorization.InstanceID, authorization.RequestID, now); err != nil {
		return nil, err
	}
	return &authContext{
		Presented: true,
		Instance:  authorization.InstanceID,
		KeyID:     authorization.KeyID,
		RequestID: authorization.RequestID,
		Timestamp: authorization.Timestamp,
	}, nil
}

func cutPort(host string) (string, string, bool) {
	for i := 0; i < len(host); i++ {
		if host[i] == ':' {
			return host[:i], host[i+1:], true
		}
	}
	return host, "", false
}
