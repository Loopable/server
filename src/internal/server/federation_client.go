package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"loopable.party/server/internal/protocol/encoding"
	"loopable.party/server/internal/protocol/federation"
	"loopable.party/server/internal/protocol/identifiers"
	"loopable.party/server/internal/protocol/instance"
)

// federationSigner signs outbound requests as this instance (61.3-61.4). The
// key must be an operational key of the instance document (61.1).
type federationSigner struct {
	instanceID []byte
	keyID      []byte
	private    ed25519.PrivateKey
}

// newFederationSigner binds an operational private key to this instance's
// document, verifying the key is listed among the operational keys.
func newFederationSigner(document *instance.Document, private ed25519.PrivateKey) (federationSigner, error) {
	if len(private) != ed25519.PrivateKeySize {
		return federationSigner{}, errors.New("invalid federation signing key length")
	}
	public, ok := private.Public().(ed25519.PublicKey)
	if !ok {
		return federationSigner{}, errors.New("signing key is not Ed25519")
	}
	digest := sha256.Sum256(public)
	keyID := digest[:16]
	listed := false
	for _, key := range document.OperationalKeys {
		if bytes.Equal(key.KeyID, keyID) && bytes.Equal(key.PublicKey, public) {
			listed = true
			break
		}
	}
	if !listed {
		return federationSigner{}, errors.New("federation signing key is not an operational key of this instance")
	}
	return federationSigner{
		instanceID: append([]byte(nil), document.InstanceID...),
		keyID:      append([]byte(nil), keyID...),
		private:    private,
	}, nil
}

// currentlyValid reports whether the operational key is time-valid at now
// per 61.5 (not_before <= ts <= not_after).
func (s federationSigner) currentlyValid(document *instance.Document, now time.Time) bool {
	key, ok := document.OperationalKey(s.keyID)
	if !ok {
		return false
	}
	nowUnix := uint64(now.Unix())
	return nowUnix >= key.NotBefore && nowUnix <= key.NotAfter
}

// header builds the signed Authorization header for one federated request.
func (s federationSigner) header(method, domain, path, query string, body []byte) (string, error) {
	canonicalPath, err := federation.CanonicalPath(path)
	if err != nil {
		return "", err
	}
	canonicalQuery, err := federation.CanonicalQuery(query)
	if err != nil {
		return "", err
	}
	requestID, err := identifiers.Random(identifiers.RequestID)
	if err != nil {
		return "", err
	}
	request := federation.RequestAuthentication{
		Method:    method,
		Host:      domain,
		Path:      canonicalPath,
		Query:     canonicalQuery,
		RequestID: requestID,
		Timestamp: uint64(time.Now().Unix()),
		BodyHash:  federation.HashBody(body),
	}
	signature, err := federation.SignRequest(s.private, request)
	if err != nil {
		return "", err
	}
	authorization := federation.Authorization{
		InstanceID: s.instanceID,
		KeyID:      s.keyID,
		RequestID:  requestID,
		Timestamp:  request.Timestamp,
		Signature:  signature,
	}
	return authorization.HeaderValue()
}

// federationTransport performs authenticated requests against a peer instance
// over HTTPS (13.8). Transport identity is TLS; protocol identity is the
// Loopable signature (61.8).
type federationTransport struct {
	signer federationSigner
	client *http.Client
	scheme string
	port   string
}

// federationResponseLimit bounds one outbound response body.
const federationResponseLimit = 64 << 20

// newFederationTransport assembles the outbound client.
func newFederationTransport(signer federationSigner, scheme, port string, client *http.Client) *federationTransport {
	if scheme == "" {
		scheme = "https"
	}
	if client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		client = &http.Client{
			Transport:     transport,
			Timeout:       90 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return &federationTransport{signer: signer, client: client, scheme: scheme, port: port}
}

func (t *federationTransport) baseURL(domain string) string {
	host := domain
	if t.port != "" && t.port != "443" {
		host = net.JoinHostPort(domain, t.port)
	}
	return t.scheme + "://" + host
}

// call signs and issues one federated request (61.3). The two public endpoints
// (61.3) skip the Authorization header. Non-200 responses yield a
// federationHTTPError carrying the peer's error code and retryable flag.
func (t *federationTransport) call(ctx context.Context, method, domain, path, query string, body []byte) ([]byte, error) {
	target := t.baseURL(domain) + path
	if query != "" {
		target += "?" + query
	}
	var request *http.Request
	var err error
	if body == nil {
		request, err = http.NewRequestWithContext(ctx, method, target, nil)
	} else {
		request, err = http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	}
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/cbor")
	request.Host = domain

	public := method == http.MethodGet && (path == "/v1/instance" || path == "/v1/capabilities")
	if !public {
		header, err := t.signer.header(method, domain, path, query, body)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Authorization", header)
	}

	response, err := t.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("federation request %s %s: %w", method, target, err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, federationResponseLimit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(responseBody)) > federationResponseLimit {
		return nil, errors.New("federation response exceeds the response limit")
	}
	if response.StatusCode != http.StatusOK {
		return nil, peerError(response.StatusCode, responseBody)
	}
	return responseBody, nil
}

// federationHTTPError is a non-200 federation response (80-errors.md).
type federationHTTPError struct {
	status    int
	code      string
	retryable bool
}

func (e *federationHTTPError) Error() string {
	if e.code != "" {
		return e.code
	}
	return fmt.Sprintf("federation request failed with status %d", e.status)
}

// isAuthError reports whether the peer rejected the authentication, which per
// 62.7 requires re-fetching the peer's instance document before retrying.
func (e *federationHTTPError) isAuthError() bool {
	return e.status == http.StatusUnauthorized || e.status == http.StatusForbidden ||
		e.code == "E_REPLAY" || e.code == "E_TIMESTAMP_OUT_OF_RANGE" || e.code == "E_AUTH_MALFORMED"
}

// peerError decodes a non-200 response into its error classification.
func peerError(status int, body []byte) *federationHTTPError {
	result := &federationHTTPError{status: status}
	var decoded any
	if encoding.Decode(body, &decoded) == nil {
		if fields, err := asUintMap(decoded); err == nil {
			if code, ok := fields[0].(string); ok {
				result.code = code
			}
			if retryable, ok := fields[3].(bool); ok {
				result.retryable = retryable
			}
		}
	}
	if result.code == "" {
		result.code = http.StatusText(status)
	}
	if status >= 500 {
		result.retryable = true
	}
	return result
}
