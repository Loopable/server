// Package server exposes the Loopable federation HTTP API of 60-federation.md.
//
// Routing, authentication (61), replay protection (61.7), rate limiting
// (82.4), body limits (82.1), and the protocol endpoints of 60.3 are
// implemented here. The data layer is injected through interfaces so the
// server runs against PostgreSQL (internal/store) or an in-memory repository
// in tests.
package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"loopable.party/server/internal/objectstore"
	"loopable.party/server/internal/protocol/encoding"
	"loopable.party/server/internal/protocol/federation"
	"loopable.party/server/internal/protocol/instance"
)

const (
	defaultBodyLimit       = 8 << 20
	defaultMediaChunkLimit = 64 << 20
	defaultPageSize        = 512
	defaultObjectBudget    = 8 << 20
	mediaPlaintextLimit    = 2 << 30
	maxEventFetch          = 512
	maxEventsPerPost       = 512
	maxObjectsPerPost      = 512
	accountLookupDeviceMax = 16
)

// Config wires the server to its repositories and protocol services.
type Config struct {
	// Domain is the receiving instance's canonical hostname per 13.4 and 61.4.
	Domain string
	// Document is this instance's signed document served at GET /v1/instance.
	Document *instance.Document
	// Moderators are additional staff account IDs served at GET /v1/instance/roles
	// (13.10.4). The document administrator is always served as administrator.
	Moderators [][]byte
	// Events is the event repository.
	Events EventRepository
	// Objects is the object-envelope registry.
	Objects ObjectRepository
	// Blobs is the object store backend (blob + resumable upload storage).
	Blobs objectstore.Store
	// Devices resolves client account device signing keys for 61.9.
	Devices DeviceResolver
	// Membership resolves group membership for member-scope acceptance.
	Membership MembershipResolver
	// Peers resolves peer instance documents for 61.5.
	Peers InstanceResolver
	// Replay is the request replay cache; created when nil.
	Replay *federation.ReplayCache
	// BodyLimit bounds request bodies (default 8 MiB). Media upload chunks
	// are bounded by MediaChunkLimit instead.
	BodyLimit int64
	// MediaChunkLimit bounds one media upload chunk read for verification
	// (default 64 MiB).
	MediaChunkLimit int64
	// PageSize is the sync page size (default 512).
	PageSize int
	// ObjectBudget bounds the objects carried in one sync page (default 8 MiB).
	ObjectBudget int64
	// MediaPlaintextLimit is the largest upload length accepted (default 2 GiB).
	MediaPlaintextLimit int64
	// RateLimits maps rate groups to requests per second; empty disables
	// per-group limiting.
	RateLimits map[string]float64
	// Now overrides the clock for tests.
	Now func() time.Time
}

// Server is the Loopable federation HTTP server.
type Server struct {
	cfg     Config
	replay  *federation.ReplayCache
	limiter *rateLimiter
}

// New validates the configuration and assembles the server.
func New(cfg Config) (*Server, error) {
	if cfg.Domain == "" {
		return nil, errors.New("server domain is required")
	}
	canonical, err := instance.CanonicalHostname(cfg.Domain)
	if err != nil {
		return nil, err
	}
	cfg.Domain = canonical
	if cfg.Document == nil {
		return nil, errors.New("instance document is required")
	}
	if cfg.Events == nil {
		return nil, errors.New("event repository is required")
	}
	if cfg.Objects == nil {
		return nil, errors.New("object repository is required")
	}
	if cfg.Blobs == nil {
		return nil, errors.New("object store is required")
	}
	if cfg.Devices == nil {
		return nil, errors.New("device resolver is required")
	}
	if cfg.Membership == nil {
		return nil, errors.New("membership resolver is required")
	}
	if cfg.Peers == nil {
		return nil, errors.New("instance resolver is required")
	}
	if cfg.BodyLimit <= 0 {
		cfg.BodyLimit = defaultBodyLimit
	}
	if cfg.MediaChunkLimit <= 0 {
		cfg.MediaChunkLimit = defaultMediaChunkLimit
	}
	if cfg.PageSize <= 0 {
		cfg.PageSize = defaultPageSize
	}
	if cfg.ObjectBudget <= 0 {
		cfg.ObjectBudget = defaultObjectBudget
	}
	if cfg.MediaPlaintextLimit <= 0 {
		cfg.MediaPlaintextLimit = mediaPlaintextLimit
	}
	if cfg.Replay == nil {
		cfg.Replay = federation.NewReplayCache()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Server{cfg: cfg, replay: cfg.Replay, limiter: newRateLimiter(cfg.RateLimits)}, nil
}

// Handler returns the routed HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	public := func(pattern string, handler http.HandlerFunc) {
		mux.HandleFunc(pattern, s.recover(handler))
	}
	protected := func(pattern string, handler http.HandlerFunc) {
		mux.HandleFunc(pattern, s.recover(s.authenticated(handler)))
	}

	public("GET /v1/instance", s.handleInstance)
	public("GET /v1/instance/roles", s.handleRoles)
	public("GET /v1/capabilities", s.handleCapabilities)
	public("POST /v1/device-join-requests", s.handleDeviceJoinRequests)
	public("GET /healthz", s.handleHealth)

	protected("POST /v1/events", s.handlePostEvents)
	protected("GET /v1/events/{event_id}", s.handleGetEvent)
	protected("POST /v1/events:fetch", s.handleFetchEvents)
	protected("POST /v1/objects", s.handlePostObjects)
	protected("GET /v1/objects/{object_id}", s.handleGetObject)
	protected("POST /v1/sync", s.handleSync)
	protected("GET /v1/accounts/{account_id}", s.handleAccountLookup)
	protected("GET /v1/members/{account_id}", s.handleMemberLookup)
	protected("POST /v1/media/uploads", s.handleMediaCreate)
	protected("PATCH /v1/media/uploads/{upload_id}", s.handleMediaAppend)
	protected("HEAD /v1/media/uploads/{upload_id}", s.handleMediaStatus)

	return mux
}

// recover middleware converts panics into E_INTERNAL responses.
func (s *Server) recover(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				fail(w, "E_INTERNAL", requestContextID(r), nil, errors.New("panic in handler"))
			}
		}()
		next(w, r)
	}
}

type requestKey struct{}

type requestContext struct {
	body   []byte
	bodyOK bool
	auth   *authContext
}

func withBody(ctx context.Context, body []byte) context.Context {
	rctx, _ := ctx.Value(requestKey{}).(*requestContext)
	if rctx == nil {
		rctx = &requestContext{}
	}
	rctx.body = body
	rctx.bodyOK = true
	return context.WithValue(ctx, requestKey{}, rctx)
}

func withAuth(ctx context.Context, auth *authContext) context.Context {
	rctx, _ := ctx.Value(requestKey{}).(*requestContext)
	if rctx == nil {
		rctx = &requestContext{}
	}
	rctx.auth = auth
	return context.WithValue(ctx, requestKey{}, rctx)
}

func requestBody(r *http.Request) []byte {
	if rctx, ok := r.Context().Value(requestKey{}).(*requestContext); ok {
		return rctx.body
	}
	return nil
}

func requestAuth(r *http.Request) *authContext {
	if rctx, ok := r.Context().Value(requestKey{}).(*requestContext); ok {
		return rctx.auth
	}
	return nil
}

func requestContextID(r *http.Request) []byte {
	if auth := requestAuth(r); auth != nil {
		return auth.RequestID
	}
	return nil
}

// authenticated verifies the Authorization header per 61.3 through 61.9.
func (s *Server) authenticated(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := s.readBody(r)
		if err != nil {
			writeError(w, err, nil)
			return
		}
		r = r.WithContext(withBody(r.Context(), body))

		auth, err := s.verify(r, body)
		if err != nil {
			writeError(w, err, nil)
			return
		}
		r = r.WithContext(withAuth(r.Context(), auth))
		next(w, r)
	}
}

// readBody buffers a request body under the appropriate limit to compute its
// hash for signature verification.
func (s *Server) readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil || r.Method == http.MethodGet || r.Method == http.MethodHead {
		return nil, nil
	}
	limit := s.cfg.BodyLimit
	if r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/v1/media/") {
		limit = s.cfg.MediaChunkLimit
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, asInvalidRequest(errors.New("request body exceeds the limit"))
	}
	return body, nil
}

// decodeRequest decodes a CBOR request body, marking failures as malformed
// encodings.
func (s *Server) decodeRequest(data []byte, value any) error {
	if err := encoding.Decode(data, value); err != nil {
		return malformedEncoding{err: err}
	}
	return nil
}

// requireAccountAuth enforces a request authenticated by an account device
// (61.9), as required by the account-scoped endpoints.
func (s *Server) requireAccountAuth(r *http.Request) (*authContext, error) {
	auth := requestAuth(r)
	if auth == nil || !auth.Presented || len(auth.Account) == 0 {
		return nil, asInvalidRequest(errors.New("account authentication required"))
	}
	return auth, nil
}

// instanceDocument returns this server's instance document.
func (s *Server) instanceDocument() *instance.Document {
	return s.cfg.Document
}
