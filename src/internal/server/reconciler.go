package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"loopable.party/server/internal/protocol/authorization"
	"loopable.party/server/internal/protocol/dag"
	"loopable.party/server/internal/protocol/encoding"
	"loopable.party/server/internal/protocol/events"
	"loopable.party/server/internal/protocol/identifiers"
	"loopable.party/server/internal/protocol/instance"
	"loopable.party/server/internal/protocol/objects"
	"loopable.party/server/internal/protocol/sync"
	storepkg "loopable.party/server/internal/store"
)

const (
	// defaultSyncInterval is how often the reconciler polls each peer (62.2
	// has no mandated cadence; operators tune this per relationship).
	defaultSyncInterval = 30 * time.Second
	// maxDependencyRounds bounds how many fetch-and-retry passes the DAG
	// resolver is allowed before a page is abandoned.
	maxDependencyRounds = 64
)

// PeerRepository is the outbound-side per-peer state store (62.8). Store
// implements it on PostgreSQL; tests may substitute an in-memory variant.
type PeerRepository interface {
	// GetPeer returns the stored state, or a "peer unknown" error when the
	// relationship has no state yet.
	GetPeer(ctx context.Context, peerID []byte) (sync.PeerState, error)
	// UpsertPeer records the relationship state after a successful sync.
	UpsertPeer(ctx context.Context, state sync.PeerState) error
	// PeerDocuments returns every recorded peer's verified instance document.
	PeerDocuments(ctx context.Context) ([]*instance.Document, error)
	// PutPeerDocument stores a verified peer instance document (61.2).
	PutPeerDocument(ctx context.Context, peerID []byte, document *instance.Document) error
}

// ReconcilerOptions configures the outbound federation reconciler.
type ReconcilerOptions struct {
	// SigningKey is this instance's operational private key. It must match an
	// operational key listed in the served instance document (61.1).
	SigningKey ed25519.PrivateKey
	// Peers is the persistent per-peer state store.
	Peers PeerRepository
	// Interval is the polling cadence (default 30s).
	Interval time.Duration
	// Interest restricts which event and object types are pulled (62.3). Nil
	// means the full permitted stream.
	Interest *sync.Interest
	// Scheme and Port build the peer base URL; scheme defaults to https (13.8).
	// Port defaults to the scheme's default when empty.
	Scheme string
	// Port is an optional non-default federation port.
	Port string
	// HTTPClient customizes the outbound client. A hardened default is used
	// when nil.
	HTTPClient *http.Client
	// Log is the reconciler logger; log.Default is used when nil.
	Log *log.Logger
}

// Reconciler pulls each peer's event and object stream into this instance
// (62.2), ingesting through the same acceptance paths as inbound traffic.
type Reconciler struct {
	server   *Server
	peers    PeerRepository
	signer   federationSigner
	client   *federationTransport
	interval time.Duration
	interest *sync.Interest
	log      *log.Logger
}

// NewReconciler assembles the reconciler, verifying the signing key against
// this instance's document.
func NewReconciler(server *Server, opts ReconcilerOptions) (*Reconciler, error) {
	if server == nil {
		return nil, errors.New("reconciler requires a server")
	}
	if opts.Peers == nil {
		return nil, errors.New("reconciler requires a peer repository")
	}
	if len(opts.SigningKey) != ed25519.PrivateKeySize {
		return nil, errors.New("reconciler requires an operational signing key")
	}
	signer, err := newFederationSigner(server.cfg.Document, opts.SigningKey)
	if err != nil {
		return nil, err
	}
	if opts.Interval <= 0 {
		opts.Interval = defaultSyncInterval
	}
	if opts.Log == nil {
		opts.Log = log.Default()
	}
	return &Reconciler{
		server:   server,
		peers:    opts.Peers,
		signer:   signer,
		client:   newFederationTransport(signer, opts.Scheme, opts.Port, opts.HTTPClient),
		interval: opts.Interval,
		interest: opts.Interest,
		log:      opts.Log,
	}, nil
}

// RestorePeers registers every persisted peer document in the server's
// instance resolver so inbound requests from those peers verify (61.5). It is
// safe to call once at startup.
func (r *Reconciler) RestorePeers(ctx context.Context) error {
	documents, err := r.peers.PeerDocuments(ctx)
	if err != nil {
		return err
	}
	registry, ok := r.server.cfg.Peers.(*PeerRegistry)
	if !ok {
		return nil
	}
	for _, document := range documents {
		if err := registry.Register(document); err != nil {
			return err
		}
	}
	return nil
}

// Run synchronizes with every peer until ctx is cancelled. A sync happens
// immediately, then at each interval.
func (r *Reconciler) Run(ctx context.Context) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	r.syncAll(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.syncAll(ctx)
		}
	}
}

// syncAll performs one pull pass over every known peer. Failures are logged
// per peer; a peer that errors this pass resumes from its stored cursor next
// pass (62.4).
func (r *Reconciler) syncAll(ctx context.Context) {
	documents, err := r.peers.PeerDocuments(ctx)
	if err != nil {
		r.log.Printf("federation: list peers: %v", err)
		return
	}
	for _, document := range documents {
		if err := r.syncPeer(ctx, document); err != nil {
			r.log.Printf("federation: peer %s sync failed: %v", peerText(document.InstanceID), err)
		}
	}
}

// syncPeer performs the sync of 62.2 against one peer: refresh its document
// when stale (61.2), page through its stream, apply each page, and persist the
// final cursor when the stream finishes cleanly. The cursor is only advanced
// after every page before it was fully applied (62.4, 63.3).
func (r *Reconciler) syncPeer(ctx context.Context, document *instance.Document) error {
	if !r.signer.currentlyValid(r.server.cfg.Document, time.Now()) {
		return errors.New("this instance has no currently valid operational key")
	}

	if r.documentStale(document, time.Now()) {
		refreshed, err := r.refreshPeerDocument(ctx, document)
		if err != nil {
			return err
		}
		document = refreshed
		if err := r.register(document); err != nil {
			return err
		}
	}

	cursor, err := restoredCursor(r.peers, ctx, document.InstanceID)
	if err != nil {
		return err
	}

	refreshed := false
	for rounds := 0; ; rounds++ {
		if rounds > maxDependencyRounds {
			return errors.New("peer stream exceeded the page limit")
		}
		page, err := r.fetchPage(ctx, document, cursor)
		if err != nil {
			var authErr *federationHTTPError
			if errors.As(err, &authErr) && authErr.isAuthError() && !refreshed {
				// 62.7 step 4: re-fetch the document and retry once.
				document, err = r.refreshPeerDocument(ctx, document)
				if err != nil {
					return err
				}
				if err := r.register(document); err != nil {
					return err
				}
				refreshed = true
				continue
			}
			return err
		}
		if page.More && (len(page.Events) == 0 || bytes.Equal(page.Cursor, cursor)) {
			return errors.New("peer page did not advance the cursor")
		}
		if err := r.applyPage(ctx, document, page); err != nil {
			return err
		}
		cursor = page.Cursor
		if !page.More {
			break
		}
	}

	state := sync.PeerState{
		PeerInstanceID:     append([]byte(nil), document.InstanceID...),
		Cursor:             append([]byte(nil), cursor...),
		ProtocolVersion:    document.ProtocolVersion,
		Capabilities:       r.fetchCapabilities(ctx, document),
		LastSuccessfulSync: time.Now(),
	}
	return r.peers.UpsertPeer(ctx, state)
}

// restoredCursor returns the recorded cursor for a peer, or nil when the
// relationship is new.
func restoredCursor(repo PeerRepository, ctx context.Context, peerID []byte) ([]byte, error) {
	state, err := repo.GetPeer(ctx, peerID)
	if err != nil {
		if errors.Is(err, storepkg.ErrUnknownPeer) || errors.Is(err, sync.ErrUnknownPeer) {
			return nil, nil
		}
		return nil, err
	}
	return state.Cursor, nil
}

// fetchPage issues one sync request and decodes the response page.
func (r *Reconciler) fetchPage(ctx context.Context, document *instance.Document, cursor []byte) (sync.Page, error) {
	request := sync.Request{Cursor: cursor, Interest: r.interest}
	body, err := request.Encode()
	if err != nil {
		return sync.Page{}, err
	}
	response, err := r.client.call(ctx, http.MethodPost, document.Domain, "/v1/sync", "", body)
	if err != nil {
		return sync.Page{}, err
	}
	page, err := sync.ParsePage(response)
	if err != nil {
		return sync.Page{}, fmt.Errorf("peer %s sent an invalid sync page: %w", document.Domain, err)
	}
	return page, nil
}

// applyPage ingests the objects and events of one page. Objects go first so
// that event object references resolve during validation. Events are ingested
// oldest-first; a page event whose predecessors are absent resolves through
// /v1/events:fetch (60.6, 63.3) until the page is complete.
func (r *Reconciler) applyPage(ctx context.Context, document *instance.Document, page sync.Page) error {
	for _, object := range page.Objects {
		if err := r.ingestObject(ctx, object); err != nil {
			return err
		}
	}

	queue := make([]events.Event, 0, len(page.Events))
	queue = append(queue, page.Events...)
	for rounds := 0; len(queue) > 0; rounds++ {
		if rounds > maxDependencyRounds {
			return fmt.Errorf("peer %s: event dependencies did not resolve", document.Domain)
		}
		event := queue[0]
		queue = queue[1:]

		switch err := r.ingestEvent(ctx, event); {
		case err == nil:
		case isRefusedEvent(err):
			r.log.Printf("federation: peer %s event %x refused: %v", document.Domain, event.EventID, err)
		default:
			var missing missingDependency
			if !errors.As(err, &missing) {
				return err
			}
			fetched, fetchErr := r.fetchEvents(ctx, document, missing.ids)
			if fetchErr != nil {
				return fetchErr
			}
			if !coversFetched(missing.ids, fetched) {
				return fmt.Errorf("peer %s did not satisfy all missing dependencies", document.Domain)
			}
			queue = append(queue, fetched...)
			queue = append(queue, event)
		}
	}
	return nil
}

// ingestEvent stores one synchronized event through the standard acceptance
// path. An identical duplicate is a no-op (62.6).
func (r *Reconciler) ingestEvent(ctx context.Context, event events.Event) error {
	_, err := r.server.submitEvent(ctx, event)
	if err != nil && !errors.Is(err, ErrEventCollision) {
		return err
	}
	return nil
}

// ingestObject stores one synchronized object envelope through the relay path,
// so large blobs land in the object store backend. Existing objects are
// skipped (62.6).
func (r *Reconciler) ingestObject(ctx context.Context, object objects.Object) error {
	_, err := r.server.storeEnvelope(ctx, object)
	return err
}

// fetchEvents pulls a batch of events (including their dependency closure) by
// ID from the peer (60.6, 63.3).
func (r *Reconciler) fetchEvents(ctx context.Context, document *instance.Document, ids [][]byte) ([]events.Event, error) {
	rawIDs := make([]any, len(ids))
	for i, id := range ids {
		rawIDs[i] = append([]byte(nil), id...)
	}
	body, err := encoding.Encode(map[uint64]any{0: rawIDs})
	if err != nil {
		return nil, err
	}
	response, err := r.client.call(ctx, http.MethodPost, document.Domain, "/v1/events:fetch", "", body)
	if err != nil {
		return nil, err
	}

	var decoded any
	if err := encoding.Decode(response, &decoded); err != nil {
		return nil, err
	}
	items, ok := decoded.([]any)
	if !ok {
		return nil, errors.New("peer events:fetch response is not an array")
	}

	eventsOut := make([]events.Event, 0, len(items))
	for i, item := range items {
		fields, err := asUintMap(item)
		if err != nil {
			return nil, fmt.Errorf("peer events:fetch record %d: %w", i, err)
		}
		// A record that reports an error was not supplied by the peer.
		if _, hasError := fields[2]; hasError {
			continue
		}
		wire, ok := fields[1].([]byte)
		if !ok {
			return nil, fmt.Errorf("peer events:fetch record %d has no event bytes", i)
		}
		var eventValue any
		if err := encoding.Decode(wire, &eventValue); err != nil {
			return nil, fmt.Errorf("peer events:fetch record %d has an invalid event encoding: %w", i, err)
		}
		event, err := events.Parse(eventValue)
		if err != nil {
			return nil, fmt.Errorf("peer events:fetch record %d has an invalid event: %w", i, err)
		}
		eventsOut = append(eventsOut, event)
	}
	return eventsOut, nil
}

// fetchCapabilities pulls the peer's advertised capabilities (62.8) and
// returns their names, or nil when the peer's list cannot be read.
func (r *Reconciler) fetchCapabilities(ctx context.Context, document *instance.Document) []string {
	response, err := r.client.call(ctx, http.MethodGet, document.Domain, "/v1/capabilities", "", nil)
	if err != nil {
		return nil
	}
	var decoded any
	if err := encoding.Decode(response, &decoded); err != nil {
		return nil
	}
	items, ok := decoded.([]any)
	if !ok {
		return nil
	}
	names := make([]string, 0, len(items))
	for _, item := range items {
		fields, err := asUintMap(item)
		if err != nil {
			continue
		}
		if name, ok := fields[0].(string); ok {
			names = append(names, name)
		}
	}
	return names
}

// refreshPeerDocument re-fetches a peer's signed instance document (61.2) and
// validates its identity before persisting and registering it.
func (r *Reconciler) refreshPeerDocument(ctx context.Context, stale *instance.Document) (*instance.Document, error) {
	response, err := r.client.call(ctx, http.MethodGet, stale.Domain, "/v1/instance", "", nil)
	if err != nil {
		return nil, fmt.Errorf("fetch %s instance document: %w", stale.Domain, err)
	}
	var decoded any
	if err := encoding.Decode(response, &decoded); err != nil {
		return nil, err
	}
	document, err := instance.Parse(decoded)
	if err != nil {
		return nil, fmt.Errorf("peer %s sent an invalid instance document: %w", stale.Domain, err)
	}
	if !bytes.Equal(document.InstanceID, stale.InstanceID) {
		return nil, errors.New("peer instance document identity changed")
	}
	if err := r.peers.PutPeerDocument(ctx, document.InstanceID, &document); err != nil {
		return nil, err
	}
	return &document, nil
}

// documentStale reports whether a cached peer document has outlived every
// listed operational key, per 61.2.
func (r *Reconciler) documentStale(document *instance.Document, now time.Time) bool {
	var latest uint64
	for _, key := range document.OperationalKeys {
		if key.NotAfter > latest {
			latest = key.NotAfter
		}
	}
	return uint64(now.Unix()) > latest
}

// register makes a refreshed document known to the inbound instance resolver.
func (r *Reconciler) register(document *instance.Document) error {
	registry, ok := r.server.cfg.Peers.(*PeerRegistry)
	if !ok {
		return nil
	}
	return registry.Register(document)
}

// isRefusedEvent reports whether an ingest error is a permanent refusal that
// must not stop the cursor (62.6). Everything else is transient and aborts the
// page so no synchronization point is silently lost.
func isRefusedEvent(err error) bool {
	switch {
	case errors.Is(err, ErrEventIDCollision):
		return true
	case errors.Is(err, authorization.ErrUnauthorizedDevice),
		errors.Is(err, authorization.ErrFirstDeviceInvalid),
		errors.Is(err, authorization.ErrTrustConflict),
		errors.Is(err, authorization.ErrSignatureInvalid),
		errors.Is(err, authorization.ErrMemberRequired),
		errors.Is(err, authorization.ErrSchemaInvalid):
		return true
	case errors.Is(err, dag.ErrCycle),
		errors.Is(err, dag.ErrUnrooted),
		errors.Is(err, dag.ErrMissing),
		errors.Is(err, dag.ErrAccount):
		return true
	default:
		return false
	}
}

// coversFetched reports whether every requested ID was supplied by the peer.
func coversFetched(requested [][]byte, fetched []events.Event) bool {
	for _, id := range requested {
		found := false
		for _, event := range fetched {
			if bytes.Equal(event.EventID, id) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// peerText renders a peer instance ID for logs.
func peerText(instanceID []byte) string {
	text, err := identifiers.String(identifiers.InstanceID, instanceID)
	if err != nil {
		return fmt.Sprintf("%x", instanceID)
	}
	return text
}
