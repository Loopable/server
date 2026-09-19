package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"loopable.party/server/internal/objectstore"
	"loopable.party/server/internal/protocol/accounts"
	"loopable.party/server/internal/protocol/encoding"
	"loopable.party/server/internal/protocol/events"
	"loopable.party/server/internal/protocol/federation"
	"loopable.party/server/internal/protocol/identifiers"
	"loopable.party/server/internal/protocol/instance"
	"loopable.party/server/internal/protocol/objects"
	"loopable.party/server/internal/protocol/signatures"
	"loopable.party/server/internal/protocol/x25519"
)

// keyIDOf derives the protocol key ID of a public key (sum 61.9).
func keyIDOf(publicKey ed25519.PublicKey) []byte {
	sum := sha256.Sum256(publicKey)
	return sum[:16]
}

const testDomain = "home.example"

var testNow = time.Unix(1_000_000, 0)

type testEnv struct {
	server   *Server
	store    *InMemoryStorage
	blobs    objectstore.Store
	document *instance.Document
	opKeyID  []byte
	opPriv   ed25519.PrivateKey
	account  *accountFixture
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	rootPub, rootPriv, err := signatures.Generate()
	if err != nil {
		t.Fatal(err)
	}
	opPub, opPriv, err := signatures.Generate()
	if err != nil {
		t.Fatal(err)
	}
	opKey, err := instance.NewOperationalKey(opPub, uint64(testNow.Unix())-100, uint64(testNow.Unix())+100)
	if err != nil {
		t.Fatal(err)
	}
	administrator := bytes.Repeat([]byte{0xaa}, identifiers.LongLength)
	document, err := instance.NewDocument(rootPub, []instance.OperationalKey{opKey}, testDomain, administrator)
	if err != nil {
		t.Fatal(err)
	}
	if err := document.Sign(rootPriv); err != nil {
		t.Fatal(err)
	}
	if err := document.Verify(); err != nil {
		t.Fatal(err)
	}

	store := NewInMemoryStorage()
	peers := NewPeerRegistry()
	if err := peers.Register(&document); err != nil {
		t.Fatal(err)
	}
	blobsDir := t.TempDir()
	blobs, err := objectstore.NewLocal(blobsDir)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{
		Domain:     testDomain,
		Document:   &document,
		Events:     store,
		Objects:    store,
		Blobs:      blobs,
		Devices:    store,
		Membership: store,
		Peers:      peers,
		Now:        func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	env := &testEnv{server: srv, store: store, blobs: blobs, document: &document, opKeyID: opKey.KeyID, opPriv: opPriv}
	env.account = newAccountFixture(t)
	for _, item := range []events.Event{parseFromWire(t, env.account.genesis)} {
		if _, err := store.PutEvent(context.Background(), item); err != nil {
			t.Fatalf("seed event: %v", err)
		}
	}
	return env
}

// parseFromWire re-parses an event through its encoded wire form so stored
// bodies carry plain []byte values, matching how the PostgreSQL store returns
// events after a wire round trip.
func parseFromWire(t *testing.T, event events.Event) events.Event {
	t.Helper()
	body, err := encoding.Encode(event.Wire())
	if err != nil {
		t.Fatal(err)
	}
	var decoded any
	if err := encoding.Decode(body, &decoded); err != nil {
		t.Fatal(err)
	}
	parsed, err := events.Parse(decoded)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func (e *testEnv) accountAuth(t *testing.T, method, path string, query string, body []byte) string {
	t.Helper()
	return e.authHeader(t, e.account.accountID, keyIDOf(e.account.first.signing), e.account.first.private, method, path, query, body, e.account.homeInstance)
}

func (e *testEnv) instanceAuth(t *testing.T, method, path string, query string, body []byte) string {
	t.Helper()
	return e.authHeader(t, nil, e.opKeyID, e.opPriv, method, path, query, body, e.document.InstanceID)
}

// authHeader signs a request like the federation client and returns the header.
func (e *testEnv) authHeader(t *testing.T, accountID, keyID []byte, private ed25519.PrivateKey, method, path, query string, body []byte, instanceID []byte) string {
	t.Helper()
	requestID, err := identifiers.Random(identifiers.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	canonicalPath, err := federation.CanonicalPath(path)
	if err != nil {
		t.Fatal(err)
	}
	canonicalQuery, err := federation.CanonicalQuery(query)
	if err != nil {
		t.Fatal(err)
	}
	request := federation.RequestAuthentication{
		Method:    method,
		Host:      testDomain,
		Path:      canonicalPath,
		Query:     canonicalQuery,
		RequestID: requestID,
		Timestamp: uint64(testNow.Unix()),
		BodyHash:  federation.HashBody(body),
		AccountID: accountID,
	}
	signature, err := federation.SignRequest(private, request)
	if err != nil {
		t.Fatal(err)
	}
	authorization := federation.Authorization{
		InstanceID: instanceID,
		KeyID:      keyID,
		RequestID:  requestID,
		Timestamp:  uint64(testNow.Unix()),
		AccountID:  accountID,
		Signature:  signature,
	}
	header, err := authorization.HeaderValue()
	if err != nil {
		t.Fatal(err)
	}
	return header
}

func do(t *testing.T, s *Server, method, path, query string, body []byte, header string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	target := path
	if query != "" {
		target += "?" + query
	}
	request := httptest.NewRequest(method, "https://"+testDomain+target, bytes.NewReader(body))
	request.Header.Set("Host", testDomain)
	if header != "" {
		request.Header.Set("Authorization", header)
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	recorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, request)
	return recorder
}

func decodeBody(t *testing.T, body []byte, value any) {
	t.Helper()
	if err := encoding.Decode(body, value); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

func asUintMapAny(t *testing.T, value any) map[uint64]any {
	t.Helper()
	fields, err := asUintMap(value)
	if err != nil {
		t.Fatalf("expected map: %v", err)
	}
	return fields
}

func expectStatus(t *testing.T, recorder *httptest.ResponseRecorder, want int) {
	t.Helper()
	if recorder.Code != want {
		t.Fatalf("status %d, want %d: %s", recorder.Code, want, recorder.Body.String())
	}
}

func TestCapabilitiesAndRoles(t *testing.T) {
	env := newTestEnv(t)
	capabilities := do(t, env.server, http.MethodGet, "/v1/capabilities", "", nil, "", nil)
	expectStatus(t, capabilities, http.StatusOK)
	var list []any
	decodeBody(t, capabilities.Body.Bytes(), &list)
	if len(list) == 0 {
		t.Fatal("capabilities list is empty")
	}

	roles := do(t, env.server, http.MethodGet, "/v1/instance/roles", "", nil, "", nil)
	expectStatus(t, roles, http.StatusOK)
	var rolesValue map[uint64]any
	decodeBody(t, roles.Body.Bytes(), &rolesValue)
	if !bytes.Equal(rolesValue[0].([]byte), env.document.Administrator) {
		t.Fatal("roles do not report the document administrator")
	}
}

func TestPublicInstanceRequest(t *testing.T) {
	env := newTestEnv(t)
	recorder := do(t, env.server, http.MethodGet, "/v1/instance", "", nil, "", nil)
	expectStatus(t, recorder, http.StatusOK)
	var decoded any
	decodeBody(t, recorder.Body.Bytes(), &decoded)
	if _, err := instance.Parse(decoded); err != nil {
		t.Fatalf("served document does not parse: %v", err)
	}
}

func TestEventSubmissionDuplicateAndCollision(t *testing.T) {
	env := newTestEnv(t)
	// The submission account is not seeded: its genesis is genuinely new here,
	// so the same request exercises status 0 (accepted), 1 (duplicate), and 2
	// (E_EVENT_ID_COLLISION when the id is reused with different bytes).
	fresh := newAccountFixture(t)
	fresh.genesis.EventID = bytes.Repeat([]byte{0x0d}, identifiers.ShortLength)
	if err := fresh.genesis.Sign(fresh.identityPriv); err != nil {
		t.Fatal(err)
	}
	path := "/v1/events"
	// A genesis is the account's first event, so it cannot yet be
	// authenticated with account credentials: provisioning is done with
	// instance auth (61.4).
	submit := func() (map[uint64]any, *httptest.ResponseRecorder) {
		wire := []any{fresh.genesis.Wire()}
		body, err := encoding.Encode(wire)
		if err != nil {
			t.Fatal(err)
		}
		header := env.instanceAuth(t, http.MethodPost, path, "", body)
		recorder := do(t, env.server, http.MethodPost, path, "", body, header, nil)
		expectStatus(t, recorder, http.StatusOK)
		var results []any
		decodeBody(t, recorder.Body.Bytes(), &results)
		return asUintMapAny(t, results[0]), recorder
	}

	result, _ := submit()
	if result[1].(uint64) != 0 {
		t.Fatalf("first submission status %d, want 0", result[1])
	}
	result, _ = submit()
	if result[1].(uint64) != 1 {
		t.Fatalf("duplicate submission status %d, want 1", result[1])
	}

	bumped := fresh.genesis
	bumped.CreatedAt = 999
	if err := bumped.Sign(fresh.identityPriv); err != nil {
		t.Fatal(err)
	}
	wire := []any{bumped.Wire()}
	body, err := encoding.Encode(wire)
	if err != nil {
		t.Fatal(err)
	}
	header := env.instanceAuth(t, http.MethodPost, path, "", body)
	recorder := do(t, env.server, http.MethodPost, path, "", body, header, nil)
	var results []any
	decodeBody(t, recorder.Body.Bytes(), &results)
	result = asUintMapAny(t, results[0])
	if result[1].(uint64) != 2 {
		t.Fatalf("collision status %d, want 2", result[1])
	}
	errorValue := asUintMapAny(t, result[2])
	if errorValue[0] != "E_EVENT_ID_COLLISION" {
		t.Fatalf("collision error code %#v, want E_EVENT_ID_COLLISION", errorValue[0])
	}
}

func TestEventSubmissionRequiresAuthentication(t *testing.T) {
	env := newTestEnv(t)
	wire := []any{env.account.genesis.Wire()}
	body, err := encoding.Encode(wire)
	if err != nil {
		t.Fatal(err)
	}
	recorder := do(t, env.server, http.MethodPost, "/v1/events", "", body, "", nil)
	expectStatus(t, recorder, http.StatusUnauthorized)
}

func TestGetAndFetchEvents(t *testing.T) {
	env := newTestEnv(t)
	post := accountPostEvent(t, env.account, env.account.genesis.EventID, 0xd3, 3, env.account.first.private)
	body, err := encoding.Encode([]any{post.Wire()})
	if err != nil {
		t.Fatal(err)
	}
	header := env.accountAuth(t, http.MethodPost, "/v1/events", "", body)
	recorder := do(t, env.server, http.MethodPost, "/v1/events", "", body, header, nil)
	expectStatus(t, recorder, http.StatusOK)
	var postResults []any
	decodeBody(t, recorder.Body.Bytes(), &postResults)
	postResult := asUintMapAny(t, postResults[0])
	if postResult[1].(uint64) != 0 {
		t.Fatalf("post submission status %d, want 0: %#v", postResult[1], postResult)
	}

	idText, err := identifiers.String(identifiers.EventID, post.EventID)
	if err != nil {
		t.Fatal(err)
	}
	header = env.accountAuth(t, http.MethodGet, "/v1/events/"+idText, "", nil)
	recorder = do(t, env.server, http.MethodGet, "/v1/events/"+idText, "", nil, header, nil)
	expectStatus(t, recorder, http.StatusOK)
	var served any
	decodeBody(t, recorder.Body.Bytes(), &served)
	parsed, err := events.Parse(served)
	if err != nil {
		t.Fatalf("served event does not parse: %v", err)
	}
	if !bytes.Equal(parsed.EventID, post.EventID) {
		t.Fatal("served event ID mismatch")
	}

	missingID := bytes.Repeat([]byte{0x5c}, identifiers.ShortLength)
	batch, err := encoding.Encode(map[uint64]any{0: []any{post.EventID, missingID}})
	if err != nil {
		t.Fatal(err)
	}
	header = env.accountAuth(t, http.MethodPost, "/v1/events:fetch", "", batch)
	recorder = do(t, env.server, http.MethodPost, "/v1/events:fetch", "", batch, header, nil)
	expectStatus(t, recorder, http.StatusOK)
	var records []any
	decodeBody(t, recorder.Body.Bytes(), &records)
	var foundPost, foundGenesis bool
	for _, raw := range records {
		record := asUintMapAny(t, raw)
		recordID := record[0].([]byte)
		switch {
		case bytes.Equal(recordID, post.EventID):
			if _, ok := record[1]; !ok {
				t.Fatal("post fetch record has no event bytes")
			}
			foundPost = true
		case bytes.Equal(recordID, env.account.genesis.EventID):
			foundGenesis = true
		case len(recordID) == identifiers.ShortLength && record[2] != nil:
			errorValue := asUintMapAny(t, record[2])
			if errorValue[0] != "E_NOT_FOUND" {
				t.Fatalf("missing event error code %#v, want E_NOT_FOUND", errorValue[0])
			}
		}
	}
	if !foundPost || !foundGenesis {
		t.Fatalf("fetch returned post=%v genesis=%v", foundPost, foundGenesis)
	}
}

func TestAccountLookup(t *testing.T) {
	env := newTestEnv(t)
	accountText, err := identifiers.String(identifiers.AccountID, env.account.accountID)
	if err != nil {
		t.Fatal(err)
	}
	header := env.accountAuth(t, http.MethodGet, "/v1/accounts/"+accountText, "", nil)
	recorder := do(t, env.server, http.MethodGet, "/v1/accounts/"+accountText, "", nil, header, nil)
	expectStatus(t, recorder, http.StatusOK)
	var fields map[uint64]any
	decodeBody(t, recorder.Body.Bytes(), &fields)
	if !bytes.Equal(fields[0].([]byte), env.account.accountID) {
		t.Fatal("account lookup returned the wrong account ID")
	}
	if fields[2].(string) != env.account.handle {
		t.Fatalf("account lookup handle %q, want %q", fields[2], env.account.handle)
	}
	summaries, ok := fields[4].([]any)
	if !ok || len(summaries) == 0 {
		t.Fatalf("account lookup device summaries missing: %#v", fields[4])
	}
	summary := asUintMapAny(t, summaries[0])
	if trusted, ok := summary[1].(bool); !ok || !trusted {
		t.Fatalf("first device trusted flag %#v, want true", summary[1])
	}
}

func TestSyncPage(t *testing.T) {
	env := newTestEnv(t)
	post := accountPostEvent(t, env.account, env.account.genesis.EventID, 0xd4, 3, env.account.first.private)
	body, err := encoding.Encode([]any{post.Wire()})
	if err != nil {
		t.Fatal(err)
	}
	header := env.accountAuth(t, http.MethodPost, "/v1/events", "", body)
	recorder := do(t, env.server, http.MethodPost, "/v1/events", "", body, header, nil)
	expectStatus(t, recorder, http.StatusOK)

	syncBody, err := encoding.Encode(map[uint64]any{})
	if err != nil {
		t.Fatal(err)
	}
	header = env.accountAuth(t, http.MethodPost, "/v1/sync", "", syncBody)
	recorder = do(t, env.server, http.MethodPost, "/v1/sync", "", syncBody, header, nil)
	expectStatus(t, recorder, http.StatusOK)
	var page map[uint64]any
	decodeBody(t, recorder.Body.Bytes(), &page)
	if len(page[1].([]any)) != 2 {
		t.Fatalf("sync page has %d events, want 2", len(page[1].([]any)))
	}
	cursor := page[0].([]byte)
	if len(cursor) != 8 {
		t.Fatalf("cursor is %d bytes, want 8", len(cursor))
	}
	pageValue := asUintMapAny(t, page)
	if more, ok := pageValue[3]; ok && more.(uint64) != 0 {
		t.Fatal("sync page unexpectedly reports more data")
	}
}

func TestMediaUploadAndBind(t *testing.T) {
	env := newTestEnv(t)
	chunk := bytes.Repeat([]byte{0x42}, 4096)

	create := do(t, env.server, http.MethodPost, "/v1/media/uploads", "",
		nil, env.accountAuth(t, http.MethodPost, "/v1/media/uploads", "", nil),
		map[string]string{"Upload-Length": "4096"})
	expectStatus(t, create, http.StatusCreated)
	uploadID := create.Header().Get("Location")
	if uploadID == "" {
		t.Fatal("media create missing Location header")
	}

	for _, attempt := range []struct{ offset string }{{"0"}} {
		appendRecorder := do(t, env.server, http.MethodPatch, uploadID, "", chunk,
			env.accountAuth(t, http.MethodPatch, uploadID, "", chunk),
			map[string]string{"Upload-Offset": attempt.offset, "Content-Type": "application/offset+octet-stream"})
		expectStatus(t, appendRecorder, http.StatusNoContent)
		if got := appendRecorder.Header().Get("Upload-Offset"); got != "4096" {
			t.Fatalf("append offset %q, want 4096", got)
		}
	}

	statusRecorder := do(t, env.server, http.MethodHead, uploadID, "",
		nil, env.accountAuth(t, http.MethodHead, uploadID, "", nil), nil)
	expectStatus(t, statusRecorder, http.StatusOK)
	if got := statusRecorder.Header().Get("Upload-Complete"); got != "1" {
		t.Fatalf("upload complete %q, want 1", got)
	}

	objectID, err := objects.NewObjectID()
	if err != nil {
		t.Fatal(err)
	}
	versionID, err := objects.NewVersionID()
	if err != nil {
		t.Fatal(err)
	}
	wrapped := map[uint64]any{
		0: objects.ProtocolVersion,
		1: objectID,
		2: objects.ObjectTypeMedia,
		3: objects.EncryptionSuiteStreamingMedia,
		4: versionID,
		5: []byte{},
		6: []byte{},
		7: []any{validDeviceRecipient(env.account)},
	}
	uploadToken, err := identifiers.Parse(identifiers.RequestID, strings.TrimPrefix(uploadID, "/v1/media/uploads/"))
	if err != nil {
		t.Fatal(err)
	}
	submission := map[uint64]any{0: wrapped, 1: uploadToken}
	body, err := encoding.Encode([]any{submission})
	if err != nil {
		t.Fatal(err)
	}
	prefix := "/v1/objects"
	header := env.accountAuth(t, http.MethodPost, prefix, "", body)
	objectsRecorder := do(t, env.server, http.MethodPost, prefix, "", body, header, nil)
	expectStatus(t, objectsRecorder, http.StatusOK)
	var results []any
	decodeBody(t, objectsRecorder.Body.Bytes(), &results)
	result := asUintMapAny(t, results[0])
	if result[1].(uint64) != 0 {
		t.Fatalf("object submission status %d, want 0: %#v", result[1], result)
	}

	objectText, err := identifiers.String(identifiers.ObjectID, objectID)
	if err != nil {
		t.Fatal(err)
	}
	header = env.accountAuth(t, http.MethodGet, "/v1/objects/"+objectText, "", nil)
	getRecorder := do(t, env.server, http.MethodGet, "/v1/objects/"+objectText, "", nil, header, nil)
	expectStatus(t, getRecorder, http.StatusOK)
	var envelope map[uint64]any
	decodeBody(t, getRecorder.Body.Bytes(), &envelope)
	if !bytes.Equal(envelope[6].([]byte), chunk) {
		t.Fatal("served media ciphertext does not match the uploaded bytes")
	}

	rangeRecorder := do(t, env.server, http.MethodGet, "/v1/objects/"+objectText, "",
		nil, env.accountAuth(t, http.MethodGet, "/v1/objects/"+objectText, "", nil),
		map[string]string{"Range": "bytes=0-11"})
	expectStatus(t, rangeRecorder, http.StatusPartialContent)
	if !bytes.Equal(rangeRecorder.Body.Bytes(), chunk[:12]) {
		t.Fatal("range response bytes mismatch")
	}
	if got := rangeRecorder.Header().Get("Content-Range"); got != "bytes 0-11/4096" {
		t.Fatalf("Content-Range %q, want bytes 0-11/4096", got)
	}
}

func TestInstanceAuthenticationAndReplay(t *testing.T) {
	env := newTestEnv(t)
	syncBody, err := encoding.Encode(map[uint64]any{})
	if err != nil {
		t.Fatal(err)
	}
	header := env.instanceAuth(t, http.MethodPost, "/v1/sync", "", syncBody)
	recorder := do(t, env.server, http.MethodPost, "/v1/sync", "", syncBody, header, nil)
	expectStatus(t, recorder, http.StatusOK)

	replayed := do(t, env.server, http.MethodPost, "/v1/sync", "", syncBody, header, nil)
	expectStatus(t, replayed, http.StatusUnauthorized)
	var errorValue map[uint64]any
	decodeBody(t, replayed.Body.Bytes(), &errorValue)
	if errorValue[0] != "E_REPLAY" {
		t.Fatalf("replay error code %#v, want E_REPLAY", errorValue[0])
	}
}

func TestUnknownPeerInstanceRejected(t *testing.T) {
	env := newTestEnv(t)
	peers := NewPeerRegistry()
	env.server.cfg.Peers = peers
	syncBody, err := encoding.Encode(map[uint64]any{})
	if err != nil {
		t.Fatal(err)
	}
	header := env.instanceAuth(t, http.MethodPost, "/v1/sync", "", syncBody)
	recorder := do(t, env.server, http.MethodPost, "/v1/sync", "", syncBody, header, nil)
	expectStatus(t, recorder, http.StatusUnauthorized)
}

func TestRateLimit(t *testing.T) {
	env := newTestEnv(t)
	env.server.limiter = newRateLimiter(map[string]float64{"events": 1.0 / 60.0})
	path := "/v1/events"
	body, err := encoding.Encode([]any{env.account.genesis.Wire()})
	if err != nil {
		t.Fatal(err)
	}
	header := env.accountAuth(t, http.MethodPost, path, "", body)
	first := do(t, env.server, http.MethodPost, path, "", body, header, nil)
	expectStatus(t, first, http.StatusOK)
	second := do(t, env.server, http.MethodPost, path, "", body, env.accountAuth(t, http.MethodPost, path, "", body), nil)
	expectStatus(t, second, http.StatusTooManyRequests)
	if second.Header().Get("Retry-After") == "" {
		t.Fatal("E_RATE_LIMITED response lacks Retry-After")
	}
}

func TestDeviceJoinRequest(t *testing.T) {
	env := newTestEnv(t)
	signing, _, err := signatures.Generate()
	if err != nil {
		t.Fatal(err)
	}
	encryption, err := x25519.Generate()
	if err != nil {
		t.Fatal(err)
	}
	body, err := encoding.Encode(map[uint64]any{
		0: env.account.accountID,
		1: bytes.Repeat([]byte{0x21}, identifiers.ShortLength),
		2: signing,
		3: encryption.PublicKey(),
		4: accounts.DeviceKindClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder := do(t, env.server, http.MethodPost, "/v1/device-join-requests", "", body, "", nil)
	expectStatus(t, recorder, http.StatusCreated)

	bad, err := encoding.Encode(map[uint64]any{
		0: env.account.accountID,
		1: bytes.Repeat([]byte{0x22}, identifiers.ShortLength),
		2: signing,
		3: encryption.PublicKey(),
		4: uint64(99),
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder = do(t, env.server, http.MethodPost, "/v1/device-join-requests", "", bad, "", nil)
	expectStatus(t, recorder, http.StatusBadRequest)
}

func TestRateLimiterDisabledWithoutConfig(t *testing.T) {
	env := newTestEnv(t)
	if ok, _ := env.server.limiter.allow("acc:x", "events"); !ok {
		t.Fatal("rate limiter rejected a request without configured groups")
	}
}

// --- shared fixtures -------------------------------------------------------

type deviceFixture struct {
	id      []byte
	signing ed25519.PublicKey
	private ed25519.PrivateKey
	encrypt []byte
	kind    uint64
}

type accountFixture struct {
	identityPriv ed25519.PrivateKey
	accountID    []byte
	handle       string
	homeInstance []byte
	first        deviceFixture
	genesis      events.Event
}

func newAccountFixture(t *testing.T) *accountFixture {
	t.Helper()
	identityPub, identityPriv, err := signatures.Generate()
	if err != nil {
		t.Fatal(err)
	}
	accountID, err := identifiers.DeriveAccountID(identityPub)
	if err != nil {
		t.Fatal(err)
	}
	homeInstance := bytes.Repeat([]byte{0xaa}, identifiers.LongLength)
	signingPub, signingPriv, err := signatures.Generate()
	if err != nil {
		t.Fatal(err)
	}
	encryption, err := x25519.Generate()
	if err != nil {
		t.Fatal(err)
	}
	first := deviceFixture{
		id:      bytes.Repeat([]byte{0x01}, identifiers.ShortLength),
		signing: signingPub,
		private: signingPriv,
		encrypt: encryption.PublicKey(),
		kind:    accounts.DeviceKindClient,
	}
	authorization := accounts.FirstDeviceAuthorization{
		AccountID:                 accountID,
		DeviceID:                  first.id,
		DeviceSigningPublicKey:    first.signing,
		DeviceEncryptionPublicKey: first.encrypt,
		DeviceKind:                first.kind,
	}
	if err := authorization.Sign(identityPriv); err != nil {
		t.Fatal(err)
	}
	genesis := events.Event{
		EventID:   bytes.Repeat([]byte{0xb1}, identifiers.ShortLength),
		EventType: 0,
		AccountID: accountID,
		CreatedAt: 1,
		Body: map[uint64]any{
			0: identityPub,
			1: "alice",
			2: homeInstance,
			3: authorization.Wire(),
		},
	}
	if err := genesis.Sign(identityPriv); err != nil {
		t.Fatal(err)
	}
	return &accountFixture{
		identityPriv: identityPriv,
		accountID:    accountID,
		handle:       "alice",
		homeInstance: homeInstance,
		first:        first,
		genesis:      genesis,
	}
}

func accountPostEvent(t *testing.T, account *accountFixture, predecessor []byte, seed uint8, createdAt uint64, signer ed25519.PrivateKey) events.Event {
	t.Helper()
	event := events.Event{
		EventID:      bytes.Repeat([]byte{seed}, identifiers.ShortLength),
		EventType:    13,
		AccountID:    account.accountID,
		DeviceID:     account.first.id,
		CreatedAt:    createdAt,
		Predecessors: [][]byte{predecessor},
		Body:         map[uint64]any{},
		ObjectReferences: []events.ObjectReference{{
			ObjectID:  bytes.Repeat([]byte{0x77}, identifiers.LongLength),
			VersionID: bytes.Repeat([]byte{0x78}, identifiers.LongLength),
		}},
	}
	if err := event.Sign(signer); err != nil {
		t.Fatal(err)
	}
	return event
}

func validDeviceRecipient(account *accountFixture) map[uint64]any {
	return map[uint64]any{
		0: objects.RecipientKindDevice,
		1: account.accountID,
		2: account.first.id,
		3: bytes.Repeat([]byte{0x31}, identifiers.ShortLength),
		4: bytes.Repeat([]byte{0x32}, 32),
		5: bytes.Repeat([]byte{0x33}, 48),
	}
}
