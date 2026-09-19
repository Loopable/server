package objectstore

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"loopable.party/server/internal/protocol/identifiers"
)

func localStore(t *testing.T) *Local {
	t.Helper()
	store, err := NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func rnd(t *testing.T, kind identifiers.Type, seed byte) []byte {
	t.Helper()
	length := map[identifiers.Type]int{identifiers.ObjectID: 32, identifiers.VersionID: 32, identifiers.RequestID: 16}[kind]
	return bytes.Repeat([]byte{seed}, length)
}

func TestLocalObjectRoundTrip(t *testing.T) {
	store := localStore(t)
	ctx := t.Context()
	objectID := rnd(t, identifiers.ObjectID, 1)
	versionID := rnd(t, identifiers.VersionID, 2)
	payload := bytes.Repeat([]byte{0xab}, 2048)

	version, err := store.PutObject(ctx, objectID, versionID, bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	if version.Size != int64(len(payload)) {
		t.Fatalf("size %d, want %d", version.Size, len(payload))
	}

	body, head, err := store.OpenObject(ctx, objectID, versionID)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	got, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch")
	}
	if head.Size != int64(len(payload)) {
		t.Fatalf("head size %d", head.Size)
	}

	headOnly, err := store.HeadObject(ctx, objectID, versionID)
	if err != nil {
		t.Fatal(err)
	}
	if headOnly.Size != int64(len(payload)) {
		t.Fatalf("HeadObject size %d", headOnly.Size)
	}
}

func TestLocalObjectRange(t *testing.T) {
	store := localStore(t)
	ctx := t.Context()
	objectID := rnd(t, identifiers.ObjectID, 3)
	versionID := rnd(t, identifiers.VersionID, 4)
	payload := []byte("abcdefghijklmnopqrstuvwxyz")

	if _, err := store.PutObject(ctx, objectID, versionID, bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatal(err)
	}
	body, _, err := store.OpenObjectRange(ctx, objectID, versionID, 5, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	got, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "fghi" {
		t.Fatalf("range got %q", got)
	}
	if _, _, err := store.OpenObjectRange(ctx, objectID, versionID, 10, 20); !errors.Is(err, ErrInvalidLength) {
		t.Fatalf("overflow range: got %v, want ErrInvalidLength", err)
	}
}

func TestLocalMissingObject(t *testing.T) {
	store := localStore(t)
	ctx := t.Context()
	if _, err := store.HeadObject(ctx, rnd(t, identifiers.ObjectID, 5), rnd(t, identifiers.VersionID, 6)); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("got %v, want ErrObjectNotFound", err)
	}
	if _, _, err := store.OpenObject(ctx, rnd(t, identifiers.ObjectID, 5), rnd(t, identifiers.VersionID, 6)); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("open: got %v, want ErrObjectNotFound", err)
	}
}

func TestLocalListVersionsAndDelete(t *testing.T) {
	store := localStore(t)
	ctx := t.Context()
	objectID := rnd(t, identifiers.ObjectID, 7)

	old := rnd(t, identifiers.VersionID, 0x11)
	new := rnd(t, identifiers.VersionID, 0x22)
	for _, versionID := range [][]byte{old, new} {
		if _, err := store.PutObject(ctx, objectID, versionID, bytes.NewReader([]byte("x")), 1); err != nil {
			t.Fatal(err)
		}
	}
	versions, err := store.ListVersions(ctx, objectID)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 2 {
		t.Fatalf("got %d versions, want 2", len(versions))
	}
	if !bytes.Equal(versions[0].VersionID, new) {
		t.Fatalf("newest first violated: %x", versions[0].VersionID)
	}
	if err := store.DeleteObject(ctx, objectID, old); err != nil {
		t.Fatal(err)
	}
	versions, err = store.ListVersions(ctx, objectID)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 1 {
		t.Fatalf("after delete got %d versions", len(versions))
	}
}

func TestLocalUploadLifecycle(t *testing.T) {
	store := localStore(t)
	ctx := t.Context()
	uploadID := rnd(t, identifiers.RequestID, 8)
	owner := rnd(t, identifiers.AccountID, 9)

	if err := store.CreateUpload(ctx, uploadID, owner, 100); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateUpload(ctx, uploadID, owner, 100); err == nil {
		t.Fatal("duplicate upload accepted")
	}
	info, err := store.UploadInfo(ctx, uploadID)
	if err != nil {
		t.Fatal(err)
	}
	if info.Offset != 0 || info.Complete {
		t.Fatalf("initial info %#v", info)
	}
	if !bytes.Equal(info.Owner, owner) || info.Length != 100 {
		t.Fatalf("owner/length mismatch")
	}

	offset, err := store.AppendUpload(ctx, uploadID, bytes.NewReader([]byte("hello ")))
	if err != nil {
		t.Fatal(err)
	}
	if offset != 6 {
		t.Fatalf("offset %d, want 6", offset)
	}
	offset, err = store.AppendUpload(ctx, uploadID, bytes.NewReader(bytes.Repeat([]byte("x"), 94)))
	if err != nil {
		t.Fatal(err)
	}
	if offset != 100 {
		t.Fatalf("offset %d, want 100", offset)
	}
	info, err = store.UploadInfo(ctx, uploadID)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Complete {
		t.Fatal("upload should be complete")
	}
	if _, err := store.AppendUpload(ctx, uploadID, bytes.NewReader([]byte("more"))); !errors.Is(err, ErrUploadComplete) {
		t.Fatalf("append after complete: got %v, want ErrUploadComplete", err)
	}

	body, info, err := store.ConsumeUpload(ctx, uploadID)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	want := append([]byte("hello "), bytes.Repeat([]byte("x"), 94)...)
	if !bytes.Equal(blob, want) || len(blob) != 100 {
		t.Fatalf("consumed %d bytes, mismatch", len(blob))
	}

	if err := store.DeleteUpload(ctx, uploadID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UploadInfo(ctx, uploadID); !errors.Is(err, ErrUploadNotFound) {
		t.Fatalf("after delete: got %v, want ErrUploadNotFound", err)
	}
}

func TestLocalAppendBeyondLength(t *testing.T) {
	store := localStore(t)
	ctx := t.Context()
	uploadID := rnd(t, identifiers.RequestID, 0x31)
	if err := store.CreateUpload(ctx, uploadID, rnd(t, identifiers.AccountID, 0x32), 10); err != nil {
		t.Fatal(err)
	}
	offset, err := store.AppendUpload(ctx, uploadID, bytes.NewReader(bytes.Repeat([]byte("z"), 50)))
	if err != nil {
		t.Fatal(err)
	}
	if offset != 10 {
		t.Fatalf("offset %d, want 10 (capped at length)", offset)
	}
	info, err := store.UploadInfo(ctx, uploadID)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Complete {
		t.Fatal("upload should finalize at length")
	}
}

func TestLocalIncompleteUploadCannotConsume(t *testing.T) {
	store := localStore(t)
	ctx := t.Context()
	uploadID := rnd(t, identifiers.RequestID, 0x41)
	if err := store.CreateUpload(ctx, uploadID, rnd(t, identifiers.AccountID, 0x42), 10); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendUpload(ctx, uploadID, bytes.NewReader([]byte("abc"))); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ConsumeUpload(ctx, uploadID); !errors.Is(err, ErrIncompleteStream) {
		t.Fatalf("got %v, want ErrIncompleteStream", err)
	}
}

func TestLocalDeleteExpired(t *testing.T) {
	store := localStore(t)
	ctx := t.Context()
	uploadID := rnd(t, identifiers.RequestID, 0x51)
	if err := store.CreateUpload(ctx, uploadID, rnd(t, identifiers.AccountID, 0x52), 10); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendUpload(ctx, uploadID, bytes.NewReader([]byte("ab"))); err != nil {
		t.Fatal(err)
	}
	removed, err := store.DeleteExpired(ctx, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("removed %d, want 1", removed)
	}
	if _, err := store.UploadInfo(ctx, uploadID); !errors.Is(err, ErrUploadNotFound) {
		t.Fatalf("got %v, want ErrUploadNotFound", err)
	}
}

func TestLocalRejectsZeroLengthUpload(t *testing.T) {
	store := localStore(t)
	ctx := t.Context()
	if err := store.CreateUpload(ctx, rnd(t, identifiers.RequestID, 0x61), rnd(t, identifiers.AccountID, 0x62), 0); !errors.Is(err, ErrInvalidLength) {
		t.Fatalf("got %v, want ErrInvalidLength", err)
	}
}
