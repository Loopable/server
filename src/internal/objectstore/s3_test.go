package objectstore

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"loopable.party/server/internal/protocol/identifiers"
)

// These tests require a running S3-compatible endpoint (AWS, or self-hosted
// like MinIO). They are skipped unless LOOPABLE_TEST_S3 is set and
// LOOPABLE_TEST_S3_BUCKET names an existing bucket. Point a MinIO/AWS
// endpoint at the SDK via the standard AWS_* env vars.
func s3Store(t *testing.T) *S3 {
	t.Helper()
	if os.Getenv("LOOPABLE_TEST_S3") == "" {
		t.Skip("LOOPABLE_TEST_S3 not set; skipping S3 integration tests")
	}
	bucket := os.Getenv("LOOPABLE_TEST_S3_BUCKET")
	if bucket == "" {
		t.Fatal("LOOPABLE_TEST_S3_BUCKET must be set")
	}
	ctx := t.Context()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	store := NewS3(s3.NewFromConfig(cfg), bucket)
	if _, err := store.HeadObject(ctx, rnd(t, identifiers.ObjectID, 0x71), rnd(t, identifiers.VersionID, 0x72)); err != nil && !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("endpoint not reachable: %v", err)
	}
	return store
}

func TestS3ObjectRoundTrip(t *testing.T) {
	store := s3Store(t)
	ctx := t.Context()
	objectID := rnd(t, identifiers.ObjectID, 0x73)
	versionID := rnd(t, identifiers.VersionID, 0x74)
	payload := bytes.Repeat([]byte{0xcd}, 4096)

	version, err := store.PutObject(ctx, objectID, versionID, bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	defer store.DeleteObject(ctx, objectID, versionID)
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

	rangeBody, _, err := store.OpenObjectRange(ctx, objectID, versionID, 100, 50)
	if err != nil {
		t.Fatal(err)
	}
	defer rangeBody.Close()
	part, err := io.ReadAll(rangeBody)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(part, payload[100:150]) {
		t.Fatal("range mismatch")
	}

	if _, err := store.HeadObject(ctx, objectID, versionID); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteObject(ctx, objectID, versionID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.HeadObject(ctx, objectID, versionID); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("after delete got %v, want ErrObjectNotFound", err)
	}
}

func TestS3UploadLifecycle(t *testing.T) {
	store := s3Store(t)
	ctx := t.Context()
	uploadID := rnd(t, identifiers.RequestID, 0x81)
	owner := rnd(t, identifiers.AccountID, 0x82)

	if err := store.CreateUpload(ctx, uploadID, owner, 42); err != nil {
		t.Fatal(err)
	}
	defer store.DeleteUpload(ctx, uploadID)

	offset, err := store.AppendUpload(ctx, uploadID, bytes.NewReader([]byte("0123456789")))
	if err != nil {
		t.Fatal(err)
	}
	if offset != 10 {
		t.Fatalf("offset %d, want 10", offset)
	}
	info, err := store.UploadInfo(ctx, uploadID)
	if err != nil {
		t.Fatal(err)
	}
	if info.Offset != 10 || info.Complete {
		t.Fatalf("info %#v", info)
	}
	if !bytes.Equal(info.Owner, owner) {
		t.Fatal("owner mismatch")
	}

	offset, err = store.AppendUpload(ctx, uploadID, bytes.NewReader([]byte("012345678901234567890123456789012")))
	if err != nil {
		t.Fatal(err)
	}
	if offset != 42 {
		t.Fatalf("offset %d, want 42", offset)
	}
	if _, err := store.AppendUpload(ctx, uploadID, bytes.NewReader([]byte("x"))); !errors.Is(err, ErrUploadComplete) {
		t.Fatalf("append past end got %v, want ErrUploadComplete", err)
	}

	body, _, err := store.ConsumeUpload(ctx, uploadID)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	body.Close()
	want := append([]byte("0123456789"), bytes.Repeat([]byte("k"), 32)...)
	if !bytes.Equal(blob, want) || len(blob) != 42 {
		t.Fatalf("consumed %d bytes, mismatch", len(blob))
	}

	if err := store.DeleteUpload(ctx, uploadID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UploadInfo(ctx, uploadID); !errors.Is(err, ErrUploadNotFound) {
		t.Fatalf("after delete got %v, want ErrUploadNotFound", err)
	}
}

func TestS3DeleteExpired(t *testing.T) {
	store := s3Store(t)
	ctx := t.Context()
	uploadID := rnd(t, identifiers.RequestID, 0x91)
	if err := store.CreateUpload(ctx, uploadID, rnd(t, identifiers.AccountID, 0x92), 100); err != nil {
		t.Fatal(err)
	}
	defer store.DeleteUpload(ctx, uploadID)
	if _, err := store.AppendUpload(ctx, uploadID, bytes.NewReader([]byte("stale"))); err != nil {
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
