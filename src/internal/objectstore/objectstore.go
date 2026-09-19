// Package objectstore stores encrypted object blobs and transient resumable
// uploads. Blob keys are derived from protocol identifiers (65.10); the store
// never sees plaintext. The local filesystem backend serves development and
// single-node deployments; an S3-compatible backend is provided for
// production, per 65.10.
package objectstore

import (
	"context"
	"errors"
	"io"
	"time"
)

var (
	ErrObjectNotFound   = errors.New("object not found")
	ErrUploadNotFound   = errors.New("upload not found")
	ErrUploadComplete   = errors.New("upload already complete")
	ErrUploadTooLarge   = errors.New("append exceeds upload length")
	ErrScopeMismatch    = errors.New("upload length or owner mismatch")
	ErrInvalidLength    = errors.New("object length is invalid")
	ErrIncompleteStream = errors.New("upload not finalized")
)

// Version describes one immutable object version stored in the backend.
type Version struct {
	VersionID []byte
	Size      int64
	CreatedAt time.Time
}

// Backend persists encrypted object blobs keyed by object ID and version ID.
type Backend interface {
	// PutObject stores the ciphertext blob for one object version, replacing
	// any bytes previously stored under the same version.
	PutObject(ctx context.Context, objectID, versionID []byte, data io.Reader, size int64) (Version, error)
	// OpenObject streams the full blob for one object version.
	OpenObject(ctx context.Context, objectID, versionID []byte) (io.ReadCloser, Version, error)
	// OpenObjectRange streams bytes [offset, offset+length) of the blob.
	OpenObjectRange(ctx context.Context, objectID, versionID []byte, offset, length int64) (io.ReadCloser, Version, error)
	// HeadObject reports the blob size and creation time without its bytes.
	HeadObject(ctx context.Context, objectID, versionID []byte) (Version, error)
	// DeleteObject removes the physical bytes of one version, per 65.7.
	DeleteObject(ctx context.Context, objectID, versionID []byte) error
	// ListVersions enumerates the stored versions of one object, newest first.
	ListVersions(ctx context.Context, objectID []byte) ([]Version, error)
}

// Upload is the transient state of one resumable upload resource, per 35.10.
type Upload struct {
	UploadID  []byte
	Owner     []byte
	Length    int64
	Offset    int64
	Complete  bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// UploadStore manages transient resumable uploads. Upload resources are not
// federated and hold ciphertext only until bound to an object envelope or
// expired.
type UploadStore interface {
	// CreateUpload opens a new upload for length bytes owned by an account.
	CreateUpload(ctx context.Context, uploadID, owner []byte, length int64) error
	// AppendUpload appends a chunk. It finalizes the upload once the stored
	// offset reaches Length and returns the new offset.
	AppendUpload(ctx context.Context, uploadID []byte, chunk io.Reader) (int64, error)
	// UploadInfo reports upload state for tus HEAD.
	UploadInfo(ctx context.Context, uploadID []byte) (Upload, error)
	// ConsumeUpload streams the uploaded bytes for binding to an envelope.
	// The upload resource is left in place until DeleteUpload is called.
	ConsumeUpload(ctx context.Context, uploadID []byte) (io.ReadCloser, Upload, error)
	// DeleteUpload removes an upload resource and its bytes.
	DeleteUpload(ctx context.Context, uploadID []byte) error
	// DeleteExpired removes incomplete uploads not updated since olderThan.
	DeleteExpired(ctx context.Context, olderThan time.Time) (int, error)
}

// Store is an object blob backend with resumable upload support.
type Store interface {
	Backend
	UploadStore
}
