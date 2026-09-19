package objectstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"loopable.party/server/internal/protocol/identifiers"
)

// Local is a filesystem-backed Store for development and single-node
// deployments. Directories are created lazily under root. Object blobs and
// upload bytes are written under the keys of keys.go.
type Local struct {
	root string
}

// NewLocal builds a Local store rooted at root. Zero-length uploads are not
// supported: tus length 0 carries no bytes and is rejected at creation.
func NewLocal(root string) (*Local, error) {
	if root == "" {
		return nil, errors.New("objectstore root is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	return &Local{root: abs}, nil
}

func (l *Local) PutObject(ctx context.Context, objectID, versionID []byte, data io.Reader, size int64) (Version, error) {
	if size < 0 {
		return Version{}, ErrInvalidLength
	}
	key, err := objectKey(objectID, versionID)
	if err != nil {
		return Version{}, err
	}
	if err := l.write(ctx, key, data, size); err != nil {
		return Version{}, err
	}
	return Version{VersionID: append([]byte(nil), versionID...), Size: size, CreatedAt: time.Now().UTC()}, nil
}

func (l *Local) OpenObject(ctx context.Context, objectID, versionID []byte) (io.ReadCloser, Version, error) {
	return l.openRange(ctx, objectID, versionID, 0, -1)
}

func (l *Local) OpenObjectRange(ctx context.Context, objectID, versionID []byte, offset, length int64) (io.ReadCloser, Version, error) {
	return l.openRange(ctx, objectID, versionID, offset, length)
}

func (l *Local) HeadObject(ctx context.Context, objectID, versionID []byte) (Version, error) {
	key, err := objectKey(objectID, versionID)
	if err != nil {
		return Version{}, err
	}
	path := l.pathFor(key)
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Version{}, ErrObjectNotFound
		}
		return Version{}, err
	}
	return Version{VersionID: append([]byte(nil), versionID...), Size: info.Size(), CreatedAt: info.ModTime().UTC()}, nil
}

func (l *Local) DeleteObject(ctx context.Context, objectID, versionID []byte) error {
	key, err := objectKey(objectID, versionID)
	if err != nil {
		return err
	}
	if err := os.Remove(l.pathFor(key)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (l *Local) ListVersions(ctx context.Context, objectID []byte) ([]Version, error) {
	prefix, err := objectPrefix(objectID)
	if err != nil {
		return nil, err
	}
	dir := l.pathFor(prefix)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	versions := make([]Version, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		versionID, err := parseKeySuffix(entry.Name())
		if err != nil {
			continue
		}
		versions = append(versions, Version{
			VersionID: versionID,
			Size:      info.Size(),
			CreatedAt: info.ModTime().UTC(),
		})
	}
	sortVersions(versions)
	return versions, nil
}

func (l *Local) CreateUpload(ctx context.Context, uploadID, owner []byte, length int64) error {
	if length <= 0 {
		return ErrInvalidLength
	}
	_, err := l.uploadInfoRaw(ctx, uploadID)
	if err == nil {
		return errors.New("upload already exists")
	}
	if !errors.Is(err, ErrUploadNotFound) {
		return err
	}
	now := time.Now().UTC()
	meta := uploadMeta{
		UploadID:  string(uploadID),
		Owner:     append([]byte(nil), owner...),
		Length:    length,
		CreatedAt: now,
		UpdatedAt: now,
	}
	return l.putMeta(ctx, meta)
}

func (l *Local) AppendUpload(ctx context.Context, uploadID []byte, chunk io.Reader) (int64, error) {
	meta, err := l.uploadInfoRaw(ctx, uploadID)
	if err != nil {
		return 0, err
	}
	if meta.Offset == meta.Length {
		return 0, ErrUploadComplete
	}
	key, err := uploadKey(uploadID)
	if err != nil {
		return 0, err
	}
	file, err := os.OpenFile(l.pathFor(key), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	remaining := meta.Length - meta.Offset
	lr := io.LimitReader(chunk, remaining)
	written, err := io.Copy(file, lr)
	if err != nil {
		return meta.Offset, err
	}
	meta.Offset += written
	meta.UpdatedAt = time.Now().UTC()
	if err := l.putMeta(ctx, meta); err != nil {
		return meta.Offset, err
	}
	if written == remaining && meta.Offset == meta.Length {
		return meta.Offset, nil
	}
	return meta.Offset, nil
}

func (l *Local) UploadInfo(ctx context.Context, uploadID []byte) (Upload, error) {
	meta, err := l.uploadInfoRaw(ctx, uploadID)
	if err != nil {
		return Upload{}, err
	}
	return meta.upload(), nil
}

func (l *Local) ConsumeUpload(ctx context.Context, uploadID []byte) (io.ReadCloser, Upload, error) {
	meta, err := l.uploadInfoRaw(ctx, uploadID)
	if err != nil {
		return nil, Upload{}, err
	}
	if meta.Offset != meta.Length {
		return nil, Upload{}, ErrIncompleteStream
	}
	key, err := uploadKey(uploadID)
	if err != nil {
		return nil, Upload{}, err
	}
	file, err := os.Open(l.pathFor(key))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, Upload{}, ErrUploadNotFound
		}
		return nil, Upload{}, err
	}
	return file, meta.upload(), nil
}

func (l *Local) DeleteUpload(ctx context.Context, uploadID []byte) error {
	dataKey, err := uploadKey(uploadID)
	if err != nil {
		return err
	}
	metaKey, err := literalUploadKey(uploadID)
	if err != nil {
		return err
	}
	for _, key := range []string{dataKey, metaKey} {
		if err := os.Remove(l.pathFor(key)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (l *Local) DeleteExpired(ctx context.Context, olderThan time.Time) (int, error) {
	dir := l.pathFor("uploads/")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	removed := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".meta") {
			continue
		}
		uploadID, err := identifiers.Parse(identifiers.RequestID, strings.TrimSuffix(name, ".meta"))
		if err != nil {
			continue
		}
		meta, err := l.uploadInfoRaw(ctx, uploadID)
		if err != nil {
			continue
		}
		if meta.Offset == meta.Length {
			continue
		}
		if meta.UpdatedAt.Before(olderThan) {
			if err := l.DeleteUpload(ctx, uploadID); err != nil {
				return removed, err
			}
			removed++
		}
	}
	return removed, nil
}

func (l *Local) write(ctx context.Context, key string, data io.Reader, size int64) error {
	path := l.pathFor(key)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := io.Copy(tmp, data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	info, err := os.Stat(tmpName)
	if err != nil {
		return err
	}
	if info.Size() != size {
		return ErrScopeMismatch
	}
	return os.Rename(tmpName, path)
}

func (l *Local) openRange(ctx context.Context, objectID, versionID []byte, offset, length int64) (io.ReadCloser, Version, error) {
	key, err := objectKey(objectID, versionID)
	if err != nil {
		return nil, Version{}, err
	}
	path := l.pathFor(key)
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, Version{}, ErrObjectNotFound
		}
		return nil, Version{}, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, Version{}, err
	}
	if offset < 0 || offset > info.Size() {
		file.Close()
		return nil, Version{}, ErrInvalidLength
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		file.Close()
		return nil, Version{}, err
	}
	var reader io.ReadCloser = file
	if length >= 0 {
		if offset+length > info.Size() {
			file.Close()
			return nil, Version{}, ErrInvalidLength
		}
		reader = &limitedReadCloser{Reader: io.LimitReader(file, length), Closer: file}
	}
	return reader, Version{
		VersionID: append([]byte(nil), versionID...),
		Size:      info.Size(),
		CreatedAt: info.ModTime().UTC(),
	}, nil
}

func (l *Local) putMeta(ctx context.Context, meta uploadMeta) error {
	key, err := literalUploadKey([]byte(meta.UploadID))
	if err != nil {
		return err
	}
	body, err := encodeUploadMeta(meta)
	if err != nil {
		return err
	}
	return l.write(ctx, key, bytes.NewReader(body), int64(len(body)))
}

func (l *Local) uploadInfoRaw(ctx context.Context, uploadID []byte) (uploadMeta, error) {
	key, err := literalUploadKey(uploadID)
	if err != nil {
		return uploadMeta{}, err
	}
	body, err := os.ReadFile(l.pathFor(key))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return uploadMeta{}, ErrUploadNotFound
		}
		return uploadMeta{}, err
	}
	return decodeUploadMeta(body)
}

// pathFor resolves a store key to a filesystem path below root. Keys are
// bounded: they contain only base32 lowercase text and separators, so they
// never traverse above root.
func (l *Local) pathFor(key string) string {
	return filepath.Join(l.root, key)
}

// parseKeySuffix decodes the base32lower filename of an object version entry.
func parseKeySuffix(name string) ([]byte, error) {
	return parseVersionText(name)
}

type limitedReadCloser struct {
	io.Reader
	io.Closer
}

var _ Store = (*Local)(nil)

func (l *Local) String() string { return fmt.Sprintf("local:%s", l.root) }
