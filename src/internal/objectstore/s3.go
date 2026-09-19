package objectstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"loopable.party/server/internal/protocol/identifiers"
)

// isObjectNotFound reports whether an S3 error is a missing object.
func isObjectNotFound(err error) bool {
	var notFound *types.NotFound
	if errors.As(err, &notFound) {
		return true
	}
	var noSuchKey *types.NoSuchKey
	return errors.As(err, &noSuchKey)
}

// S3 is an S3-compatible Store. Object blobs map one-to-one onto object keys
// (65.10). Uploads are stored as ordered part objects so PATCH never rewrites
// previously appended bytes; binding streams the parts in order. The S3
// client must be pointed at the deployment endpoint via standard SDK
// configuration.
type S3 struct {
	client   *s3.Client
	uploader *manager.Uploader
	bucket   string
}

// NewS3 builds an S3 Store for the given bucket.
func NewS3(client *s3.Client, bucket string) *S3 {
	return &S3{
		client:   client,
		uploader: manager.NewUploader(client),
		bucket:   bucket,
	}
}

func (s *S3) PutObject(ctx context.Context, objectID, versionID []byte, data io.Reader, size int64) (Version, error) {
	if size < 0 {
		return Version{}, ErrInvalidLength
	}
	key, err := objectKey(objectID, versionID)
	if err != nil {
		return Version{}, err
	}
	_, err = s.uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(key),
		Body:          io.NopCloser(io.LimitReader(data, size)),
		ContentLength: aws.Int64(size),
	})
	if err != nil {
		return Version{}, err
	}
	return Version{VersionID: append([]byte(nil), versionID...), Size: size, CreatedAt: time.Now().UTC()}, nil
}

func (s *S3) OpenObject(ctx context.Context, objectID, versionID []byte) (io.ReadCloser, Version, error) {
	return s.openRange(ctx, objectID, versionID, 0, -1)
}

func (s *S3) OpenObjectRange(ctx context.Context, objectID, versionID []byte, offset, length int64) (io.ReadCloser, Version, error) {
	return s.openRange(ctx, objectID, versionID, offset, length)
}

func (s *S3) HeadObject(ctx context.Context, objectID, versionID []byte) (Version, error) {
	key, err := objectKey(objectID, versionID)
	if err != nil {
		return Version{}, err
	}
	head, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		if isObjectNotFound(err) {
			return Version{}, ErrObjectNotFound
		}
		return Version{}, err
	}
	created := time.Now().UTC()
	if head.LastModified != nil {
		created = head.LastModified.UTC()
	}
	return Version{
		VersionID: append([]byte(nil), versionID...),
		Size:      valueOrZero(head.ContentLength),
		CreatedAt: created,
	}, nil
}

func (s *S3) DeleteObject(ctx context.Context, objectID, versionID []byte) error {
	key, err := objectKey(objectID, versionID)
	if err != nil {
		return err
	}
	_, err = s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil && !isObjectNotFound(err) {
		return err
	}
	return nil
}

func (s *S3) ListVersions(ctx context.Context, objectID []byte) ([]Version, error) {
	prefix, err := objectPrefix(objectID)
	if err != nil {
		return nil, err
	}
	keys, err := s.listKeys(ctx, prefix)
	if err != nil {
		return nil, err
	}
	versions := make([]Version, 0, len(keys))
	for _, key := range keys {
		versionID, err := parseVersionText(trimObjectKey(prefix, key))
		if err != nil {
			continue
		}
		head, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(s.bucket),
			Key:    aws.String(key),
		})
		if err != nil {
			return nil, err
		}
		created := time.Now().UTC()
		if head.LastModified != nil {
			created = head.LastModified.UTC()
		}
		versions = append(versions, Version{
			VersionID: versionID,
			Size:      valueOrZero(head.ContentLength),
			CreatedAt: created,
		})
	}
	sortVersions(versions)
	return versions, nil
}

func (s *S3) CreateUpload(ctx context.Context, uploadID, owner []byte, length int64) error {
	if length <= 0 {
		return ErrInvalidLength
	}
	if _, err := s.UploadInfo(ctx, uploadID); err == nil {
		return errors.New("upload already exists")
	} else if !errors.Is(err, ErrUploadNotFound) {
		return err
	}
	now := time.Now().UTC()
	meta := uploadMeta{
		UploadID:  append([]byte(nil), uploadID...),
		Owner:     append([]byte(nil), owner...),
		Length:    length,
		CreatedAt: now,
		UpdatedAt: now,
	}
	return s.putMeta(ctx, meta)
}

func (s *S3) AppendUpload(ctx context.Context, uploadID []byte, chunk io.Reader) (int64, error) {
	meta, err := s.uploadInfoRaw(ctx, uploadID)
	if err != nil {
		return 0, err
	}
	if meta.Offset == meta.Length {
		return 0, ErrUploadComplete
	}
	parts, err := s.listParts(ctx, uploadID)
	if err != nil {
		return 0, err
	}
	next := len(parts)
	remaining := meta.Length - meta.Offset
	// A single tus PATCH chunk is bounded by the HTTP request body limit, so
	// buffering it for upload is acceptable; the full media stream is never
	// resident at once.
	body, err := io.ReadAll(io.LimitReader(chunk, remaining))
	if err != nil {
		return meta.Offset, err
	}
	if int64(len(body)) > remaining {
		return meta.Offset, ErrUploadTooLarge
	}
	partPrefix, err := uploadPrefix(uploadID)
	if err != nil {
		return meta.Offset, err
	}
	partKey := partPrefix + fmt.Sprintf("%08d", next)
	if _, err := s.uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(partKey),
		Body:          strings.NewReader(string(body)),
		ContentLength: aws.Int64(int64(len(body))),
	}); err != nil {
		return meta.Offset, err
	}
	meta.Offset += int64(len(body))
	meta.UpdatedAt = time.Now().UTC()
	if err := s.putMeta(ctx, meta); err != nil {
		return meta.Offset, err
	}
	return meta.Offset, nil
}

func (s *S3) UploadInfo(ctx context.Context, uploadID []byte) (Upload, error) {
	meta, err := s.uploadInfoRaw(ctx, uploadID)
	if err != nil {
		return Upload{}, err
	}
	return meta.upload(), nil
}

func (s *S3) ConsumeUpload(ctx context.Context, uploadID []byte) (io.ReadCloser, Upload, error) {
	meta, err := s.uploadInfoRaw(ctx, uploadID)
	if err != nil {
		return nil, Upload{}, err
	}
	if meta.Offset != meta.Length {
		return nil, Upload{}, ErrIncompleteStream
	}
	parts, err := s.listParts(ctx, uploadID)
	if err != nil {
		return nil, Upload{}, err
	}
	bodies := make([]io.ReadCloser, 0, len(parts))
	for _, partKey := range parts {
		body, err := s.objectBody(ctx, partKey)
		if err != nil {
			_ = closeAll(bodies)
			return nil, Upload{}, err
		}
		bodies = append(bodies, body)
	}
	return &multiReadCloser{readers: bodies}, meta.upload(), nil
}

func (s *S3) DeleteUpload(ctx context.Context, uploadID []byte) error {
	prefix, err := uploadPrefix(uploadID)
	if err != nil {
		return err
	}
	if prefix == "" {
		return nil
	}
	keys, err := s.listKeys(ctx, prefix)
	if err != nil {
		return err
	}
	for _, key := range keys {
		if _, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(s.bucket),
			Key:    aws.String(key),
		}); err != nil && !isObjectNotFound(err) {
			return err
		}
	}
	metaKey, err := literalUploadKey(uploadID)
	if err != nil {
		return err
	}
	if _, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(metaKey),
	}); err != nil && !isObjectNotFound(err) {
		return err
	}
	return nil
}

func (s *S3) DeleteExpired(ctx context.Context, olderThan time.Time) (int, error) {
	keys, err := s.listKeys(ctx, "uploads/")
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, key := range keys {
		name := strings.TrimPrefix(key, "uploads/")
		if !strings.HasSuffix(name, ".meta") {
			continue
		}
		uploadID, err := identifiers.Parse(identifiers.RequestID, strings.TrimSuffix(name, ".meta"))
		if err != nil {
			continue
		}
		meta, err := s.uploadInfoRaw(ctx, uploadID)
		if err != nil {
			continue
		}
		if meta.Offset == meta.Length {
			continue
		}
		if meta.UpdatedAt.Before(olderThan) {
			if err := s.DeleteUpload(ctx, uploadID); err != nil {
				return removed, err
			}
			removed++
		}
	}
	return removed, nil
}

func (s *S3) openRange(ctx context.Context, objectID, versionID []byte, offset, length int64) (io.ReadCloser, Version, error) {
	head, err := s.HeadObject(ctx, objectID, versionID)
	if err != nil {
		return nil, Version{}, err
	}
	if offset < 0 || offset > head.Size {
		return nil, Version{}, ErrInvalidLength
	}
	key, err := objectKey(objectID, versionID)
	if err != nil {
		return nil, Version{}, err
	}
	request := &s3.GetObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)}
	if length >= 0 {
		if offset+length > head.Size {
			return nil, Version{}, ErrInvalidLength
		}
		if length == 0 {
			return io.NopCloser(strings.NewReader("")), head, nil
		}
		request.Range = aws.String(fmt.Sprintf("bytes=%d-%d", offset, offset+length-1))
	} else if offset > 0 {
		request.Range = aws.String(fmt.Sprintf("bytes=%d-", offset))
	}
	result, err := s.client.GetObject(ctx, request)
	if err != nil {
		if isObjectNotFound(err) {
			return nil, Version{}, ErrObjectNotFound
		}
		return nil, Version{}, err
	}
	return result.Body, head, nil
}

func (s *S3) putMeta(ctx context.Context, meta uploadMeta) error {
	key, err := literalUploadKey(meta.UploadID)
	if err != nil {
		return err
	}
	body, err := encodeUploadMeta(meta)
	if err != nil {
		return err
	}
	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(key),
		Body:          strings.NewReader(string(body)),
		ContentLength: aws.Int64(int64(len(body))),
	})
	return err
}

func (s *S3) uploadInfoRaw(ctx context.Context, uploadID []byte) (uploadMeta, error) {
	key, err := literalUploadKey(uploadID)
	if err != nil {
		return uploadMeta{}, err
	}
	body, err := s.objectBytes(ctx, key)
	if err != nil {
		if isObjectNotFound(err) {
			return uploadMeta{}, ErrUploadNotFound
		}
		return uploadMeta{}, err
	}
	return decodeUploadMeta(body)
}

func (s *S3) listParts(ctx context.Context, uploadID []byte) ([]string, error) {
	prefix, err := uploadPrefix(uploadID)
	if err != nil {
		return nil, err
	}
	keys, err := s.listKeys(ctx, prefix)
	if err != nil {
		return nil, err
	}
	sort.Slice(keys, func(i, j int) bool {
		return partOrdinal(keys[i]) < partOrdinal(keys[j])
	})
	return keys, nil
}

func (s *S3) listKeys(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(prefix),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, object := range page.Contents {
			if object.Key != nil {
				keys = append(keys, *object.Key)
			}
		}
	}
	return keys, nil
}

func (s *S3) objectBody(ctx context.Context, key string) (io.ReadCloser, error) {
	result, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}
	return result.Body, nil
}

func (s *S3) objectBytes(ctx context.Context, key string) ([]byte, error) {
	body, err := s.objectBody(ctx, key)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return io.ReadAll(io.LimitReader(body, 1<<20))
}

func uploadPrefix(uploadID []byte) (string, error) {
	text, err := identifiers.String(identifiers.RequestID, uploadID)
	if err != nil {
		return "", fmt.Errorf("upload ID: %w", err)
	}
	return "uploads/" + text + "/", nil
}

// trimObjectKey strips the base32lower version component from an object key.
func trimObjectKey(prefix, key string) string {
	return strings.TrimPrefix(key, prefix)
}

func partOrdinal(key string) int {
	_, suffix, ok := strings.Cut(key, "/")
	if !ok {
		return 0
	}
	ordinal, err := strconv.Atoi(suffix)
	if err != nil {
		return 0
	}
	return ordinal
}

func valueOrZero(value *int64) int64 {
	if value == nil {
		return 0
	}
	return *value
}

func closeAll(readers []io.ReadCloser) error {
	var errs []error
	for _, reader := range readers {
		if err := reader.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

type multiReadCloser struct {
	readers []io.ReadCloser
	index   int
}

func (m *multiReadCloser) Read(p []byte) (int, error) {
	for m.index < len(m.readers) {
		n, err := m.readers[m.index].Read(p)
		if err == io.EOF {
			_ = m.readers[m.index].Close()
			m.index++
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
	return 0, io.EOF
}

func (m *multiReadCloser) Close() error {
	return closeAll(m.readers)
}

var _ Store = (*S3)(nil)
