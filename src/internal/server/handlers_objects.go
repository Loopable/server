package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"loopable.party/server/internal/objectstore"
	"loopable.party/server/internal/protocol/encoding"
	"loopable.party/server/internal/protocol/identifiers"
	"loopable.party/server/internal/protocol/objects"
	storepkg "loopable.party/server/internal/store"
)

// smallEnvelopeLimit is the ciphertext size kept inline in the envelope wire;
// larger blobs are stored in the object store backend with the envelope
// recorded ciphertext-empty.
const smallEnvelopeLimit = 128 << 10

// handlePostObjects submits a CBOR array of object submissions (60.5): either
// complete object envelopes or, for account-authenticated media creation,
// media_upload_submission wrappers (35.10). The response mirrors the request.
func (s *Server) handlePostObjects(w http.ResponseWriter, r *http.Request) {
	s.limit(w, r, "objects", func() {
		requestID := requestContextID(r)
		auth := requestAuth(r)

		var raw []any
		if err := s.decodeRequest(requestBody(r), &raw); err != nil {
			writeError(w, err, requestID)
			return
		}
		if len(raw) == 0 || len(raw) > maxObjectsPerPost {
			writeError(w, asInvalidRequest(errors.New("batch has no objects or exceeds the limit")), requestID)
			return
		}

		results := make([]any, 0, len(raw))
		for _, item := range raw {
			results = append(results, s.acceptObject(r, auth, item))
		}
		_ = s.writeCBOR(w, http.StatusOK, results)
	})
}

// acceptObject resolves one object submission into its result record.
func (s *Server) acceptObject(r *http.Request, auth *authContext, item any) map[uint64]any {
	requestID := requestContextID(r)
	objectID, err := firstFieldBytes(item)
	if err != nil {
		return submitResult(nil, 2, mapError(asInvalidRequest(err), requestID))
	}
	submission, err := asUintMap(item)
	if err != nil {
		return submitResult(objectID, 2, mapError(asInvalidRequest(err), requestID))
	}

	var envelope objects.Object
	// A media_upload_submission wrapper is a map whose field 0 is itself a map
	// (the wrapped envelope) and whose field 1 is the upload token (35.10).
	// A complete envelope's field 0 is the protocol version string.
	if wrapped, err := asUintMap(submission[0]); err == nil {
		envelope, err = s.bindMediaUpload(r, auth, wrapped, submission)
		if err != nil {
			return submitResult(objectID, 2, mapError(err, requestID))
		}
	} else {
		envelope, err = objects.Parse(item)
		if err != nil {
			return submitResult(objectID, 2, mapError(asInvalidRequest(err), requestID))
		}
	}

	duplicate, err := s.storeEnvelope(r.Context(), envelope)
	switch {
	case err == nil:
		status := uint64(0)
		if duplicate {
			status = 1
		}
		return submitResult(envelope.ObjectID, status, nil)
	case errors.Is(err, ErrObjectCollision), errors.Is(err, storepkg.ErrObjectCollision):
		return submitResult(envelope.ObjectID, 2, mapError(ErrObjectCollision, requestID))
	default:
		return submitResult(envelope.ObjectID, 2, mapError(err, requestID))
	}
}

// bindMediaUpload verifies a finalized upload owned by the submitting account
// and merges its bytes into the media envelope (35.10 step 4). Instance
// authentication never uploads via the wrapper.
func (s *Server) bindMediaUpload(r *http.Request, auth *authContext, envelopeFields map[uint64]any, submission map[uint64]any) (objects.Object, error) {
	if auth == nil || len(auth.Account) == 0 {
		return objects.Object{}, asInvalidRequest(errors.New("media upload submission requires account authentication"))
	}
	uploadID, ok := submission[1].([]byte)
	if !ok {
		return objects.Object{}, asInvalidRequest(errors.New("media upload submission is missing its upload_id"))
	}
	// The wrapped envelope has empty ciphertext, which fails object.Parse's
	// streaming-suite check; parse it with a placeholder and bind the real
	// bytes afterward.
	placeholder := make(map[uint64]any, len(envelopeFields))
	for key, value := range envelopeFields {
		placeholder[key] = value
	}
	placeholder[6] = []byte{0x00}
	envelope, err := objects.Parse(placeholder)
	if err != nil {
		return objects.Object{}, asInvalidRequest(err)
	}
	if envelope.ObjectType != objects.ObjectTypeMedia || envelope.EncryptionSuite != objects.EncryptionSuiteStreamingMedia {
		return objects.Object{}, asInvalidRequest(errors.New("media upload submission must wrap a streaming media envelope"))
	}

	info, err := s.cfg.Blobs.UploadInfo(r.Context(), uploadID)
	if err != nil {
		if errors.Is(err, objectstore.ErrUploadNotFound) {
			return objects.Object{}, asInvalidRequest(errors.New("upload not found"))
		}
		return objects.Object{}, err
	}
	if !info.Complete {
		return objects.Object{}, asInvalidRequest(errors.New("upload is not finalized"))
	}
	if !bytes.Equal(info.Owner, auth.Account) {
		return objects.Object{}, asInvalidRequest(errors.New("upload belongs to another account"))
	}
	if info.Length > s.cfg.MediaPlaintextLimit {
		return objects.Object{}, asInvalidRequest(errors.New("upload exceeds the media limit"))
	}

	reader, upload, err := s.cfg.Blobs.ConsumeUpload(r.Context(), uploadID)
	if err != nil {
		return objects.Object{}, err
	}
	ciphertext, err := readAllLimited(reader, upload.Length, s.cfg.MediaPlaintextLimit)
	closeErr := reader.Close()
	if err != nil {
		return objects.Object{}, asInvalidRequest(err)
	}
	if closeErr != nil {
		return objects.Object{}, closeErr
	}
	envelope.Ciphertext = ciphertext
	if err := envelope.Validate(); err != nil {
		return objects.Object{}, asInvalidRequest(err)
	}
	if err := mustStorePath(r.Context(), s.cfg.Blobs, envelope); err != nil {
		return objects.Object{}, err
	}
	if err := s.cfg.Blobs.DeleteUpload(r.Context(), uploadID); err != nil && !errors.Is(err, objectstore.ErrUploadNotFound) {
		return objects.Object{}, err
	}
	return envelope, nil
}

// storeEnvelope registers an envelope in the object repository, storing any
// large ciphertext in the blob backend. It reports whether the (object_id,
// version_id) pair was already registered.
func (s *Server) storeEnvelope(ctx context.Context, envelope objects.Object) (bool, error) {
	duplicate, err := s.cfg.Objects.HasObject(ctx, envelope.ObjectID, envelope.VersionID)
	if err != nil {
		return false, err
	}
	blobBacked := int64(len(envelope.Ciphertext)) > smallEnvelopeLimit
	wire, err := recordWire(envelope, blobBacked)
	if err != nil {
		return false, err
	}
	if blobBacked {
		if err := mustStorePath(ctx, s.cfg.Blobs, envelope); err != nil {
			return false, err
		}
	}
	_, err = s.cfg.Objects.PutObject(ctx, ObjectRecord{
		ObjectID:         envelope.ObjectID,
		ObjectType:       envelope.ObjectType,
		EncryptionSuite:  envelope.EncryptionSuite,
		VersionID:        envelope.VersionID,
		BlobBacked:       blobBacked,
		CiphertextLength: int64(len(envelope.Ciphertext)),
		Wire:             wire,
	})
	return duplicate, err
}

// recordWire renders the stored envelope wire. Blob-backed envelopes carry
// empty ciphertext; their true length is recorded separately.
func recordWire(envelope objects.Object, blobBacked bool) ([]byte, error) {
	value := envelope.Wire()
	if blobBacked {
		value[6] = []byte{}
	}
	return encoding.Encode(value)
}

// mustStorePath stores an object's ciphertext blob in the backend.
func mustStorePath(ctx context.Context, blobs objectstore.Store, envelope objects.Object) error {
	_, err := blobs.PutObject(ctx, envelope.ObjectID, envelope.VersionID, bytes.NewReader(envelope.Ciphertext), int64(len(envelope.Ciphertext)))
	return err
}

// readAllLimited reads an upload stream honoring its declared length.
func readAllLimited(reader io.Reader, declared, absolute int64) ([]byte, error) {
	if declared < 0 || declared > absolute {
		return nil, errors.New("invalid upload length")
	}
	data, err := io.ReadAll(io.LimitReader(reader, declared+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != declared {
		return nil, errors.New("upload length mismatch")
	}
	return data, nil
}

// recordEnvelope rebuilds the complete object envelope of a stored record,
// splicing the blob bytes into the wire for blob-backed records.
func (s *Server) recordEnvelope(ctx context.Context, record ObjectRecord) (objects.Object, error) {
	var decoded any
	if err := encoding.Decode(record.Wire, &decoded); err != nil {
		return objects.Object{}, err
	}
	fields, err := asUintMap(decoded)
	if err != nil {
		return objects.Object{}, err
	}
	if record.BlobBacked {
		ciphertext, err := s.readBlob(ctx, record.ObjectID, record.VersionID, record.CiphertextLength)
		if err != nil {
			return objects.Object{}, err
		}
		fields[6] = ciphertext
	}
	return objects.Parse(fields)
}

// recordBytes renders the complete envelope bytes of a stored record.
func (s *Server) recordBytes(ctx context.Context, record ObjectRecord) ([]byte, error) {
	if !record.BlobBacked {
		return record.Wire, nil
	}
	envelope, err := s.recordEnvelope(ctx, record)
	if err != nil {
		return nil, err
	}
	return envelope.CanonicalBytes()
}

// readBlob streams the ciphertext of one object version from the backend.
func (s *Server) readBlob(ctx context.Context, objectID, versionID []byte, length int64) ([]byte, error) {
	reader, _, err := s.cfg.Blobs.OpenObject(ctx, objectID, versionID)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, length+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != length {
		return nil, errors.New("stored blob length mismatch")
	}
	return data, nil
}

// handleGetObject serves one object envelope, or a ciphertext byte range for
// media objects (60.6, 35.11).
func (s *Server) handleGetObject(w http.ResponseWriter, r *http.Request) {
	s.limit(w, r, "objects", func() {
		requestID := requestContextID(r)
		objectID, err := s.parsePathID(identifiers.ObjectID, r.PathValue("object_id"))
		if err != nil {
			writeError(w, err, requestID)
			return
		}
		var versionID []byte
		if version := r.URL.Query().Get("version"); version != "" {
			versionID, err = s.parsePathID(identifiers.VersionID, version)
			if err != nil {
				writeError(w, err, requestID)
				return
			}
		}
		record, err := s.cfg.Objects.GetObject(r.Context(), objectID, versionID)
		if err != nil {
			writeError(w, err, requestID)
			return
		}

		envelope, err := s.recordEnvelope(r.Context(), record)
		if err != nil {
			writeError(w, err, requestID)
			return
		}
		if err := s.authorizeObject(r, envelope); err != nil {
			writeError(w, err, requestID)
			return
		}

		w.Header().Set("Accept-Ranges", "bytes")
		rangeHeader := r.Header.Get("Range")
		if rangeHeader == "" || envelope.ObjectType != objects.ObjectTypeMedia {
			body, err := envelope.CanonicalBytes()
			if err != nil {
				writeError(w, err, requestID)
				return
			}
			s.writeBytesCBOR(w, http.StatusOK, body)
			return
		}

		start, length, err := parseByteRange(rangeHeader, record.CiphertextLength)
		if err != nil {
			body, err := envelope.CanonicalBytes()
			if err != nil {
				writeError(w, err, requestID)
				return
			}
			s.writeBytesCBOR(w, http.StatusOK, body)
			return
		}
		ciphertext, err := s.readCiphertext(r.Context(), record, start, length)
		if err != nil {
			writeError(w, err, requestID)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Range", "bytes "+formatInt(int(start))+"-"+formatInt(int(start+length-1))+"/"+formatInt(int(record.CiphertextLength)))
		w.Header().Set("Content-Length", formatInt(int(length)))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(ciphertext)
	})
}

// authorizeObject applies the object authorization of 33.5: a requester may
// read an object when it holds a recipient record. Instance (relay) requests
// are always permitted; they carry no plaintext access.
func (s *Server) authorizeObject(r *http.Request, envelope objects.Object) error {
	auth := requestAuth(r)
	if auth == nil || !auth.Presented {
		return asInvalidRequest(errors.New("authentication required"))
	}
	if len(auth.Account) == 0 {
		return nil
	}
	for _, recipient := range envelope.Recipients {
		if bytes.Equal(recipient.AccountID, auth.Account) {
			return nil
		}
	}
	return errObjectNotAuthorized
}

// readCiphertext streams the ciphertext of a record range, using the blob
// backend when blob-backed.
func (s *Server) readCiphertext(ctx context.Context, record ObjectRecord, start, length int64) ([]byte, error) {
	if record.BlobBacked {
		reader, _, err := s.cfg.Blobs.OpenObjectRange(ctx, record.ObjectID, record.VersionID, start, length)
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		return io.ReadAll(reader)
	}
	envelope, err := s.recordEnvelope(ctx, record)
	if err != nil {
		return nil, err
	}
	end := start + length
	if end > int64(len(envelope.Ciphertext)) {
		end = int64(len(envelope.Ciphertext))
	}
	return envelope.Ciphertext[start:end], nil
}

// parseByteRange handles a single closed "bytes=a-b" range.
func parseByteRange(value string, size int64) (int64, int64, error) {
	if !strings.HasPrefix(value, "bytes=") {
		return 0, 0, errors.New("unsupported range unit")
	}
	spec := strings.TrimPrefix(value, "bytes=")
	if strings.Contains(spec, ",") {
		return 0, 0, errors.New("multi-range requests are unsupported")
	}
	startText, endText, ok := strings.Cut(spec, "-")
	if !ok {
		return 0, 0, errors.New("malformed range")
	}
	if startText == "" {
		return 0, 0, errors.New("suffix ranges are unsupported")
	}
	start, err := strconv.ParseInt(startText, 10, 64)
	if err != nil || start < 0 {
		return 0, 0, errors.New("invalid range start")
	}
	end := size - 1
	if endText != "" {
		end, err = strconv.ParseInt(endText, 10, 64)
		if err != nil || end < start {
			return 0, 0, errors.New("invalid range end")
		}
	}
	if start >= size {
		return 0, 0, errors.New("range start exceeds size")
	}
	if end >= size {
		end = size - 1
	}
	return start, end - start + 1, nil
}
