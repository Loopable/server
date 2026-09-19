package server

import (
	"bytes"
	"errors"
	"net/http"
	"strconv"

	"loopable.party/server/internal/objectstore"
	"loopable.party/server/internal/protocol/identifiers"
)

// handleMediaCreate creates a resumable media upload (tus creation, 35.10
// step 2). Account-authenticated only; Upload-Length fixes the final size.
func (s *Server) handleMediaCreate(w http.ResponseWriter, r *http.Request) {
	s.limit(w, r, "media", func() {
		requestID := requestContextID(r)
		auth := requestAuth(r)
		if auth == nil || len(auth.Account) == 0 {
			writeError(w, asInvalidRequest(errors.New("media upload requires account authentication")), requestID)
			return
		}
		lengthText := r.Header.Get("Upload-Length")
		if lengthText == "" {
			writeError(w, asInvalidRequest(errors.New("Upload-Length is required")), requestID)
			return
		}
		length, err := strconv.ParseInt(lengthText, 10, 64)
		if err != nil || length <= 0 || length > s.cfg.MediaPlaintextLimit {
			writeError(w, asInvalidRequest(errors.New("Upload-Length is outside the media limit")), requestID)
			return
		}
		uploadID, err := identifiers.Random(identifiers.RequestID)
		if err != nil {
			writeError(w, err, requestID)
			return
		}
		if err := s.cfg.Blobs.CreateUpload(r.Context(), uploadID, auth.Account, length); err != nil {
			writeError(w, err, requestID)
			return
		}
		location, err := identifiers.String(identifiers.RequestID, uploadID)
		if err != nil {
			writeError(w, err, requestID)
			return
		}
		w.Header().Set("Location", "/v1/media/uploads/"+location)
		w.Header().Set("Upload-Offset", "0")
		w.Header().Set("Upload-Length", lengthText)
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusCreated)
	})
}

// handleMediaAppend appends ciphertext bytes to a resumable upload (tus PATCH,
// 35.10 step 3). The body is already buffered and hashed for authentication.
func (s *Server) handleMediaAppend(w http.ResponseWriter, r *http.Request) {
	s.limit(w, r, "media", func() {
		requestID := requestContextID(r)
		auth := requestAuth(r)
		if auth == nil || len(auth.Account) == 0 {
			writeError(w, asInvalidRequest(errors.New("media upload requires account authentication")), requestID)
			return
		}
		uploadID, err := s.parsePathID(identifiers.RequestID, r.PathValue("upload_id"))
		if err != nil {
			writeError(w, err, requestID)
			return
		}
		info, err := s.cfg.Blobs.UploadInfo(r.Context(), uploadID)
		if err != nil {
			if errors.Is(err, objectstore.ErrUploadNotFound) {
				writeError(w, err, requestID)
			} else {
				writeError(w, err, requestID)
			}
			return
		}
		if !bytes.Equal(info.Owner, auth.Account) {
			writeError(w, objectstore.ErrUploadNotFound, requestID)
			return
		}
		if info.Complete {
			http.Error(w, "upload already complete", http.StatusForbidden)
			return
		}
		if contentType := r.Header.Get("Content-Type"); contentType != "application/offset+octet-stream" {
			http.Error(w, "unsupported content type", http.StatusUnsupportedMediaType)
			return
		}
		if offset := r.Header.Get("Upload-Offset"); offset != formatInt(int(info.Offset)) {
			http.Error(w, "upload offset mismatch", http.StatusConflict)
			return
		}

		offset, err := s.cfg.Blobs.AppendUpload(r.Context(), uploadID, bytes.NewReader(requestBody(r)))
		if err != nil {
			writeError(w, err, requestID)
			return
		}
		w.Header().Set("Upload-Offset", formatInt(int(offset)))
		w.Header().Set("Upload-Length", formatInt(int(info.Length)))
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	})
}

// handleMediaStatus reports upload offset and status (tus HEAD).
func (s *Server) handleMediaStatus(w http.ResponseWriter, r *http.Request) {
	s.limit(w, r, "media", func() {
		requestID := requestContextID(r)
		auth := requestAuth(r)
		if auth == nil || len(auth.Account) == 0 {
			writeError(w, asInvalidRequest(errors.New("media upload requires account authentication")), requestID)
			return
		}
		uploadID, err := s.parsePathID(identifiers.RequestID, r.PathValue("upload_id"))
		if err != nil {
			writeError(w, err, requestID)
			return
		}
		info, err := s.cfg.Blobs.UploadInfo(r.Context(), uploadID)
		if err != nil {
			writeError(w, err, requestID)
			return
		}
		if !bytes.Equal(info.Owner, auth.Account) {
			writeError(w, objectstore.ErrUploadNotFound, requestID)
			return
		}
		w.Header().Set("Upload-Offset", formatInt(int(info.Offset)))
		w.Header().Set("Upload-Length", formatInt(int(info.Length)))
		w.Header().Set("Upload-Complete", boolText(info.Complete))
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
	})
}

func boolText(value bool) string {
	if value {
		return "1"
	}
	return "0"
}
