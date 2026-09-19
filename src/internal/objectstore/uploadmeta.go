package objectstore

import (
	"encoding/json"
	"time"
)

// uploadMeta is the durable state of a resumable upload, stored as an opaque
// sidecar next to the uploaded bytes. It never carries ciphertext.
type uploadMeta struct {
	UploadID  string    `json:"upload_id"`
	Owner     []byte    `json:"owner"`
	Length    int64     `json:"length"`
	Offset    int64     `json:"offset"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (m uploadMeta) upload() Upload {
	return Upload{
		UploadID:  []byte(m.UploadID),
		Owner:     m.Owner,
		Length:    m.Length,
		Offset:    m.Offset,
		Complete:  m.Offset == m.Length && m.Length != 0,
		CreatedAt: m.CreatedAt,
		UpdatedAt: m.UpdatedAt,
	}
}

func encodeUploadMeta(meta uploadMeta) ([]byte, error) {
	return json.Marshal(&meta)
}

func decodeUploadMeta(data []byte) (uploadMeta, error) {
	var meta uploadMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return uploadMeta{}, err
	}
	return meta, nil
}
