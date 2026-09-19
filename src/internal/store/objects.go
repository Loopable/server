package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

var (
	ErrObjectNotFound  = errors.New("object not found")
	ErrObjectCollision = errors.New("object ID already associated with different bytes")
)

// StoredObject is an object registry row. Wire is the canonical envelope with
// ciphertext zeroed when the blob lives in the object store backend
// (BlobBacked); otherwise it is the complete envelope bytes.
type StoredObject struct {
	Seq              uint64
	ObjectID         []byte
	ObjectType       uint64
	EncryptionSuite  uint64
	VersionID        []byte
	BlobBacked       bool
	CiphertextLength int64
	Wire             []byte
}

// PutObject registers an object envelope immutably. Re-submitting identical
// bytes for the same (object_id, version_id) is idempotent; distinct bytes
// yield ErrObjectCollision. The returned sequence orders versions of an object.
func (s *Store) PutObject(ctx context.Context, record StoredObject) (uint64, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO objects (object_id, version_id, object_type, encryption_suite, blob_backed, ciphertext_length, wire)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (object_id, version_id) DO NOTHING
		RETURNING seq
	`, record.ObjectID, record.VersionID, uint32(record.ObjectType), uint32(record.EncryptionSuite), record.BlobBacked, record.CiphertextLength, record.Wire)

	var seq int64
	err := row.Scan(&seq)
	if err == nil {
		return uint64(seq), nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, err
	}
	wires, err := s.objectWires(ctx, record.ObjectID, record.VersionID)
	if err != nil {
		return 0, err
	}
	recordWire := record.Wire
	collides := false
	for _, existing := range wires {
		if !bytes.Equal(existing, recordWire) {
			collides = true
			continue
		}
		seq, err = s.objectSeq(ctx, record.ObjectID, record.VersionID)
		if err != nil {
			return 0, err
		}
		return uint64(seq), nil
	}
	if collides {
		return 0, ErrObjectCollision
	}
	return 0, fmt.Errorf("object row disappeared for %x", record.ObjectID)
}

// GetObject returns the registry row for an object version; a nil versionID
// selects the most recently stored version.
func (s *Store) GetObject(ctx context.Context, objectID, versionID []byte) (StoredObject, error) {
	var seq int64
	var objectType, encryptionSuite int32
	var blobBacked bool
	var ciphertextLength int64
	var wire []byte
	var latestWithSeq int64
	var err error
	if len(versionID) == 0 {
		err = s.pool.QueryRow(ctx, `
			SELECT seq, object_type, encryption_suite, blob_backed, ciphertext_length, wire
			FROM objects
			WHERE object_id = $1
			ORDER BY seq DESC
			LIMIT 1
		`, objectID).Scan(&seq, &objectType, &encryptionSuite, &blobBacked, &ciphertextLength, &wire)
		latestWithSeq = seq
	} else {
		err = s.pool.QueryRow(ctx, `
			SELECT seq, object_type, encryption_suite, blob_backed, ciphertext_length, wire
			FROM objects
			WHERE object_id = $1 AND version_id = $2
		`, objectID, versionID).Scan(&seq, &objectType, &encryptionSuite, &blobBacked, &ciphertextLength, &wire)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredObject{}, ErrObjectNotFound
	}
	if err != nil {
		return StoredObject{}, err
	}
	if len(versionID) == 0 {
		versionID, err = s.objectVersion(ctx, objectID, uint64(latestWithSeq))
		if err != nil {
			return StoredObject{}, err
		}
	}
	return StoredObject{
		Seq:              uint64(seq),
		ObjectID:         objectID,
		ObjectType:       uint64(objectType),
		EncryptionSuite:  uint64(encryptionSuite),
		VersionID:        versionID,
		BlobBacked:       blobBacked,
		CiphertextLength: ciphertextLength,
		Wire:             wire,
	}, nil
}

// HasObject reports whether the object version is registered; a nil versionID
// reports whether any version exists.
func (s *Store) HasObject(ctx context.Context, objectID, versionID []byte) (bool, error) {
	var exists bool
	if len(versionID) == 0 {
		err := s.pool.QueryRow(ctx,
			`SELECT exists(SELECT 1 FROM objects WHERE object_id = $1)`, objectID).Scan(&exists)
		return exists, err
	}
	err := s.pool.QueryRow(ctx,
		`SELECT exists(SELECT 1 FROM objects WHERE object_id = $1 AND version_id = $2)`, objectID, versionID).Scan(&exists)
	return exists, err
}

// ListObjectVersions returns all registered versions of an object, newest first.
func (s *Store) ListObjectVersions(ctx context.Context, objectID []byte) ([]StoredObject, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT seq, version_id, object_type, encryption_suite, blob_backed, ciphertext_length, wire
		FROM objects
		WHERE object_id = $1
		ORDER BY seq DESC
	`, objectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	objects := make([]StoredObject, 0)
	for rows.Next() {
		var seq int64
		var versionID, wire []byte
		var objectType, encryptionSuite int32
		var blobBacked bool
		var ciphertextLength int64
		if err := rows.Scan(&seq, &versionID, &objectType, &encryptionSuite, &blobBacked, &ciphertextLength, &wire); err != nil {
			return nil, err
		}
		objects = append(objects, StoredObject{
			Seq:              uint64(seq),
			ObjectID:         objectID,
			ObjectType:       uint64(objectType),
			EncryptionSuite:  uint64(encryptionSuite),
			VersionID:        versionID,
			BlobBacked:       blobBacked,
			CiphertextLength: ciphertextLength,
			Wire:             wire,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return objects, nil
}

func (s *Store) objectWires(ctx context.Context, objectID, versionID []byte) ([][]byte, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT wire FROM objects WHERE object_id = $1 AND version_id = $2`, objectID, versionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var wires [][]byte
	for rows.Next() {
		var wire []byte
		if err := rows.Scan(&wire); err != nil {
			return nil, err
		}
		wires = append(wires, wire)
	}
	return wires, rows.Err()
}

func (s *Store) objectSeq(ctx context.Context, objectID, versionID []byte) (int64, error) {
	var seq int64
	err := s.pool.QueryRow(ctx,
		`SELECT seq FROM objects WHERE object_id = $1 AND version_id = $2`, objectID, versionID).Scan(&seq)
	return seq, err
}

func (s *Store) objectVersion(ctx context.Context, objectID []byte, seq uint64) ([]byte, error) {
	var versionID []byte
	err := s.pool.QueryRow(ctx,
		`SELECT version_id FROM objects WHERE object_id = $1 AND seq = $2`, objectID, seq).Scan(&versionID)
	return versionID, err
}
