package objectstore

import (
	"fmt"

	"loopable.party/server/internal/protocol/identifiers"
)

// objectKey maps an object ID and version ID to the storage key, per 65.10:
// a component derived from the object_id with the version_id as an additional
// component. The base32lower text forms keep keys filesystem- and URL-safe.
func objectKey(objectID, versionID []byte) (string, error) {
	objectText, err := identifiers.String(identifiers.ObjectID, objectID)
	if err != nil {
		return "", fmt.Errorf("object ID: %w", err)
	}
	versionText, err := identifiers.String(identifiers.VersionID, versionID)
	if err != nil {
		return "", fmt.Errorf("version ID: %w", err)
	}
	return "objects/" + objectText + "/" + versionText, nil
}

// objectPrefix returns the storage prefix enumerating every version of an
// object.
func objectPrefix(objectID []byte) (string, error) {
	objectText, err := identifiers.String(identifiers.ObjectID, objectID)
	if err != nil {
		return "", fmt.Errorf("object ID: %w", err)
	}
	return "objects/" + objectText + "/", nil
}

// uploadKey maps an upload ID to its data key.
func uploadKey(uploadID []byte) (string, error) {
	text, err := identifiers.String(identifiers.RequestID, uploadID)
	if err != nil {
		return "", fmt.Errorf("upload ID: %w", err)
	}
	return "uploads/" + text, nil
}

// literalUploadKey maps an upload ID to its metadata key.
func literalUploadKey(uploadID []byte) (string, error) {
	key, err := uploadKey(uploadID)
	if err != nil {
		return "", err
	}
	return key + ".meta", nil
}
