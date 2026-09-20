// Package content validates plaintext object content schemas, per
// protospec/spec/53-contexts-and-membership.md and 55-content.md.
package content

import (
	"errors"
	"fmt"

	"loopable.party/server/internal/protocol/identifiers"
)

var (
	ErrInvalid = errors.New("invalid content")
	ErrEmpty   = errors.New("content is empty")
)

// Role values per 53.5.
const (
	RoleRegular uint64 = 0
	RoleOwner   uint64 = 1
)

// ValidateMembership checks a membership object (object type 6) per 53.5:
// field 0 member_account_id bytes(32), optional field 1 role uint (0 or 1).
func ValidateMembership(body map[uint64]any) error {
	if len(body) == 0 {
		return fmt.Errorf("%w: membership is empty", ErrEmpty)
	}
	if _, err := requiredBytes(body, 0); err != nil {
		return err
	}
	if accountID, err := requiredBytes(body, 0); err != nil {
		return err
	} else if len(accountID) != identifiers.LongLength {
		return fmt.Errorf("%w: member_account_id must be %d bytes", ErrInvalid, identifiers.LongLength)
	}
	if role, ok := body[1]; ok {
		value, err := expectedUint(role)
		if err != nil {
			return err
		}
		if value != RoleRegular && value != RoleOwner {
			return fmt.Errorf("%w: unknown role %d", ErrInvalid, value)
		}
	}
	return noUnexpectedFields(body, 0, 1)
}

// ValidateGroupMetadata checks a group_metadata object (object type 7) per
// 53.6: field 0 name text.
func ValidateGroupMetadata(body map[uint64]any) error {
	if len(body) == 0 {
		return fmt.Errorf("%w: group metadata is empty", ErrEmpty)
	}
	if _, err := requiredText(body, 0); err != nil {
		return err
	}
	return noUnexpectedFields(body, 0)
}

// ValidatePost checks a post object (object type 0) per 55.1: field 0 text,
// optional field 1 attachments array of object_reference, optional field 2
// created_locale text.
func ValidatePost(body map[uint64]any) error {
	if len(body) == 0 {
		return fmt.Errorf("%w: post is empty", ErrEmpty)
	}
	if _, err := requiredText(body, 0); err != nil {
		return err
	}
	if attachments, ok := body[1]; ok {
		if err := validateAttachments(attachments); err != nil {
			return err
		}
	}
	return noUnexpectedFields(body, 0, 1, 2)
}

// ValidateReply checks a reply object (object type 1) per 55.1: field 0 parent
// object_reference, field 1 text, optional field 2 attachments.
func ValidateReply(body map[uint64]any) error {
	if len(body) == 0 {
		return fmt.Errorf("%w: reply is empty", ErrEmpty)
	}
	parent, ok := body[0]
	if !ok {
		return fmt.Errorf("%w: parent reference is required", ErrInvalid)
	}
	if err := validateObjectReference(parent); err != nil {
		return err
	}
	if _, err := requiredText(body, 1); err != nil {
		return err
	}
	if attachments, ok := body[2]; ok {
		if err := validateAttachments(attachments); err != nil {
			return err
		}
	}
	return noUnexpectedFields(body, 0, 1, 2)
}

// ValidateLike checks a like object (object type 10) per 55.10: field 0 target
// object_reference.
func ValidateLike(body map[uint64]any) error {
	if len(body) == 0 {
		return fmt.Errorf("%w: like is empty", ErrEmpty)
	}
	target, ok := body[0]
	if !ok {
		return fmt.Errorf("%w: target reference is required", ErrInvalid)
	}
	if err := validateObjectReference(target); err != nil {
		return err
	}
	return noUnexpectedFields(body, 0)
}

func requiredBytes(body map[uint64]any, key uint64) ([]byte, error) {
	value, ok := body[key]
	if !ok {
		return nil, fmt.Errorf("%w: field %d is required", ErrInvalid, key)
	}
	buffer, ok := value.([]byte)
	if !ok || len(buffer) == 0 {
		return nil, fmt.Errorf("%w: field %d must be bytes", ErrInvalid, key)
	}
	return buffer, nil
}

func requiredText(body map[uint64]any, key uint64) (string, error) {
	value, ok := body[key]
	if !ok {
		return "", fmt.Errorf("%w: field %d is required", ErrInvalid, key)
	}
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%w: field %d must be text", ErrInvalid, key)
	}
	return text, nil
}

func expectedUint(value any) (uint64, error) {
	number, ok := value.(uint64)
	if !ok {
		return 0, fmt.Errorf("%w: expected an unsigned integer", ErrInvalid)
	}
	return number, nil
}

func validateAttachments(value any) error {
	list, ok := value.([]any)
	if !ok && value != nil {
		return fmt.Errorf("%w: attachments must be an array", ErrInvalid)
	}
	for _, item := range list {
		if err := validateObjectReference(item); err != nil {
			return err
		}
	}
	return nil
}

func validateObjectReference(value any) error {
	reference, ok := value.(map[uint64]any)
	if !ok {
		return fmt.Errorf("%w: object_reference must be a map", ErrInvalid)
	}
	if _, err := requiredBytes(reference, 0); err != nil {
		return err
	}
	if objectID, err := requiredBytes(reference, 0); err != nil {
		return err
	} else if len(objectID) != identifiers.LongLength {
		return fmt.Errorf("%w: object_id must be %d bytes", ErrInvalid, identifiers.LongLength)
	}
	if versionID, ok := reference[1]; ok {
		buffer, ok := versionID.([]byte)
		if !ok || len(buffer) != identifiers.LongLength {
			return fmt.Errorf("%w: version_id must be %d bytes", ErrInvalid, identifiers.LongLength)
		}
	}
	return noUnexpectedFields(reference, 0, 1)
}

func noUnexpectedFields(body map[uint64]any, allowed ...uint64) error {
	seen := make(map[uint64]bool, len(body))
	for name := range body {
		seen[name] = true
	}
	for _, name := range allowed {
		delete(seen, name)
	}
	for name := range seen {
		return fmt.Errorf("%w: unexpected field %d", ErrInvalid, name)
	}
	return nil
}
