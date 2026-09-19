package authorization

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"

	"loopable.party/server/internal/protocol/accounts"
	"loopable.party/server/internal/protocol/events"
	"loopable.party/server/internal/protocol/identifiers"
)

// validateBodySchema enforces the per-type body and object-reference schema of
// protospec/spec/34-event-types.md section 34.14, including every cross-field
// requirement stated in 34.3 through 34.13.
func validateBodySchema(event events.Event) error {
	if err := validateObjectReferenceCardinality(event); err != nil {
		return err
	}
	switch event.EventType {
	case 0:
		return validateAccountCreatedBody(event)
	case 1:
		return validateDeviceAuthorizedBody(event)
	case 2:
		return validateDeviceRevokedBody(event)
	case 3:
		return validateTrustedDeviceTransferredBody(event)
	case 4:
		return validateUsernameChangedBody(event)
	case 5:
		return validateAccountDeletedBody(event)
	case 6, 7, 8, 9:
		return validateRelationshipBody(event)
	case 12:
		return validateProfileUpdatedBody(event)
	case 13:
		return validateEmptyBody(event)
	case 14:
		return validatePostEditedBody(event)
	case 15:
		return validateEmptyBody(event)
	case 16:
		return validateReplyCreatedBody(event)
	case 17:
		return validateGroupCreatedBody(event)
	case 18:
		return validateGroupIDOnlyBody(event)
	case 19, 20:
		return validateGroupMemberChangeBody(event)
	case 21, 22, 23:
		return validateGroupEpochBody(event)
	case 24:
		return validateMessageCreatedBody(event)
	case 25:
		return validateProfileVisibilityBody(event)
	default:
		return fmt.Errorf("event type %d has no schema", event.EventType)
	}
}

// validateObjectReferenceCardinality enforces the reference counts of 34.10.
func validateObjectReferenceCardinality(event events.Event) error {
	count := len(event.ObjectReferences)
	exactlyOne := func() error {
		if count != 1 {
			return fmt.Errorf("event type %d requires exactly one object reference, got %d", event.EventType, count)
		}
		return nil
	}
	atMostOne := func() error {
		if count > 1 {
			return fmt.Errorf("event type %d allows at most one object reference, got %d", event.EventType, count)
		}
		return nil
	}
	none := func() error {
		if count != 0 {
			return fmt.Errorf("event type %d must not reference objects, got %d", event.EventType, count)
		}
		return nil
	}
	switch event.EventType {
	case 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 17, 18, 19, 20, 22, 25:
		return none()
	case 12, 13, 14, 16:
		if err := exactlyOne(); err != nil {
			return err
		}
		if event.ObjectReferences[0].VersionID == nil {
			return fmt.Errorf("event type %d must reference an object version", event.EventType)
		}
		return nil
	case 24:
		return exactlyOne()
	case 15:
		if err := exactlyOne(); err != nil {
			return err
		}
		if event.ObjectReferences[0].VersionID != nil {
			return errors.New("POST_DELETED must reference an object without a version")
		}
		return nil
	case 21, 23:
		return atMostOne()
	}
	return nil
}

func validateAccountCreatedBody(event events.Event) error {
	body := event.Body
	if _, err := requiredText(body, 1); err != nil {
		return err
	}
	if _, err := requiredBytesLength(body, 2, identifiers.LongLength); err != nil {
		return err
	}
	if _, ok := body[0]; !ok {
		return errors.New("body field 0 identity_public_key is required")
	}
	if _, ok := body[3]; !ok {
		return errors.New("body field 3 first_device_authorization is required")
	}
	return noUnexpectedFields(body, 0, 1, 2, 3)
}

func validateDeviceAuthorizedBody(event events.Event) error {
	if _, err := requiredBytesLength(event.Body, 0, identifiers.ShortLength); err != nil {
		return err
	}
	if _, err := requiredBytesLength(event.Body, 1, ed25519PublicKeySize); err != nil {
		return err
	}
	if _, err := requiredBytesLength(event.Body, 2, ed25519PublicKeySize); err != nil {
		return err
	}
	kind, err := requiredUint(event.Body, 3)
	if err != nil {
		return err
	}
	if kind != accounts.DeviceKindClient && kind != accounts.DeviceKindBackup && kind != accounts.DeviceKindService {
		return fmt.Errorf("body field 3 device_kind %d is unknown", kind)
	}
	if _, ok := event.Body[4]; ok {
		if _, err := optionalText(event.Body, 4); err != nil {
			return err
		}
	}
	return noUnexpectedFields(event.Body, 0, 1, 2, 3, 4)
}

func validateDeviceRevokedBody(event events.Event) error {
	if _, err := requiredBytesLength(event.Body, 0, identifiers.ShortLength); err != nil {
		return err
	}
	if _, ok := event.Body[1]; ok {
		if _, err := optionalUint(event.Body, 1); err != nil {
			return err
		}
	}
	return noUnexpectedFields(event.Body, 0, 1)
}

func validateTrustedDeviceTransferredBody(event events.Event) error {
	if _, err := requiredBytesLength(event.Body, 0, identifiers.ShortLength); err != nil {
		return err
	}
	return noUnexpectedFields(event.Body, 0)
}

func validateUsernameChangedBody(event events.Event) error {
	if _, err := requiredText(event.Body, 0); err != nil {
		return err
	}
	if _, err := requiredText(event.Body, 1); err != nil {
		return err
	}
	return noUnexpectedFields(event.Body, 0, 1)
}

func validateAccountDeletedBody(event events.Event) error {
	if _, ok := event.Body[0]; ok {
		if _, err := optionalUint(event.Body, 0); err != nil {
			return err
		}
	}
	return noUnexpectedFields(event.Body, 0)
}

// validateRelationshipBody enforces 34.9: the target is another account.
func validateRelationshipBody(event events.Event) error {
	target, err := requiredBytesLength(event.Body, 0, identifiers.LongLength)
	if err != nil {
		return err
	}
	if bytes.Equal(target, event.AccountID) {
		return errors.New("relationship event must not target the account itself")
	}
	return noUnexpectedFields(event.Body, 0)
}

// validateProfileUpdatedBody enforces 51.5: the body is empty for private
// accounts or carries only the plaintext public profile card.
func validateProfileUpdatedBody(event events.Event) error {
	for key := range event.Body {
		if key > 2 {
			return fmt.Errorf("profile event body field %d is not part of the public profile card", key)
		}
		if _, err := optionalText(event.Body, key); err != nil {
			return err
		}
	}
	reference := event.ObjectReferences[0]
	if reference.VersionID == nil {
		return errors.New("PROFILE_UPDATED must reference a profile version")
	}
	return nil
}

func validateEmptyBody(event events.Event) error {
	if len(event.Body) != 0 {
		return errors.New("event body must be empty")
	}
	return nil
}

func validatePostEditedBody(event events.Event) error {
	if _, err := requiredBytesLength(event.Body, 0, identifiers.LongLength); err != nil {
		return err
	}
	if err := noUnexpectedFields(event.Body, 0); err != nil {
		return err
	}
	if event.ObjectReferences[0].VersionID == nil {
		return errors.New("POST_EDITED must reference the new post version")
	}
	return nil
}

func validateReplyCreatedBody(event events.Event) error {
	if parentValue, ok := event.Body[0]; ok {
		if err := validateObjectReferenceValue(0, parentValue); err != nil {
			return err
		}
	}
	if err := noUnexpectedFields(event.Body, 0); err != nil {
		return err
	}
	if event.ObjectReferences[0].VersionID == nil {
		return errors.New("REPLY_CREATED must reference a reply version")
	}
	return nil
}

func validateGroupCreatedBody(event events.Event) error {
	if _, err := requiredBytesLength(event.Body, 0, identifiers.ShortLength); err != nil {
		return err
	}
	if nameValue, ok := event.Body[1]; ok {
		if err := validateObjectReferenceValue(1, nameValue); err != nil {
			return err
		}
	}
	return noUnexpectedFields(event.Body, 0, 1)
}

func validateGroupIDOnlyBody(event events.Event) error {
	if _, err := requiredBytesLength(event.Body, 0, identifiers.ShortLength); err != nil {
		return err
	}
	return noUnexpectedFields(event.Body, 0)
}

func validateGroupMemberChangeBody(event events.Event) error {
	if _, err := requiredBytesLength(event.Body, 0, identifiers.ShortLength); err != nil {
		return err
	}
	if _, err := requiredUint(event.Body, 1); err != nil {
		return err
	}
	if _, err := requiredBytesLength(event.Body, 2, identifiers.LongLength); err != nil {
		return err
	}
	if _, ok := event.Body[3]; ok {
		if _, err := requiredBytesLength(event.Body, 3, identifiers.ShortLength); err != nil {
			return err
		}
	}
	return noUnexpectedFields(event.Body, 0, 1, 2, 3)
}

func validateGroupEpochBody(event events.Event) error {
	if _, err := requiredBytesLength(event.Body, 0, identifiers.ShortLength); err != nil {
		return err
	}
	if _, err := requiredUint(event.Body, 1); err != nil {
		return err
	}
	return noUnexpectedFields(event.Body, 0, 1)
}

func validateMessageCreatedBody(event events.Event) error {
	if _, ok := event.Body[0]; ok {
		if _, err := requiredBytesLength(event.Body, 0, identifiers.ShortLength); err != nil {
			return err
		}
	}
	return noUnexpectedFields(event.Body, 0)
}

func validateProfileVisibilityBody(event events.Event) error {
	value, ok := event.Body[0]
	if !ok {
		return errors.New("body field 0 profile_is_public is required")
	}
	if _, ok := value.(bool); !ok {
		return errors.New("body field 0 profile_is_public must be a boolean")
	}
	return noUnexpectedFields(event.Body, 0)
}

func validateObjectReferenceValue(key uint64, value any) error {
	fields, ok := value.(map[uint64]any)
	if !ok {
		return fmt.Errorf("body field %d must be an object reference map", key)
	}
	if _, err := requiredBytesLength(fields, 0, identifiers.LongLength); err != nil {
		return fmt.Errorf("body field %d: %w", key, err)
	}
	if versionValue, ok := fields[1]; ok {
		if _, err := requiredBytesLength(map[uint64]any{1: versionValue}, 1, identifiers.LongLength); err != nil {
			return fmt.Errorf("body field %d: %w", key, err)
		}
	}
	if len(fields) > 2 {
		return fmt.Errorf("body field %d has unexpected sub-fields", key)
	}
	return nil
}

func requiredBytesLength(body map[uint64]any, key uint64, length int) ([]byte, error) {
	value, ok := body[key]
	if !ok {
		return nil, fmt.Errorf("body field %d is required", key)
	}
	var buffer []byte
	switch typed := value.(type) {
	case []byte:
		buffer = typed
	case ed25519.PublicKey:
		buffer = []byte(typed)
	default:
		return nil, fmt.Errorf("body field %d must be bytes", key)
	}
	if len(buffer) != length {
		return nil, fmt.Errorf("body field %d must be %d bytes", key, length)
	}
	return buffer, nil
}

func requiredUint(body map[uint64]any, key uint64) (uint64, error) {
	value, ok := body[key]
	if !ok {
		return 0, fmt.Errorf("body field %d is required", key)
	}
	number, ok := value.(uint64)
	if !ok {
		return 0, fmt.Errorf("body field %d must be an unsigned integer", key)
	}
	return number, nil
}

func optionalUint(body map[uint64]any, key uint64) (uint64, error) {
	return requiredUint(body, key)
}

func requiredText(body map[uint64]any, key uint64) (string, error) {
	text, err := optionalText(body, key)
	if err != nil {
		return "", err
	}
	if text == "" {
		return "", fmt.Errorf("body field %d must not be empty", key)
	}
	return text, nil
}

func optionalText(body map[uint64]any, key uint64) (string, error) {
	value, ok := body[key]
	if !ok {
		return "", nil
	}
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("body field %d must be text", key)
	}
	return text, nil
}

func noUnexpectedFields(body map[uint64]any, expected ...uint64) error {
	seen := make(map[uint64]bool, len(expected))
	for _, key := range expected {
		seen[key] = true
	}
	for key := range body {
		if !seen[key] {
			return fmt.Errorf("unexpected body field %d", key)
		}
	}
	return nil
}

const ed25519PublicKeySize = 32
