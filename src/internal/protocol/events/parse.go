package events

import (
	"errors"
	"fmt"
)

// Parse validates a decoded wire envelope and returns its typed form.
func Parse(value any) (Event, error) {
	fields, err := asFieldMap(value)
	if err != nil {
		return Event{}, err
	}
	version, ok := fields[0].(string)
	if !ok || version != ProtocolVersion {
		return Event{}, errors.New("event envelope protocol version is invalid")
	}
	eventID, err := fieldBytes(fields, 1)
	if err != nil {
		return Event{}, err
	}
	eventType, err := fieldUint(fields, 2)
	if err != nil {
		return Event{}, err
	}
	accountID, err := fieldBytes(fields, 3)
	if err != nil {
		return Event{}, err
	}
	deviceID, err := fieldBytes(fields, 4)
	if err != nil {
		return Event{}, err
	}
	createdAt, err := fieldUint(fields, 5)
	if err != nil {
		return Event{}, err
	}
	predecessors, err := fieldDigestList(fields, 6)
	if err != nil {
		return Event{}, err
	}
	referencesValue, ok := fields[7].([]any)
	if !ok {
		return Event{}, errors.New("event envelope object references must be an array")
	}
	references := make([]ObjectReference, len(referencesValue))
	for i, item := range referencesValue {
		referenceFields, err := asFieldMap(item)
		if err != nil {
			return Event{}, fmt.Errorf("object reference %d is not a map", i)
		}
		objectID, err := fieldBytes(referenceFields, 0)
		if err != nil {
			return Event{}, fmt.Errorf("object reference %d: %w", i, err)
		}
		reference := ObjectReference{ObjectID: objectID}
		if versionValue, ok := referenceFields[1]; ok {
			reference.VersionID, err = fieldBytesValue(1, versionValue)
			if err != nil {
				return Event{}, fmt.Errorf("object reference %d: %w", i, err)
			}
		}
		references[i] = reference
	}
	bodyValue, ok := fields[8]
	if !ok {
		return Event{}, errors.New("event envelope body is required")
	}
	body, err := asFieldMap(normalize(bodyValue))
	if err != nil {
		return Event{}, errors.New("event envelope body must be a map")
	}
	signature, err := fieldBytes(fields, 9)
	if err != nil {
		return Event{}, err
	}
	event := Event{
		EventID:          eventID,
		EventType:        eventType,
		AccountID:        accountID,
		DeviceID:         deviceID,
		CreatedAt:        createdAt,
		Predecessors:     predecessors,
		ObjectReferences: references,
		Body:             body,
		Signature:        signature,
	}
	if err := event.Validate(); err != nil {
		return Event{}, err
	}
	return event, nil
}

func asFieldMap(value any) (map[uint64]any, error) {
	switch value := value.(type) {
	case map[uint64]any:
		return value, nil
	case map[any]any:
		fields := make(map[uint64]any, len(value))
		for key, item := range value {
			id, ok := key.(uint64)
			if !ok {
				return nil, errors.New("map keys must be unsigned integers")
			}
			fields[id] = item
		}
		return fields, nil
	default:
		return nil, errors.New("value must be a map")
	}
}

// normalize converts wire-decoded containers to their canonical forms so
// nested records (for example the map-valued first-device authorization in an
// ACCOUNT_CREATED body) parse without re-encoding. Byte content is untouched.
func normalize(value any) any {
	switch value := value.(type) {
	case map[any]any:
		fields := make(map[uint64]any, len(value))
		for key, item := range value {
			id, ok := key.(uint64)
			if !ok {
				continue
			}
			fields[id] = normalize(item)
		}
		return fields
	case map[uint64]any:
		fields := make(map[uint64]any, len(value))
		for key, item := range value {
			fields[key] = normalize(item)
		}
		return fields
	case []any:
		items := make([]any, len(value))
		for i, item := range value {
			items[i] = normalize(item)
		}
		return items
	default:
		return value
	}
}

func fieldBytes(fields map[uint64]any, key uint64) ([]byte, error) {
	value, ok := fields[key]
	if !ok {
		return nil, fmt.Errorf("field %d is required", key)
	}
	return fieldBytesValue(key, value)
}

func fieldBytesValue(key uint64, value any) ([]byte, error) {
	bytes, ok := value.([]byte)
	if !ok {
		return nil, fmt.Errorf("field %d must be bytes", key)
	}
	return append([]byte(nil), bytes...), nil
}

func fieldUint(fields map[uint64]any, key uint64) (uint64, error) {
	value, ok := fields[key]
	if !ok {
		return 0, fmt.Errorf("field %d is required", key)
	}
	integer, ok := value.(uint64)
	if !ok {
		return 0, fmt.Errorf("field %d must be an unsigned integer", key)
	}
	return integer, nil
}

func fieldDigestList(fields map[uint64]any, key uint64) ([][]byte, error) {
	value, ok := fields[key]
	if !ok {
		return nil, fmt.Errorf("field %d is required", key)
	}
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("field %d must be an array", key)
	}
	list := make([][]byte, len(items))
	for i, item := range items {
		digest, ok := item.([]byte)
		if !ok || len(digest) != 16 {
			return nil, fmt.Errorf("field %d item %d must be a 16-byte digest", key, i)
		}
		list[i] = append([]byte(nil), digest...)
	}
	return list, nil
}
