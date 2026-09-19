package server

import (
	"errors"
	"fmt"
)

// asUintMap normalizes a decoded CBOR map into map[uint64]any.
func asUintMap(value any) (map[uint64]any, error) {
	switch fields := value.(type) {
	case map[uint64]any:
		return fields, nil
	case map[any]any:
		normalized := make(map[uint64]any, len(fields))
		for key, item := range fields {
			number, ok := key.(uint64)
			if !ok {
				return nil, errors.New("map key is not an unsigned integer")
			}
			normalized[number] = item
		}
		return normalized, nil
	default:
		return nil, errors.New("value is not a map")
	}
}

// firstFieldBytes extracts the bytes of field 1 (an event_id or object_id)
// from a submission for error records when the submission cannot be parsed.
func firstFieldBytes(value any) ([]byte, error) {
	fields, err := asUintMap(value)
	if err != nil {
		return nil, err
	}
	field, ok := fields[1]
	if !ok {
		return nil, errors.New("submission has no identifier field")
	}
	id, ok := field.([]byte)
	if !ok {
		return nil, errors.New("submission identifier is not bytes")
	}
	return append([]byte(nil), id...), nil
}

// fieldUintKeyBytes reads an array of byte arrays from a request map key.
func fieldUintKeyBytes(fields map[uint64]any, key uint64) ([][]byte, error) {
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
		buffer, ok := item.([]byte)
		if !ok {
			return nil, fmt.Errorf("field %d item %d must be bytes", key, i)
		}
		list[i] = append([]byte(nil), buffer...)
	}
	return list, nil
}
