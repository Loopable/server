// Package sync implements synchronization (62) and event-dependency (63)
// protocol constructs.
package sync

import (
	"errors"
	"fmt"

	"loopable.party/server/internal/protocol/encoding"
	"loopable.party/server/internal/protocol/events"
	"loopable.party/server/internal/protocol/objects"
)

const (
	// DefaultPageSize is the recommended page_size for sync pages, per 62.5.
	DefaultPageSize = 512
	// DefaultObjectBudget bounds the bytes of objects carried in one page, per 62.5.
	DefaultObjectBudget = 8 << 20
)

// Interest is the optional filter of 62.3. Key 0 holds event type codes and
// key 1 object type codes; an empty or absent map means everything the peer
// is permitted to receive.
type Interest struct {
	EventTypes  []uint64
	ObjectTypes []uint64
}

// Wire returns the interest map, omitting empty filters.
func (i Interest) Wire() map[uint64]any {
	if len(i.EventTypes) == 0 && len(i.ObjectTypes) == 0 {
		return nil
	}
	value := map[uint64]any{}
	if len(i.EventTypes) != 0 {
		value[0] = i.EventTypes
	}
	if len(i.ObjectTypes) != 0 {
		value[1] = i.ObjectTypes
	}
	return value
}

// ParseInterest validates and decodes an interest map.
func ParseInterest(value any) (Interest, error) {
	fields, err := asFieldMap(value)
	if err != nil {
		return Interest{}, err
	}
	var interest Interest
	if eventTypes, ok := fields[0]; ok {
		interest.EventTypes, err = fieldUintList(0, eventTypes)
		if err != nil {
			return Interest{}, err
		}
		for _, eventType := range interest.EventTypes {
			if _, err := events.LookupType(eventType); err != nil {
				return Interest{}, fmt.Errorf("interest event type: %w", err)
			}
		}
	}
	if objectTypes, ok := fields[1]; ok {
		interest.ObjectTypes, err = fieldUintList(1, objectTypes)
		if err != nil {
			return Interest{}, err
		}
		for _, objectType := range interest.ObjectTypes {
			if _, err := objects.LookupType(objectType); err != nil {
				return Interest{}, fmt.Errorf("interest object type: %w", err)
			}
		}
	}
	return interest, nil
}

// Request is the sync request body of 62.2 step 1: an optional cursor and an
// optional interest filter.
type Request struct {
	Cursor   []byte
	Interest *Interest
}

// Wire returns the request map, omitting absent fields.
func (r Request) Wire() map[uint64]any {
	value := map[uint64]any{}
	if len(r.Cursor) != 0 {
		value[0] = r.Cursor
	}
	if r.Interest != nil {
		value[1] = r.Interest.Wire()
	}
	return value
}

// Encode returns the canonical CBOR of the request body.
func (r Request) Encode() ([]byte, error) {
	return encoding.Encode(r.Wire())
}

// ParseRequest validates and decodes a sync request body.
func ParseRequest(data []byte) (Request, error) {
	var decoded any
	if err := encoding.Decode(data, &decoded); err != nil {
		return Request{}, err
	}
	fields, err := asFieldMap(decoded)
	if err != nil {
		return Request{}, err
	}
	request := Request{}
	if cursorValue, ok := fields[0]; ok {
		request.Cursor, err = asBytes(0, cursorValue)
		if err != nil {
			return Request{}, err
		}
	}
	if interestValue, ok := fields[1]; ok {
		interest, err := ParseInterest(interestValue)
		if err != nil {
			return Request{}, err
		}
		request.Interest = &interest
	}
	return request, nil
}

// Page is the sync response body of 62.2 step 2. The cursor is opaque and
// mandatory; events arrive oldest first.
type Page struct {
	Cursor  []byte
	Events  []events.Event
	Objects []objects.Object
	More    bool
}

// Wire returns the page map, omitting empty arrays.
func (p Page) Wire() map[uint64]any {
	eventMaps := make([]any, len(p.Events))
	for i, event := range p.Events {
		eventMaps[i] = event.Wire()
	}
	objectMaps := make([]any, len(p.Objects))
	for i, object := range p.Objects {
		objectMaps[i] = object.Wire()
	}
	value := map[uint64]any{0: p.Cursor}
	if len(eventMaps) != 0 {
		value[1] = eventMaps
	}
	if len(objectMaps) != 0 {
		value[2] = objectMaps
	}
	if p.More {
		value[3] = p.More
	}
	return value
}

// Encode returns the canonical CBOR of the page.
func (p Page) Encode() ([]byte, error) {
	return encoding.Encode(p.Wire())
}

// ParsePage validates and decodes a sync page.
func ParsePage(data []byte) (Page, error) {
	var decoded any
	if err := encoding.Decode(data, &decoded); err != nil {
		return Page{}, err
	}
	fields, err := asFieldMap(decoded)
	if err != nil {
		return Page{}, err
	}
	cursor, err := asBytes(0, fields[0])
	if err != nil {
		return Page{}, err
	}
	var page Page
	page.Cursor = cursor
	if eventValue, ok := fields[1]; ok {
		items, err := asList(1, eventValue)
		if err != nil {
			return Page{}, err
		}
		page.Events = make([]events.Event, len(items))
		for i, item := range items {
			event, err := events.Parse(item)
			if err != nil {
				return Page{}, fmt.Errorf("page event %d: %w", i, err)
			}
			page.Events[i] = event
		}
	}
	if objectValue, ok := fields[2]; ok {
		items, err := asList(2, objectValue)
		if err != nil {
			return Page{}, err
		}
		page.Objects = make([]objects.Object, len(items))
		for i, item := range items {
			object, err := objects.Parse(item)
			if err != nil {
				return Page{}, fmt.Errorf("page object %d: %w", i, err)
			}
			page.Objects[i] = object
		}
	}
	if moreValue, ok := fields[3]; ok {
		more, ok := moreValue.(bool)
		if !ok || !more {
			return Page{}, errors.New("page field 3 must be true when present")
		}
		page.More = true
	}
	return page, nil
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

func asBytes(key uint64, value any) ([]byte, error) {
	bytes, ok := value.([]byte)
	if !ok {
		return nil, fmt.Errorf("field %d must be bytes", key)
	}
	return append([]byte(nil), bytes...), nil
}

func asList(key uint64, value any) ([]any, error) {
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("field %d must be an array", key)
	}
	return items, nil
}

func fieldUintList(key uint64, value any) ([]uint64, error) {
	items, err := asList(key, value)
	if err != nil {
		return nil, err
	}
	list := make([]uint64, len(items))
	for i, item := range items {
		integer, ok := item.(uint64)
		if !ok {
			return nil, fmt.Errorf("field %d item %d must be an unsigned integer", key, i)
		}
		list[i] = integer
	}
	return list, nil
}
