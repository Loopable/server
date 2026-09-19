// Package encoding implements Loopable's deterministic CBOR representation.
//
// The rules in this package correspond to protospec/spec/30-serialization.md
// and protospec/spec/31-wire-types.md.
package encoding

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/fxamacker/cbor/v2"
)

var (
	encodeMode cbor.EncMode
	decodeMode cbor.DecMode
)

func init() {
	options := cbor.CanonicalEncOptions()
	options.IndefLength = cbor.IndefLengthForbidden
	options.TagsMd = cbor.TagsForbidden
	var err error
	encodeMode, err = options.EncMode()
	if err != nil {
		panic(fmt.Sprintf("create canonical CBOR encoder: %v", err))
	}

	decodeMode, err = (cbor.DecOptions{
		DupMapKey:   cbor.DupMapKeyEnforcedAPF,
		IndefLength: cbor.IndefLengthForbidden,
		TagsMd:      cbor.TagsForbidden,
	}).DecMode()
	if err != nil {
		panic(fmt.Sprintf("create strict CBOR decoder: %v", err))
	}
}

// Encode returns the canonical CBOR representation of value.
func Encode(value any) ([]byte, error) {
	return encodeMode.Marshal(value)
}

// Decode validates a complete canonical CBOR item and decodes it into value.
// It rejects duplicate keys, indefinite-length items, tags, non-canonical
// encodings, negative integers, floating-point values, null, and undefined.
func Decode(data []byte, value any) error {
	if err := validate(data); err != nil {
		return err
	}
	if err := decodeMode.Unmarshal(data, value); err != nil {
		return fmt.Errorf("decode canonical CBOR: %w", err)
	}
	return nil
}

func validate(data []byte) error {
	var decoded any
	if err := decodeMode.Unmarshal(data, &decoded); err != nil {
		return fmt.Errorf("decode canonical CBOR: %w", err)
	}
	if err := validateValue(decoded); err != nil {
		return err
	}

	canonical, err := Encode(decoded)
	if err != nil {
		return fmt.Errorf("re-encode canonical CBOR: %w", err)
	}
	if !bytes.Equal(canonical, data) {
		return errors.New("CBOR is not canonical")
	}
	return nil
}

func validateValue(value any) error {
	switch value := value.(type) {
	case nil:
		return errors.New("null and undefined are not protocol values")
	case int64:
		if value < 0 {
			return errors.New("negative integers are not protocol values")
		}
	case float32, float64:
		return errors.New("floating-point values are not protocol values")
	case cbor.SimpleValue:
		return fmt.Errorf("unsupported CBOR simple value %d", value)
	case []any:
		for _, item := range value {
			if err := validateValue(item); err != nil {
				return err
			}
		}
	case map[any]any:
		for key, item := range value {
			if err := validateValue(key); err != nil {
				return err
			}
			if err := validateValue(item); err != nil {
				return err
			}
		}
	}
	return nil
}
