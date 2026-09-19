package encoding

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestEncodeCanonicalVectors(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  string
	}{
		{name: "zero", value: uint64(0), want: "00"},
		{name: "twenty-three", value: uint64(23), want: "17"},
		{name: "twenty-four", value: uint64(24), want: "1818"},
		{name: "two-hundred-fifty-five", value: uint64(255), want: "18ff"},
		{name: "two-hundred-fifty-six", value: uint64(256), want: "190100"},
		{name: "sixty-five-thousand-five-hundred-thirty-five", value: uint64(65535), want: "19ffff"},
		{name: "two-to-the-sixteenth", value: uint64(65536), want: "1a00010000"},
		{name: "two-to-the-thirty-second-minus-one", value: uint64(4294967295), want: "1affffffff"},
		{name: "two-to-the-thirty-second", value: uint64(4294967296), want: "1b0000000100000000"},
		{name: "maximum-uint64", value: ^uint64(0), want: "1bffffffffffffffff"},
		{name: "empty-bytes", value: []byte{}, want: "40"},
		{name: "text", value: "hello", want: "6568656c6c6f"},
		{name: "boolean", value: map[uint64]any{1: true}, want: "a101f5"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := Encode(test.value)
			if err != nil {
				t.Fatal(err)
			}
			want, err := hex.DecodeString(test.want)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("Encode() = %x, want %x", got, want)
			}
		})
	}
}

func TestDecodeRejectsNonCanonicalVectors(t *testing.T) {
	tests := map[string]string{
		"duplicate map key":      "a201010102",
		"indefinite text":        "7f616161ff",
		"indefinite bytes":       "5f414261ff",
		"indefinite array":       "9f0102ff",
		"indefinite map":         "bf0101ff",
		"expanded integer":       "1817",
		"expanded large integer": "1a00000100",
		"semantic tag":           "c100",
		"invalid utf8":           "6161c080",
		"negative integer":       "20",
		"null":                   "f6",
		"floating point":         "fa3f800000",
	}

	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(encoded)
			if err != nil {
				t.Fatal(err)
			}
			var value any
			if err := Decode(data, &value); err == nil {
				t.Fatalf("Decode(%x) succeeded, want error", data)
			}
		})
	}
}

func TestDecodeRequiresOneCanonicalItem(t *testing.T) {
	var value any
	if err := Decode([]byte{0x00, 0x00}, &value); err == nil {
		t.Fatal("Decode accepted trailing data")
	}
}

func TestDecodeCanonicalMap(t *testing.T) {
	data, err := hex.DecodeString("a26161830102036162a0")
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := Decode(data, &value); err != nil {
		t.Fatal(err)
	}
}
