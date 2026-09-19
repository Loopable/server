package federation

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// CanonicalPath applies the path canonicalization rules of section 61.6.
func CanonicalPath(path string) (string, error) {
	if path == "" || path[0] != '/' || strings.IndexByte(path, 0) >= 0 {
		return "", errors.New("path must begin with / and contain no NUL")
	}
	parts := strings.Split(path, "/")
	for i, part := range parts {
		decoded, err := decodeUnreserved(part)
		if err != nil {
			return "", fmt.Errorf("canonicalize path segment %d: %w", i, err)
		}
		if decoded == "." || decoded == ".." || strings.IndexByte(decoded, 0) >= 0 {
			return "", errors.New("path contains prohibited segment")
		}
		parts[i] = encodeUnreserved(decoded)
	}
	return strings.Join(parts, "/"), nil
}

// CanonicalQuery applies the query canonicalization rules of section 61.6.
func CanonicalQuery(query string) (string, error) {
	if query == "" {
		return "", nil
	}
	type pair struct{ name, value string }
	pairs := make([]pair, 0, strings.Count(query, "&")+1)
	for _, item := range strings.Split(query, "&") {
		name, value, found := strings.Cut(item, "=")
		if !found {
			value = ""
		}
		canonicalName, err := canonicalQueryPart(name)
		if err != nil {
			return "", err
		}
		canonicalValue, err := canonicalQueryPart(value)
		if err != nil {
			return "", err
		}
		pairs = append(pairs, pair{name: canonicalName, value: canonicalValue})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].name != pairs[j].name {
			return pairs[i].name < pairs[j].name
		}
		return pairs[i].value < pairs[j].value
	})
	result := make([]string, len(pairs))
	for i, item := range pairs {
		result[i] = item.name + "=" + item.value
	}
	return strings.Join(result, "&"), nil
}

func canonicalQueryPart(value string) (string, error) {
	if strings.IndexByte(value, 0) >= 0 {
		return "", errors.New("query contains NUL")
	}
	decoded, err := decodeUnreserved(value)
	if err != nil {
		return "", fmt.Errorf("canonicalize query component: %w", err)
	}
	return encodeUnreserved(decoded), nil
}

func decodeUnreserved(value string) (string, error) {
	result := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		if value[i] != '%' {
			result = append(result, value[i])
			continue
		}
		if i+2 >= len(value) {
			return "", errors.New("malformed percent escape")
		}
		hi, okHigh := hex(value[i+1])
		lo, okLow := hex(value[i+2])
		if !okHigh || !okLow {
			return "", errors.New("malformed percent escape")
		}
		decoded := hi<<4 | lo
		if isUnreserved(decoded) {
			result = append(result, decoded)
		} else {
			result = append(result, '%', lowerHex(hi), lowerHex(lo))
		}
		i += 2
	}
	return string(result), nil
}

func encodeUnreserved(value string) string {
	const hexDigits = "0123456789abcdef"
	result := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		if value[i] == '%' && i+2 < len(value) {
			hi, okHigh := hex(value[i+1])
			lo, okLow := hex(value[i+2])
			if okHigh && okLow {
				result = append(result, '%', lowerHex(hi), lowerHex(lo))
				i += 2
				continue
			}
		}
		if isUnreserved(value[i]) {
			result = append(result, value[i])
		} else {
			result = append(result, '%', hexDigits[value[i]>>4], hexDigits[value[i]&15])
		}
	}
	return string(result)
}

func isUnreserved(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' || value >= '0' && value <= '9' || value == '-' || value == '.' || value == '_' || value == '~'
}

func hex(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	default:
		return 0, false
	}
}

func lowerHex(value byte) byte {
	if value < 10 {
		return '0' + value
	}
	return 'a' + value - 10
}
