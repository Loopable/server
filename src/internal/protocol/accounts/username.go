package accounts

import (
	"errors"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

var ErrInvalidUsername = errors.New("invalid username")

// CanonicalUsername normalizes and validates a protocol username.
func CanonicalUsername(value string) (string, error) {
	value = norm.NFC.String(value)
	value = cases.Fold().String(value)
	if len(value) < 4 || len(value) > 14 {
		return "", ErrInvalidUsername
	}
	if value != strings.ToLower(value) {
		return "", ErrInvalidUsername
	}
	for i := 0; i < len(value); i++ {
		character := value[i]
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_' {
			continue
		}
		return "", ErrInvalidUsername
	}
	if value[0] == '_' || value[len(value)-1] == '_' {
		return "", ErrInvalidUsername
	}
	for i := 0; i < len(value); i++ {
		if value[i] >= 'a' && value[i] <= 'z' {
			return value, nil
		}
	}
	return "", ErrInvalidUsername
}
