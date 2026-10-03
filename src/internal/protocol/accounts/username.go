package accounts

import (
	"errors"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

var ErrInvalidUsername = errors.New("invalid username")

// NormalizeUsername applies the normalization 11.6 requires before a username
// is validated, stored, or compared: Unicode normalization form C, then full
// case folding. It never returns an error, so an account registered before the
// grammar was enforced still yields a name in the only form an instance may
// serve.
func NormalizeUsername(value string) string {
	return cases.Fold().String(norm.NFC.String(value))
}

// CanonicalUsername normalizes and validates a protocol username.
func CanonicalUsername(value string) (string, error) {
	value = NormalizeUsername(value)
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
