// Package federation implements federation request authentication.
//
// The signature construction corresponds to protospec/spec/61-federation-authentication.md.
package federation

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"loopable.party/server/internal/protocol/identifiers"
	"loopable.party/server/internal/protocol/signatures"
)

const RequestDomain = "loopable-federation-request-v1\x00"

type RequestAuthentication struct {
	Method    string
	Host      string
	Path      string
	Query     string
	RequestID []byte
	Timestamp uint64
	BodyHash  []byte
}

func (r RequestAuthentication) unsigned() map[uint64]any {
	return map[uint64]any{0: r.Method, 1: r.Host, 2: r.Path, 3: r.Query, 4: r.RequestID, 5: r.Timestamp, 6: r.BodyHash}
}

func HashBody(body []byte) []byte {
	digest := sha256.Sum256(body)
	return digest[:]
}

func SignRequest(privateKey ed25519.PrivateKey, request RequestAuthentication) ([]byte, error) {
	if err := request.Validate(); err != nil {
		return nil, err
	}
	return signatures.Sign(privateKey, RequestDomain, request.unsigned())
}

func VerifyRequest(publicKey ed25519.PublicKey, request RequestAuthentication, signature []byte, now time.Time) error {
	if err := request.Validate(); err != nil {
		return err
	}
	if err := signatures.Verify(publicKey, RequestDomain, request.unsigned(), signature); err != nil {
		return err
	}
	current := uint64(now.Unix())
	if current > request.Timestamp {
		if current-request.Timestamp > 300 {
			return errors.New("federation request is stale")
		}
	} else if request.Timestamp-current > 300 {
		return errors.New("federation request is from the future")
	}
	return nil
}

func (r RequestAuthentication) Validate() error {
	if r.Method == "" || r.Method != strings.ToUpper(r.Method) {
		return errors.New("method must be uppercase and non-empty")
	}
	if r.Host == "" || r.Path == "" || !strings.HasPrefix(r.Path, "/") {
		return errors.New("invalid federation request target")
	}
	if len(r.RequestID) != identifiers.ShortLength {
		return fmt.Errorf("request ID has %d bytes, want %d", len(r.RequestID), identifiers.ShortLength)
	}
	if len(r.BodyHash) != sha256.Size {
		return fmt.Errorf("body hash has %d bytes, want %d", len(r.BodyHash), sha256.Size)
	}
	return nil
}
