// Package federation implements federation request authentication.
//
// The signature construction corresponds to protospec/spec/61-federation-authentication.md.
package federation

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"loopable.party/server/internal/protocol/identifiers"
	"loopable.party/server/internal/protocol/signatures"
)

const RequestDomain = "loopable-federation-request-v1\x00"

type Authorization struct {
	InstanceID []byte
	KeyID      []byte
	RequestID  []byte
	Timestamp  uint64
	Signature  []byte
}

func (a Authorization) HeaderValue() (string, error) {
	instance, err := identifiers.String(identifiers.InstanceID, a.InstanceID)
	if err != nil {
		return "", err
	}
	key, err := identifiers.String(identifiers.KeyID, a.KeyID)
	if err != nil {
		return "", err
	}
	request, err := identifiers.String(identifiers.RequestID, a.RequestID)
	if err != nil {
		return "", err
	}
	if len(a.Signature) != ed25519.SignatureSize {
		return "", errors.New("invalid authorization signature")
	}
	return "Loopable v=1;instance=" + instance + ";key=" + key + ";request=" + request + ";ts=" + strconv.FormatUint(a.Timestamp, 10) + ";sig=" + base64.RawURLEncoding.EncodeToString(a.Signature), nil
}

func ParseAuthorization(value string) (Authorization, error) {
	if !strings.HasPrefix(value, "Loopable ") {
		return Authorization{}, errors.New("invalid authorization scheme")
	}
	parts := strings.Split(value[len("Loopable "):], ";")
	if len(parts) != 6 {
		return Authorization{}, errors.New("invalid authorization parameters")
	}
	values := make(map[string]string, len(parts))
	for _, part := range parts {
		name, parameter, ok := strings.Cut(part, "=")
		if !ok || name == "" || parameter == "" {
			return Authorization{}, errors.New("invalid authorization parameter")
		}
		if _, exists := values[name]; exists {
			return Authorization{}, errors.New("duplicate authorization parameter")
		}
		values[name] = parameter
	}
	if values["v"] != "1" {
		return Authorization{}, errors.New("unsupported authorization version")
	}
	instanceID, err := identifiers.Parse(identifiers.InstanceID, values["instance"])
	if err != nil {
		return Authorization{}, err
	}
	keyID, err := identifiers.Parse(identifiers.KeyID, values["key"])
	if err != nil {
		return Authorization{}, err
	}
	requestID, err := identifiers.Parse(identifiers.RequestID, values["request"])
	if err != nil {
		return Authorization{}, err
	}
	timestamp, err := strconv.ParseUint(values["ts"], 10, 64)
	if err != nil {
		return Authorization{}, errors.New("invalid authorization timestamp")
	}
	signature, err := base64.RawURLEncoding.DecodeString(values["sig"])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Authorization{}, errors.New("invalid authorization signature")
	}
	return Authorization{InstanceID: instanceID, KeyID: keyID, RequestID: requestID, Timestamp: timestamp, Signature: signature}, nil
}

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
