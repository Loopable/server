package events

import "errors"

type AuthorizationLevel uint8

const (
	Genesis AuthorizationLevel = iota
	Trusted
	Authorized
	Member
)

type TypeDefinition struct {
	Code          uint64
	Name          string
	Authorization AuthorizationLevel
}

var typeRegistry = map[uint64]TypeDefinition{
	0: {0, "ACCOUNT_CREATED", Genesis}, 1: {1, "DEVICE_AUTHORIZED", Trusted}, 2: {2, "DEVICE_REVOKED", Trusted}, 3: {3, "TRUSTED_DEVICE_TRANSFERRED", Trusted}, 4: {4, "USERNAME_CHANGED", Trusted}, 5: {5, "ACCOUNT_DELETED", Trusted},
	6: {6, "FOLLOW_CREATED", Authorized}, 7: {7, "FOLLOW_REMOVED", Authorized}, 8: {8, "BLOCK_CREATED", Authorized}, 9: {9, "BLOCK_REMOVED", Authorized},
	12: {12, "PROFILE_UPDATED", Authorized}, 13: {13, "POST_CREATED", Authorized}, 14: {14, "POST_EDITED", Authorized}, 15: {15, "POST_DELETED", Authorized}, 16: {16, "REPLY_CREATED", Authorized},
	17: {17, "GROUP_CREATED", Authorized}, 18: {18, "GROUP_DELETED", Member}, 19: {19, "GROUP_MEMBER_ADDED", Member}, 20: {20, "GROUP_MEMBER_REMOVED", Member}, 21: {21, "GROUP_JOINED", Authorized}, 22: {22, "GROUP_LEFT", Member}, 23: {23, "GROUP_UPDATED", Member}, 24: {24, "MESSAGE_CREATED", Authorized}, 25: {25, "PROFILE_VISIBILITY_SET", Authorized},
}

var ErrUnknownType = errors.New("unknown or retired event type")

func LookupType(code uint64) (TypeDefinition, error) {
	definition, ok := typeRegistry[code]
	if !ok {
		return TypeDefinition{}, ErrUnknownType
	}
	return definition, nil
}
