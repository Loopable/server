package accounts

import (
	"bytes"
	"errors"
)

type DeviceStatus uint8

const (
	DeviceAuthorized DeviceStatus = iota
	DeviceRevoked
	DeviceSuperseded
)

// Device kinds per protospec/spec/12-devices.md section 12.5.
const (
	DeviceKindClient  uint64 = 0
	DeviceKindBackup  uint64 = 1
	DeviceKindService uint64 = 2
)

type DeviceState struct {
	ID            []byte
	SigningKey    []byte
	EncryptionKey []byte
	Kind          uint64
	Status        DeviceStatus
}

// AuthorizationIndex is derived from signed account events. It does not mint
// device bindings or contain private key material.
type AuthorizationIndex struct {
	Devices       map[string]DeviceState
	TrustedDevice []byte
}

func NewAuthorizationIndex() *AuthorizationIndex {
	return &AuthorizationIndex{Devices: make(map[string]DeviceState)}
}

func (i *AuthorizationIndex) SeedFirstDevice(device DeviceState) error {
	if len(i.Devices) != 0 || len(i.TrustedDevice) != 0 {
		return errors.New("account already has a first device")
	}
	if err := validateDevice(device); err != nil {
		return err
	}
	i.Devices[string(device.ID)] = cloneDevice(device)
	i.TrustedDevice = append([]byte(nil), device.ID...)
	return nil
}

func (i *AuthorizationIndex) Authorize(device DeviceState) error {
	if err := validateDevice(device); err != nil {
		return err
	}
	if existing, ok := i.Devices[string(device.ID)]; ok {
		if !bytes.Equal(existing.SigningKey, device.SigningKey) || !bytes.Equal(existing.EncryptionKey, device.EncryptionKey) {
			return errors.New("device binding conflicts")
		}
		return nil
	}
	i.Devices[string(device.ID)] = cloneDevice(device)
	return nil
}

func (i *AuthorizationIndex) Revoke(deviceID []byte) error {
	device, ok := i.Devices[string(deviceID)]
	if !ok {
		return errors.New("device is not authorized")
	}
	if bytes.Equal(i.TrustedDevice, deviceID) {
		return errors.New("trusted device cannot be revoked")
	}
	if device.Status != DeviceAuthorized {
		return errors.New("device is not active")
	}
	device.Status = DeviceRevoked
	i.Devices[string(deviceID)] = device
	return nil
}

func (i *AuthorizationIndex) TransferTrust(newDeviceID []byte) error {
	newDevice, ok := i.Devices[string(newDeviceID)]
	if !ok || newDevice.Status != DeviceAuthorized {
		return errors.New("new trusted device is not authorized")
	}
	if newDevice.Kind == DeviceKindBackup {
		return errors.New("backup device cannot be the trusted device")
	}
	if len(i.TrustedDevice) == 0 {
		return errors.New("trusted device is not established")
	}
	old := i.Devices[string(i.TrustedDevice)]
	if !bytes.Equal(old.ID, newDeviceID) {
		old.Status = DeviceSuperseded
		i.Devices[string(old.ID)] = old
	}
	i.TrustedDevice = append([]byte(nil), newDeviceID...)
	return nil
}

func (i *AuthorizationIndex) CanSign(deviceID []byte) bool {
	device, ok := i.Devices[string(deviceID)]
	return ok && device.Status == DeviceAuthorized
}

func validateDevice(device DeviceState) error {
	if len(device.ID) != 16 || len(device.SigningKey) != 32 || len(device.EncryptionKey) != 32 {
		return errors.New("invalid device binding")
	}
	return nil
}

func cloneDevice(device DeviceState) DeviceState {
	device.ID = append([]byte(nil), device.ID...)
	device.SigningKey = append([]byte(nil), device.SigningKey...)
	device.EncryptionKey = append([]byte(nil), device.EncryptionKey...)
	return device
}
