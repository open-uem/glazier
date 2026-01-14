// Copyright 2021 Google LLC
//
// Copyright 2026 Miguel Angel Alvarez Cabrerizo for the following methods
// - Decrypt
// - ChangePassphrase
// - EnableKeyProtectors
// - DisableKeyProtectors
// - GetConversionStatus
// - ProtectKeyWithExternalKey
// - EnableAutoUnlock
// - DisableAutoUnlock
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build windows
// +build windows

// Package bitlocker provides functionality for managing Bitlocker.
package bitlocker

import (
	"fmt"
	"reflect"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"github.com/google/deck"
	winapi "github.com/iamacarpet/go-win64api"
	"github.com/scjalliance/comshim"
)

var (
	// Test Helpers
	funcBackup       = winapi.BackupBitLockerRecoveryKeys
	funcRecoveryInfo = winapi.GetBitLockerRecoveryInfo
)

// BackupToAD backs up Bitlocker recovery keys to Active Directory.
func BackupToAD() error {
	infos, err := funcRecoveryInfo()
	if err != nil {
		return err
	}
	volIDs := []string{}
	for _, i := range infos {
		if i.ConversionStatus != 1 {
			deck.Warningf("Skipping volume %s due to conversion status (%d).", i.DriveLetter, i.ConversionStatus)
			continue
		}
		deck.Infof("Backing up Bitlocker recovery password for drive %q.", i.DriveLetter)
		volIDs = append(volIDs, i.PersistentVolumeID)
	}
	return funcBackup(volIDs)
}

// Volume Type
// https://docs.microsoft.com/en-us/windows/win32/secprov/getencryptionmethod-win32-encryptablevolume
type VolumeType uint32

const (
	VolumeTypeSystem VolumeType = iota
	VolumeTypeFixedDisk
	VolumeTypeRemovable
)

// Encryption Methods
// https://docs.microsoft.com/en-us/windows/win32/secprov/getencryptionmethod-win32-encryptablevolume
type EncryptionMethod int32

const (
	None EncryptionMethod = iota
	AES128WithDiffuser
	AES256WithDiffuser
	AES128
	AES256
	HardwareEncryption
	XtsAES128
	XtsAES256
)

// Encryption Flags
// https://docs.microsoft.com/en-us/windows/win32/secprov/encrypt-win32-encryptablevolume
type EncryptionFlag int32

const (
	EncryptDataOnly    EncryptionFlag = 0x00000001
	EncryptDemandWipe  EncryptionFlag = 0x00000002
	EncryptSynchronous EncryptionFlag = 0x00010000

	// Error Codes
	ERROR_IO_DEVICE                        int32 = -2147023779
	FVE_E_EDRIVE_INCOMPATIBLE_VOLUME       int32 = -2144272206
	FVE_E_NO_TPM_WITH_PASSPHRASE           int32 = -2144272212
	FVE_E_PASSPHRASE_TOO_LONG              int32 = -2144272214
	FVE_E_POLICY_PASSPHRASE_NOT_ALLOWED    int32 = -2144272278
	FVE_E_NOT_DECRYPTED                    int32 = -2144272327
	FVE_E_INVALID_PASSWORD_FORMAT          int32 = -2144272331
	FVE_E_BOOTABLE_CDDVD                   int32 = -2144272336
	FVE_E_PROTECTOR_EXISTS                 int32 = -2144272335
	FVE_E_LOCKED_VOLUME                    int32 = -2144272384
	FVE_E_AUTOUNLOCK_ENABLED               int32 = -2144272343
	FVE_E_NOT_ACTIVATED                    int32 = -2144272376
	FVE_E_OVERLAPPED_UPDATE                int32 = -2144272348
	FVE_E_INVALID_PROTECTOR_TYPE           int32 = -2144272326
	FVE_E_POLICY_INVALID_PASSPHRASE_LENGTH int32 = -2144272256
	FVE_E_POLICY_PASSPHRASE_TOO_SIMPLE     int32 = -2144272255
	FVE_E_KEY_REQUIRED                     int32 = -2144272355
	FVE_E_SECURE_KEY_REQUIRED              int32 = -2144272377
	FVE_E_NOT_DATA_VOLUME                  int32 = -2144272359
	FVE_E_OS_NOT_PROTECTED                 int32 = -2144272352
	FVE_E_VOLUME_BOUND_ALREADY             int32 = -2144272353
	E_INVALIDARG                           int32 = -2147024809
	FVE_E_VOLUME_NOT_BOUND                 int32 = -2144272361
	FVE_E_NOT_ALLOWED_IN_SAFE_MODE         int32 = -2144272320
	FVE_E_FIPS_PREVENTS_PASSPHRASE         int32 = -2144272276
	FVE_E_KEY_PROTECTOR_NOT_SUPPORTED      int32 = -2144272279
	FVE_E_OS_VOLUME_PASSPHRASE_NOT_ALLOWED int32 = -2144272275
	TBS_E_SERVICE_NOT_RUNNING              int32 = -2144845816
	FVE_E_FOREIGN_VOLUME                   int32 = -2144272349
	FVE_E_CANNOT_ENCRYPT_NO_KEY            int32 = -2144272338
)

func errHandler(val int32) error {
	switch val {
	case ERROR_IO_DEVICE:
		return fmt.Errorf("an I/O error has occurred during encryption; the device may need to be reset")
	case FVE_E_EDRIVE_INCOMPATIBLE_VOLUME:
		return fmt.Errorf("the drive specified does not support hardware-based encryption")
	case FVE_E_NO_TPM_WITH_PASSPHRASE:
		return fmt.Errorf("a TPM key protector cannot be added because a password protector exists on the drive")
	case FVE_E_PASSPHRASE_TOO_LONG:
		return fmt.Errorf("the passphrase cannot exceed 256 characters")
	case FVE_E_POLICY_PASSPHRASE_NOT_ALLOWED:
		return fmt.Errorf("Group Policy settings do not permit the creation of a password")
	case FVE_E_NOT_DECRYPTED:
		return fmt.Errorf("the drive must be fully decrypted to complete this operation")
	case FVE_E_INVALID_PASSWORD_FORMAT:
		return fmt.Errorf("the format of the recovery password provided is invalid")
	case FVE_E_BOOTABLE_CDDVD:
		return fmt.Errorf("BitLocker Drive Encryption detected bootable media (CD or DVD) in the computer. " +
			"Remove the media and restart the computer before configuring BitLocker.")
	case FVE_E_NOT_ACTIVATED:
		return fmt.Errorf("BitLocker is not enabled on the volume. Add a key protector to enable BitLocker")
	case FVE_E_NOT_DATA_VOLUME:
		return fmt.Errorf("the method cannot be run for the currently running operating system volume")
	case FVE_E_PROTECTOR_EXISTS:
		return fmt.Errorf("key protector cannot be added; only one key protector of this type is allowed for this drive")
	case FVE_E_CANNOT_ENCRYPT_NO_KEY:
		return fmt.Errorf("BitLocker Drive Encryption cannot encrypt the specified drive because an encryption key is not available. Add a key protector to encrypt this drive")
	default:
		return fmt.Errorf("error code returned during encryption: %d", val)
	}
}

func decryptErrHandler(val int32) error {
	switch val {
	case FVE_E_LOCKED_VOLUME:
		return fmt.Errorf("the volume is locked")
	case FVE_E_AUTOUNLOCK_ENABLED:
		return fmt.Errorf("this volume cannot be decrypted because keys used to automatically unlock data volumes are available. Use ClearAllAutoUnlockKeys to remove these keys")
	default:
		return fmt.Errorf("error code returned during decryption: %d", val)
	}
}

func changePassphraseErrHandler(val int32) error {
	switch val {
	case FVE_E_LOCKED_VOLUME:
		return fmt.Errorf("the volume is already locked by BitLocker Drive Encryption. You must unlock the drive from Control Panel")
	case FVE_E_NOT_ACTIVATED:
		return fmt.Errorf("BitLocker is not enabled on the volume. Add a key protector to enable BitLocker")
	case FVE_E_OVERLAPPED_UPDATE:
		return fmt.Errorf("the control block for the encrypted volume was updated by another thread")
	case FVE_E_INVALID_PROTECTOR_TYPE:
		return fmt.Errorf("The specified key protector is not of the correct type")
	case FVE_E_POLICY_INVALID_PASSPHRASE_LENGTH:
		return fmt.Errorf("the updated passphrase provided does not meet the minimum or maximum length requirements")
	case FVE_E_POLICY_PASSPHRASE_TOO_SIMPLE:
		return fmt.Errorf("the updated passphrase does not meet the complexity requirements set by the administrator in group policy")
	case FVE_E_KEY_REQUIRED:
		return fmt.Errorf("The last key protector for a partially or fully encrypted volume cannot be removed if key protectors are enabled")
	default:
		return fmt.Errorf("error code returned during change passphrase: %d", val)
	}
}

func enableKeyProtectorsErrHandler(val int32) error {
	switch val {
	case FVE_E_LOCKED_VOLUME:
		return fmt.Errorf("the volume is locked")
	case FVE_E_NOT_ACTIVATED:
		return fmt.Errorf("BitLocker is not enabled on the volume. Add a key protector to enable BitLocker")
	default:
		return fmt.Errorf("error code returned during enable key protectors: %d", val)
	}
}

func disableKeyProtectorsErrHandler(val int32) error {
	switch val {
	case FVE_E_SECURE_KEY_REQUIRED:
		return fmt.Errorf("no key protectors exist on the volume")
	case FVE_E_LOCKED_VOLUME:
		return fmt.Errorf("the volume is locked")
	default:
		return fmt.Errorf("error code returned during disable key protectors: %d", val)
	}
}

func enableAutoUnlockErrHandler(val int32) error {
	switch val {
	case E_INVALIDARG:
		return fmt.Errorf("The VolumeKeyProtectorID parameter does not refer to a valid key protector of the type External Key")
	case FVE_E_NOT_ACTIVATED:
		return fmt.Errorf("BitLocker is not enabled on the volume. Add a key protector to enable BitLocker")
	case FVE_E_LOCKED_VOLUME:
		return fmt.Errorf("the volume is locked")
	case FVE_E_NOT_DATA_VOLUME:
		return fmt.Errorf("the method cannot be run for the currently running operating system volume")
	case FVE_E_OS_NOT_PROTECTED:
		return fmt.Errorf("the method cannot be run if the currently running operating system volume is not protected by BitLocker Drive Encryption or does not have encryption in progress")
	case FVE_E_VOLUME_BOUND_ALREADY:
		return fmt.Errorf("automatic unlocking on the volume has previously been enabled")
	default:
		return fmt.Errorf("error code returned during disable key protectors: %d", val)
	}
}

func protectKeyWithNumericalPasswordErrHandler(val int32) error {
	switch val {
	case E_INVALIDARG:
		return fmt.Errorf("the NumericalPassword parameter does not have a valid format")
	case FVE_E_LOCKED_VOLUME:
		return fmt.Errorf("the volume is locked")
	case FVE_E_INVALID_PASSWORD_FORMAT:
		return fmt.Errorf("the NumericalPassword parameter does not have a valid format")
	default:
		return fmt.Errorf("error code returned when protecting with numerical password: %d", val)
	}
}

func protectKeyWithExternalKeyErrHandler(val int32) error {
	switch val {
	case E_INVALIDARG:
		return fmt.Errorf("the ExternalKey parameter is provided but is not an array of size 4")
	case FVE_E_NOT_ACTIVATED:
		return fmt.Errorf("BitLocker is not enabled on the volume. Add a key protector to enable BitLocker")
	case FVE_E_LOCKED_VOLUME:
		return fmt.Errorf("the volume is locked")
	default:
		return fmt.Errorf("error code returned when protecting with external key: %d", val)
	}
}

func protectKeyWithPassphraseErrHandler(val int32) error {
	switch val {
	case FVE_E_NOT_ALLOWED_IN_SAFE_MODE:
		return fmt.Errorf("BitLocker Drive Encryption can only be used for recovery purposes when used in Safe Mode")
	case FVE_E_POLICY_PASSPHRASE_NOT_ALLOWED:
		return fmt.Errorf("Group policy does not permit the creation of a passphrase")
	case FVE_E_FIPS_PREVENTS_PASSPHRASE:
		return fmt.Errorf("the group policy setting that requires FIPS compliance prevented the passphrase from being generated or used")
	case FVE_E_POLICY_INVALID_PASSPHRASE_LENGTH:
		return fmt.Errorf("the passphrase provided does not meet the minimum or maximum length requirements")
	case FVE_E_POLICY_PASSPHRASE_TOO_SIMPLE:
		return fmt.Errorf("the passphrase does not meet the complexity requirements set by the administrator in group policy")
	case FVE_E_LOCKED_VOLUME:
		return fmt.Errorf("the volume is already locked by BitLocker Drive Encryption. You must unlock the drive from Control Panel")
	case FVE_E_OVERLAPPED_UPDATE:
		return fmt.Errorf("the control block for the encrypted volume was updated by another thread")
	case FVE_E_KEY_PROTECTOR_NOT_SUPPORTED:
		return fmt.Errorf("the key protector is not supported by the version of BitLocker Drive Encryption currently on the volume")
	case FVE_E_OS_VOLUME_PASSPHRASE_NOT_ALLOWED:
		return fmt.Errorf("the passphrase cannot be added to the operating system volume")
	case FVE_E_PROTECTOR_EXISTS:
		return fmt.Errorf("the provided key protector already exists on this volume")
	default:
		return fmt.Errorf("error code returned when protecting with passphrase: %d", val)
	}
}

func protectKeyWithTPMErrHandler(val int32) error {
	switch val {
	case FVE_E_LOCKED_VOLUME:
		return fmt.Errorf("the volume is locked")
	case TBS_E_SERVICE_NOT_RUNNING:
		return fmt.Errorf("no compatible TPM is found on this computer")
	case FVE_E_FOREIGN_VOLUME:
		return fmt.Errorf("the TPM cannot secure the volume's encryption key because the volume does not contain the currently running operating system")
	case E_INVALIDARG:
		return fmt.Errorf("the PlatformValidationProfile parameter is provided but its values are not within the known range, or it does not match the Group Policy setting currently in effect")
	case FVE_E_PROTECTOR_EXISTS:
		return fmt.Errorf("a key protector of this type already exists")
	default:
		return fmt.Errorf("error code returned when protecting with TPM: %d", val)
	}
}

func getConversionStatusErrHandler(val int32) error {
	switch val {
	case FVE_E_LOCKED_VOLUME:
		return fmt.Errorf("the volume is locked")
	default:
		return fmt.Errorf("error code returned when getting conversion status: %d", val)
	}
}

func disableAutoUnlockErrHandler(val int32) error {
	switch val {
	case FVE_E_VOLUME_NOT_BOUND:
		return fmt.Errorf("automatic unlocking on the volume is disabled")
	case FVE_E_NOT_ACTIVATED:
		return fmt.Errorf("BitLocker is not enabled on the volume. Add a key protector to enable BitLocker")
	case FVE_E_NOT_DATA_VOLUME:
		return fmt.Errorf("the method cannot be run for the currently running operating system volume")
	default:
		return fmt.Errorf("error code returned when protecting with external key: %d", val)
	}
}

// A Volume tracks an open encryptable volume.
type Volume struct {
	ConversionStatus                 uint32
	DeviceID                         string
	DriveLetter                      string
	EncryptionMethod                 uint32
	IsVolumeInitializedForProtection bool
	PersistentVolumeID               string
	ProtectionStatus                 uint32
	VolumeType                       uint32
	handle                           *ole.IDispatch
	wmiIntf                          *ole.IDispatch
	wmiSvc                           *ole.IDispatch
}

// Status of the encryption or decryption on the volume
type ConversionStatus struct {
	ConversionStatus     int32
	EncryptionPercentage int32
	EncryptionFlags      int32
	WipingStatus         int32
	WipingPercentage     int32
}

// Close frees all resources associated with a volume.
func (v *Volume) Close() {
	v.handle.Release()
	v.wmiIntf.Release()
	v.wmiSvc.Release()
	comshim.Done()
}

// Connect connects to an encryptable volume in order to manage it.
// You must call Close() to release the volume when finished.
//
// Example: bitlocker.Connect("c:")
func Connect(driveLetter string) (Volume, error) {
	comshim.Add(1)
	v := Volume{DriveLetter: driveLetter}

	unknown, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		comshim.Done()
		return v, fmt.Errorf("CreateObject: %w", err)
	}
	defer unknown.Release()
	v.wmiIntf, err = unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		comshim.Done()
		return v, fmt.Errorf("QueryInterface: %w", err)
	}
	serviceRaw, err := oleutil.CallMethod(v.wmiIntf, "ConnectServer", nil, `\\.\ROOT\CIMV2\Security\MicrosoftVolumeEncryption`)
	if err != nil {
		v.Close()
		return v, fmt.Errorf("ConnectServer: %w", err)
	}
	v.wmiSvc = serviceRaw.ToIDispatch()

	raw, err := oleutil.CallMethod(v.wmiSvc, "ExecQuery", "SELECT * FROM Win32_EncryptableVolume WHERE DriveLetter = '"+driveLetter+"'")
	if err != nil {
		v.Close()
		return v, fmt.Errorf("ExecQuery: %w", err)
	}
	result := raw.ToIDispatch()
	defer result.Release()

	itemRaw, err := oleutil.CallMethod(result, "ItemIndex", 0)
	if err != nil {
		v.Close()
		return v, fmt.Errorf("failed to fetch result row while processing BitLocker info: %w", err)
	}
	v.handle = itemRaw.ToIDispatch()

	return v, nil
}

// Encrypt encrypts the volume.
//
// Example: vol.Encrypt(bitlocker.XtsAES256, bitlocker.EncryptDataOnly)
//
// Ref: https://docs.microsoft.com/en-us/windows/win32/secprov/encrypt-win32-encryptablevolume
func (v *Volume) Encrypt(method EncryptionMethod, flags EncryptionFlag) error {
	resultRaw, err := oleutil.CallMethod(v.handle, "Encrypt", int32(method), int32(flags))
	if err != nil {
		return fmt.Errorf("Encrypt(%s): %w", v.DriveLetter, err)
	} else if val, ok := resultRaw.Value().(int32); val != 0 || !ok {
		return fmt.Errorf("Encrypt(%s): %w", v.DriveLetter, errHandler(val))
	}

	return nil
}

// Decrypt encrypts the volume.
//
// Example: vol.Decrypt()
//
// Ref: https://docs.microsoft.com/en-us/windows/win32/secprov/encrypt-win32-encryptablevolume
func (v *Volume) Decrypt() error {
	resultRaw, err := oleutil.CallMethod(v.handle, "Decrypt")
	if err != nil {
		return fmt.Errorf("Decrypt(%s): %w", v.DriveLetter, err)
	} else if val, ok := resultRaw.Value().(int32); val != 0 || !ok {
		return fmt.Errorf("Decrypt(%s): %w", v.DriveLetter, decryptErrHandler(val))
	}

	return nil
}

// ChangePassphrase uses the new passphrase to obtain a new derived key. After the derived key is calculated,
// the new derived key is used to secure the encrypted volume's master key.
//
// Example: vol.ChangePassphrase()
//
// Ref: https://docs.microsoft.com/en-us/windows/win32/secprov/encrypt-win32-encryptablevolume
func (v *Volume) ChangePassphrase(volumeKeyProtectorID string, newPassphrase string) (string, error) {
	var newVolumeKeyProtectorID ole.VARIANT
	if err := ole.VariantInit(&newVolumeKeyProtectorID); err != nil {
		return "", err
	}

	resultRaw, err := oleutil.CallMethod(v.handle, "ChangePassphrase", string(volumeKeyProtectorID), string(newPassphrase), &newVolumeKeyProtectorID)
	if err != nil {
		return "", fmt.Errorf("ChangePassphrase(%s): %w", v.DriveLetter, err)
	} else if val, ok := resultRaw.Value().(int32); val != 0 || !ok {
		return "", fmt.Errorf("ChangePassphrase(%s): %w", v.DriveLetter, changePassphraseErrHandler(val))
	}

	return newVolumeKeyProtectorID.ToString(), nil
}

// DiscoveryVolumeType specifies the type of discovery volume to be used by Prepare.
//
// Ref: https://docs.microsoft.com/en-us/windows/win32/secprov/preparevolume-win32-encryptablevolume
type DiscoveryVolumeType string

const (
	// VolumeTypeNone indicates no discovery volume. This value creates a native BitLocker volume.
	VolumeTypeNone DiscoveryVolumeType = "<none>"
	// VolumeTypeDefault indicates the default behavior.
	VolumeTypeDefault DiscoveryVolumeType = "<default>"
	// VolumeTypeFAT32 creates a FAT32 discovery volume.
	VolumeTypeFAT32 DiscoveryVolumeType = "FAT32"
)

// ForceEncryptionType specifies the encryption type to be used when calling Prepare on the volume.
//
// Ref: https://docs.microsoft.com/en-us/windows/win32/secprov/preparevolume-win32-encryptablevolume
type ForceEncryptionType int32

const (
	// EncryptionTypeUnspecified indicates that the encryption type is not specified.
	EncryptionTypeUnspecified ForceEncryptionType = 0
	// EncryptionTypeSoftware specifies software encryption.
	EncryptionTypeSoftware ForceEncryptionType = 1
	// EncryptionTypeHardware specifies hardware encryption.
	EncryptionTypeHardware ForceEncryptionType = 2
)

// Prepare prepares a new Bitlocker Volume. This should be called BEFORE any key protectors are added.
//
// Example: vol.Prepare(bitlocker.VolumeTypeDefault, bitlocker.EncryptionTypeHardware)
//
// Ref: https://docs.microsoft.com/en-us/windows/win32/secprov/preparevolume-win32-encryptablevolume
func (v *Volume) Prepare(volType DiscoveryVolumeType, encType ForceEncryptionType) error {
	resultRaw, err := oleutil.CallMethod(v.handle, "PrepareVolume", string(volType), int32(encType))
	if err != nil {
		return fmt.Errorf("PrepareVolume(%s): %w", v.DriveLetter, err)
	} else if val, ok := resultRaw.Value().(int32); val != 0 || !ok {
		return fmt.Errorf("PrepareVolume(%s): %w", v.DriveLetter, errHandler(val))
	}
	return nil
}

// ProtectWithNumericalPassword adds a numerical password key protector.
//
// Leave password as a blank string to have one auto-generated by Windows. (Recommended)
//
// In Powershell this is referred to as a RecoveryPasswordProtector.
//
// Ref: https://docs.microsoft.com/en-us/windows/win32/secprov/protectkeywithnumericalpassword-win32-encryptablevolume
func (v *Volume) ProtectWithNumericalPassword(password string) error {
	var volumeKeyProtectorID ole.VARIANT
	ole.VariantInit(&volumeKeyProtectorID)
	var resultRaw *ole.VARIANT
	var err error
	if password != "" {
		resultRaw, err = oleutil.CallMethod(v.handle, "ProtectKeyWithNumericalPassword", nil, password, &volumeKeyProtectorID)
	} else {
		resultRaw, err = oleutil.CallMethod(v.handle, "ProtectKeyWithNumericalPassword", nil, nil, &volumeKeyProtectorID)
	}
	if err != nil {
		return fmt.Errorf("ProtectKeyWithNumericalPassword(%s): %w", v.DriveLetter, err)
	} else if val, ok := resultRaw.Value().(int32); val != 0 || !ok {
		return fmt.Errorf("ProtectKeyWithNumericalPassword(%s): %w", v.DriveLetter, protectKeyWithNumericalPasswordErrHandler(val))
	}

	return nil
}

// ProtectWithPassphrase adds a passphrase key protector.
//
// Ref: https://docs.microsoft.com/en-us/windows/win32/secprov/protectkeywithpassphrase-win32-encryptablevolume
func (v *Volume) ProtectWithPassphrase(passphrase string) (string, error) {
	var volumeKeyProtectorID ole.VARIANT
	ole.VariantInit(&volumeKeyProtectorID)
	resultRaw, err := oleutil.CallMethod(v.handle, "ProtectKeyWithPassphrase", nil, passphrase, &volumeKeyProtectorID)
	if err != nil {
		return "", fmt.Errorf("ProtectWithPassphrase(%s): %w", v.DriveLetter, err)
	} else if val, ok := resultRaw.Value().(int32); val != 0 || !ok {
		return "", fmt.Errorf("ProtectWithPassphrase(%s): %w", v.DriveLetter, protectKeyWithPassphraseErrHandler(val))
	}

	return volumeKeyProtectorID.ToString(), nil
}

// ProtectWithTPM adds the TPM key protector.
//
// Ref: https://docs.microsoft.com/en-us/windows/win32/secprov/protectkeywithtpm-win32-encryptablevolume
func (v *Volume) ProtectWithTPM(platformValidationProfile *[]uint8) error {
	var volumeKeyProtectorID ole.VARIANT
	ole.VariantInit(&volumeKeyProtectorID)
	var resultRaw *ole.VARIANT
	var err error
	if platformValidationProfile == nil {
		resultRaw, err = oleutil.CallMethod(v.handle, "ProtectKeyWithTPM", nil, nil, &volumeKeyProtectorID)
	} else {
		resultRaw, err = oleutil.CallMethod(v.handle, "ProtectKeyWithTPM", nil, *platformValidationProfile, &volumeKeyProtectorID)
	}
	if err != nil {
		return fmt.Errorf("ProtectKeyWithTPM(%s): %w", v.DriveLetter, err)
	} else if val, ok := resultRaw.Value().(int32); val != 0 || !ok {
		return fmt.Errorf("ProtectKeyWithTPM(%s): %w", v.DriveLetter, protectKeyWithTPMErrHandler(val))
	}

	return nil
}

// ProtectKeyWithExternalKey secures the volume's encryption key with a 256-bit external key.
// This external key can be used to recover from the authentication failures of other key protectors
//
// Ref: https://docs.microsoft.com/en-us/windows/win32/secprov/protectkeywithtpm-win32-encryptablevolume
func (v *Volume) ProtectKeyWithExternalKey(friendlyName string, externalKey []uint8) (string, error) {
	var volumeKeyProtectorID ole.VARIANT
	ole.VariantInit(&volumeKeyProtectorID)
	var resultRaw *ole.VARIANT
	var err error

	if friendlyName == "" {
		if externalKey == nil {
			resultRaw, err = oleutil.CallMethod(v.handle, "ProtectKeyWithExternalKey", nil, nil, &volumeKeyProtectorID)
		} else {
			resultRaw, err = oleutil.CallMethod(v.handle, "ProtectKeyWithExternalKey", nil, externalKey, &volumeKeyProtectorID)
		}
	} else {
		if externalKey == nil {
			resultRaw, err = oleutil.CallMethod(v.handle, "ProtectKeyWithExternalKey", friendlyName, nil, &volumeKeyProtectorID)
		} else {
			resultRaw, err = oleutil.CallMethod(v.handle, "ProtectKeyWithExternalKey", friendlyName, externalKey, &volumeKeyProtectorID)
		}
	}

	if err != nil {
		return "", fmt.Errorf("ProtectKeyWithExternalKey(%s): %w", v.DriveLetter, err)
	} else if val, ok := resultRaw.Value().(int32); val != 0 || !ok {
		return "", fmt.Errorf("ProtectKeyWithExternalKey(%s): %w", v.DriveLetter, protectKeyWithExternalKeyErrHandler(val))
	}

	return volumeKeyProtectorID.ToString(), nil
}

// EnableKeyProtectors enables or resumes all disabled or suspended key protectors.
// You can use this method to reenable or resume BitLocker protection on an encrypted volume.
// This method ensures that the volume's encryption key is not exposed in the clear on the hard disk.
//
// Example: vol.EnableKeyProtectors()
//
// Ref: https://docs.microsoft.com/en-us/windows/win32/secprov/encrypt-win32-encryptablevolume
func (v *Volume) EnableKeyProtectors() error {
	resultRaw, err := oleutil.CallMethod(v.handle, "EnableKeyProtectors")
	if err != nil {
		return fmt.Errorf("EnableKeyProtectors(%s): %w", v.DriveLetter, err)
	} else if val, ok := resultRaw.Value().(int32); val != 0 || !ok {
		return fmt.Errorf("EnableKeyProtectors(%s): %w", v.DriveLetter, enableKeyProtectorsErrHandler(val))
	}

	return nil
}

// DisableKeyProtectors disables or suspends all key protectors associated with this volume.
//
// DisableCount is an optional integer that specifies the number of reboots for which the key
// protectors will be disabled. This parameter is only available on OS volumes.
//
// Example: vol.DisableKeyProtectors(0)
//
// Ref: https://docs.microsoft.com/en-us/windows/win32/secprov/encrypt-win32-encryptablevolume
func (v *Volume) DisableKeyProtectors(disableCount uint32) error {
	var resultRaw *ole.VARIANT
	var err error

	if disableCount > 0 {
		resultRaw, err = oleutil.CallMethod(v.handle, "DisableKeyProtectors", disableCount)
	} else {
		resultRaw, err = oleutil.CallMethod(v.handle, "DisableKeyProtectors", nil)
	}
	if err != nil {
		return fmt.Errorf("DisableKeyProtectors(%s): %w", v.DriveLetter, err)
	} else if val, ok := resultRaw.Value().(int32); val != 0 || !ok {
		return fmt.Errorf("DisableKeyProtectors(%s): %w", v.DriveLetter, disableKeyProtectorsErrHandler(val))
	}

	return nil
}

// GetConversionStatus indicates the status of the encryption or decryption on the volume
//
// PrecisionFactor is a value from 0 to 4 that specifies the precision levels.
//
// Example: vol.GetConversionStatus(2)
//
// Ref: https://docs.microsoft.com/en-us/windows/win32/secprov/encrypt-win32-encryptablevolume
func (v *Volume) GetConversionStatus(precisionFactor uint32) (*ConversionStatus, error) {
	var conversionStatus ole.VARIANT
	ole.VariantInit(&conversionStatus)
	var encryptionPercentage ole.VARIANT
	ole.VariantInit(&encryptionPercentage)
	var encryptionFlags ole.VARIANT
	ole.VariantInit(&encryptionFlags)
	var wipingStatus ole.VARIANT
	ole.VariantInit(&wipingStatus)
	var wipingPercentage ole.VARIANT
	ole.VariantInit(&wipingPercentage)

	resultRaw, err := oleutil.CallMethod(
		v.handle, "GetConversionStatus",
		&conversionStatus,
		&encryptionPercentage,
		&encryptionFlags,
		&wipingStatus,
		&wipingPercentage,
		0,
	)

	if err != nil {
		return nil, fmt.Errorf("GetConversionStatus(%s): %w", v.DriveLetter, err)
	} else if val, ok := resultRaw.Value().(int32); val != 0 || !ok {
		return nil, fmt.Errorf("GetConversionStatus(%s): %w", v.DriveLetter, getConversionStatusErrHandler(val))
	}

	cs := ConversionStatus{
		ConversionStatus:     conversionStatus.Value().(int32),
		EncryptionFlags:      encryptionFlags.Value().(int32),
		EncryptionPercentage: encryptionPercentage.Value().(int32),
		WipingStatus:         wipingStatus.Value().(int32),
		WipingPercentage:     wipingPercentage.Value().(int32),
	}

	return &cs, nil
}

// EnableAutoUnlock disables or suspends all key protectors associated with this volume.
//
// Example: vol.EnableAutoUnlock("{9A43582E-B70D-4956-9031-B5D47D9EE797}")
//
// Ref: https://docs.microsoft.com/en-us/windows/win32/secprov/encrypt-win32-encryptablevolume
func (v *Volume) EnableAutoUnlock(volumeKeyProtectorID string) error {
	resultRaw, err := oleutil.CallMethod(v.handle, "EnableAutoUnlock", volumeKeyProtectorID)
	if err != nil {
		return fmt.Errorf("EnableAutoUnlock(%s): %w", v.DriveLetter, err)
	} else if val, ok := resultRaw.Value().(int32); val != 0 || !ok {
		return fmt.Errorf("EnableAutoUnlock(%s): %w", v.DriveLetter, enableAutoUnlockErrHandler(val))
	}

	return nil
}

// DisableAutoUnlock removes the external key saved onto the currently // running operating
// system volume so that a data volume is not automatically unlocked when it is mounted.
//
// Example: vol.DisableAutoUnlock()
//
// Ref: https://docs.microsoft.com/en-us/windows/win32/secprov/encrypt-win32-encryptablevolume
func (v *Volume) DisableAutoUnlock() error {
	resultRaw, err := oleutil.CallMethod(v.handle, "DisableAutoUnlock")
	if err != nil {
		return fmt.Errorf("DisableAutoUnlock(%s): %w", v.DriveLetter, err)
	} else if val, ok := resultRaw.Value().(int32); val != 0 || !ok {
		return fmt.Errorf("DisableAutoUnlock(%s): %w", v.DriveLetter, disableAutoUnlockErrHandler(val))
	}

	return nil
}

// IsAutoUnlockEnabled indicates whether the volume is automatically unlocked when it is mounted
// (for example, when removable memory devices are connected to the computer)
//
// Example: vol.IsAutoUnlockEnabled()
//
// Ref: https://docs.microsoft.com/en-us/windows/win32/secprov/encrypt-win32-encryptablevolume
func (v *Volume) IsAutoUnlockEnabled() (bool, string, error) {
	var isAutoUnlockEnabled ole.VARIANT
	ole.VariantInit(&isAutoUnlockEnabled)
	var volumeKeyProtectorID ole.VARIANT
	ole.VariantInit(&volumeKeyProtectorID)

	resultRaw, err := oleutil.CallMethod(
		v.handle, "IsAutoUnlockEnabled",
		&isAutoUnlockEnabled,
		&volumeKeyProtectorID,
	)

	if err != nil {
		return false, "", fmt.Errorf("IsAutoUnlockEnabled(%s): %w", v.DriveLetter, err)
	} else if val, ok := resultRaw.Value().(int32); val != 0 || !ok {
		return false, "", fmt.Errorf("IsAutoUnlockEnabled(%s): %w", v.DriveLetter, errHandler(val))
	}

	return isAutoUnlockEnabled.Value().(bool), volumeKeyProtectorID.Value().(string), nil
}

// GetKeyProtectors lists the protectors used to secure the volume's encryption key.
// If a protector type is provided, then only volume key protectors of the specified type are returned
//
// Example: vol.GetKeyProtectors(0)
//
// Ref: https://docs.microsoft.com/en-us/windows/win32/secprov/encrypt-win32-encryptablevolume
func (v *Volume) GetKeyProtectors(keyProtectorType int32) ([]string, error) {
	values := []string{}

	var volumeKeyProtectorIDs ole.VARIANT
	ole.VariantInit(&volumeKeyProtectorIDs)

	resultRaw, err := oleutil.CallMethod(
		v.handle, "GetKeyProtectors",
		keyProtectorType,
		&volumeKeyProtectorIDs,
	)

	if err != nil {
		return nil, fmt.Errorf("GetKeyProtectors(%s): %w", v.DriveLetter, err)
	} else if val, ok := resultRaw.Value().(int32); val != 0 || !ok {
		return nil, fmt.Errorf("GetKeyProtectors(%s): %w", v.DriveLetter, errHandler(val))
	}

	keyProtectorValues := volumeKeyProtectorIDs.ToArray().ToValueArray()
	for _, keyIDItemRaw := range keyProtectorValues {
		keyIDItem, ok := keyIDItemRaw.(string)
		if !ok {
			return nil, fmt.Errorf("KeyProtectorID wasn't a string...")
		}
		values = append(values, keyIDItem)
	}
	return values, nil
}

// GetKeyProtectorType indicates the type of a given key protector
//
// Example: vol.GetKeyProtectorType("{E5CBFAAC-C757-4683-9A07-2AFF00EF0123}"")
//
// Ref: https://docs.microsoft.com/en-us/windows/win32/secprov/encrypt-win32-encryptablevolume
func (v *Volume) GetKeyProtectorType(volumeKeyProtectorID string) (int32, error) {
	var keyProtectorType ole.VARIANT
	ole.VariantInit(&keyProtectorType)

	resultRaw, err := oleutil.CallMethod(
		v.handle, "GetKeyProtectorType",
		volumeKeyProtectorID,
		&keyProtectorType,
	)

	if err != nil {
		return 0, fmt.Errorf("GetKeyProtectorType(%s): %w", v.DriveLetter, err)
	} else if val, ok := resultRaw.Value().(int32); val != 0 || !ok {
		return 0, fmt.Errorf("GetKeyProtectorType(%s): %w", v.DriveLetter, errHandler(val))
	}

	return keyProtectorType.Value().(int32), nil
}

func (v *Volume) GetProperties() error {
	// Get ConversionStatus
	resConversionStatus, err := oleutil.GetProperty(v.handle, "ConversionStatus")
	if err != nil {
		return fmt.Errorf("Error while getting property ConversionStatus from Win32_EncryptableVolume. %s", err.Error())
	}
	if resConversionStatus.Value() != nil {
		if res, ok := resConversionStatus.Value().(int32); ok {
			v.ConversionStatus = uint32(res)
		} else {
			return fmt.Errorf("Error while setting ConversionStatus property to int32. Got type %s", reflect.TypeOf(resConversionStatus.Value()).Name())
		}
	}

	// Get DeviceID
	resDeviceID, err := oleutil.GetProperty(v.handle, "DeviceID")
	if err != nil {
		return fmt.Errorf("Error while getting property DeviceID from Win32_EncryptableVolume info. %s", err.Error())
	}
	v.DeviceID = resDeviceID.ToString()

	// Get EncryptionMethod
	resEncryptionMethod, err := oleutil.GetProperty(v.handle, "EncryptionMethod")
	if err != nil {
		return fmt.Errorf("Error while getting property EncryptionMethod from Win32_EncryptableVolume. %s", err.Error())
	}
	if resEncryptionMethod.Value() != nil {
		if res, ok := resEncryptionMethod.Value().(int32); ok {
			v.EncryptionMethod = uint32(res)
		} else {
			return fmt.Errorf("Error while setting EncryptionMethod property to int32. Got type %s", reflect.TypeOf(resEncryptionMethod.Value()).Name())
		}
	}

	// IsVolumeInitializedForProtection
	resIsVolumeInitializedForProtection, err := oleutil.GetProperty(v.handle, "IsVolumeInitializedForProtection")
	if err != nil {
		return fmt.Errorf("Error while getting property IsVolumeInitializedForProtection from Win32_EncryptableVolume. %s", err.Error())
	}
	if resIsVolumeInitializedForProtection.Value() != nil {
		if res, ok := resIsVolumeInitializedForProtection.Value().(bool); ok {
			v.IsVolumeInitializedForProtection = res
		} else {
			return fmt.Errorf("Error while setting IsVolumeInitializedForProtection property to bool. Got type %s", reflect.TypeOf(resIsVolumeInitializedForProtection.Value()).Name())
		}
	}

	// Get PersistentVolumeID
	resPersistentVolumeID, err := oleutil.GetProperty(v.handle, "PersistentVolumeID")
	if err != nil {
		return fmt.Errorf("Error while getting property PersistentVolumeID from Win32_EncryptableVolume info. %s", err.Error())
	}
	v.PersistentVolumeID = resPersistentVolumeID.ToString()

	// Get ProtectionStatus
	resProtectionStatus, err := oleutil.GetProperty(v.handle, "ProtectionStatus")
	if err != nil {
		return fmt.Errorf("Error while getting property ProtectionStatus from Win32_EncryptableVolume. %s", err.Error())
	}
	if resProtectionStatus.Value() != nil {
		if res, ok := resProtectionStatus.Value().(int32); ok {
			v.ProtectionStatus = uint32(res)
		} else {
			return fmt.Errorf("Error while setting ProtectionStatus property to int32. Got type %s", reflect.TypeOf(resProtectionStatus.Value()).Name())
		}
	}

	// Get VolumeType
	resVolumeType, err := oleutil.GetProperty(v.handle, "VolumeType")
	if err != nil {
		return fmt.Errorf("Error while getting property VolumeType from Win32_EncryptableVolume. %s", err.Error())
	}
	if resVolumeType.Value() != nil {
		if res, ok := resVolumeType.Value().(int32); ok {
			v.VolumeType = uint32(res)
		} else {
			return fmt.Errorf("Error while setting VolumeType property to int32. Got type %s", reflect.TypeOf(resVolumeType.Value()).Name())
		}
	}

	return nil
}
