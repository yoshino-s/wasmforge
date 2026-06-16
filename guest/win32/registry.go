//go:build wasip1

package win32

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// Predefined registry key handles.
const (
	HKEY_CLASSES_ROOT   Handle = -2147483648 // 0x80000000
	HKEY_CURRENT_USER   Handle = -2147483647 // 0x80000001
	HKEY_LOCAL_MACHINE  Handle = -2147483646 // 0x80000002
	HKEY_USERS          Handle = -2147483645 // 0x80000003
	HKEY_CURRENT_CONFIG Handle = -2147483643 // 0x80000005
)

// Registry access rights.
const (
	KEY_READ       = uint32(0x20019)
	KEY_WRITE      = uint32(0x20006)
	KEY_ALL_ACCESS = uint32(0xF003F)
)

// Registry value types.
const (
	REG_SZ        = uint32(1)
	REG_EXPAND_SZ = uint32(2)
	REG_BINARY    = uint32(3)
	REG_DWORD     = uint32(4)
	REG_QWORD     = uint32(11)
)

// RegOpenKey opens a registry key under hkey with the given access rights.
func RegOpenKey(hkey Handle, subKey string, access uint32) (Handle, error) {
	b := []byte(subKey)
	var subKeyPtr *byte
	if len(b) > 0 {
		subKeyPtr = &b[0]
	}
	var h int32
	errno := _win32_reg_open_key(int32(hkey), subKeyPtr, int32(len(b)), access, &h)
	if err := errFromErrno(errno); err != nil {
		return 0, fmt.Errorf("win32: RegOpenKey %q: %w", subKey, err)
	}
	return Handle(h), nil
}

// RegCloseKey closes an open registry key handle.
func RegCloseKey(h Handle) error {
	return errFromErrno(_win32_reg_close_key(int32(h)))
}

// RegQueryValue queries the raw type and data bytes for a named registry value.
// The returned data slice is freshly allocated.
func RegQueryValue(h Handle, name string) (regType uint32, data []byte, err error) {
	b := []byte(name)
	var namePtr *byte
	if len(b) > 0 {
		namePtr = &b[0]
	}

	// Initial buffer attempt.
	buf := make([]byte, 4096)
	dataLen := uint32(len(buf))

	errno := _win32_reg_query_value(int32(h), namePtr, int32(len(b)), &regType, &buf[0], &dataLen)
	if errno == 0 {
		return regType, buf[:dataLen], nil
	}

	// errno 234 is ERROR_MORE_DATA; retry with the indicated size.
	if errno != 234 {
		return 0, nil, errFromErrno(errno)
	}

	buf = make([]byte, dataLen)
	errno = _win32_reg_query_value(int32(h), namePtr, int32(len(b)), &regType, &buf[0], &dataLen)
	if err := errFromErrno(errno); err != nil {
		return 0, nil, err
	}
	return regType, buf[:dataLen], nil
}

// RegQueryString reads a REG_SZ or REG_EXPAND_SZ value and returns it as a Go string.
// The raw data from Windows is UTF-16LE; this function decodes it.
func RegQueryString(h Handle, name string) (string, error) {
	regType, data, err := RegQueryValue(h, name)
	if err != nil {
		return "", err
	}
	if regType != REG_SZ && regType != REG_EXPAND_SZ {
		return "", fmt.Errorf("win32: RegQueryString: unexpected type %d", regType)
	}
	return decodeUTF16(data), nil
}

// RegQueryDWORD reads a REG_DWORD value.
func RegQueryDWORD(h Handle, name string) (uint32, error) {
	regType, data, err := RegQueryValue(h, name)
	if err != nil {
		return 0, err
	}
	if regType != REG_DWORD {
		return 0, fmt.Errorf("win32: RegQueryDWORD: unexpected type %d", regType)
	}
	if len(data) < 4 {
		return 0, fmt.Errorf("win32: RegQueryDWORD: short data (%d bytes)", len(data))
	}
	return binary.LittleEndian.Uint32(data[:4]), nil
}

// RegSetString writes a REG_SZ value. The string is encoded as UTF-16LE with a
// null terminator before being written.
func RegSetString(h Handle, name, value string) error {
	nameB := []byte(name)
	var namePtr *byte
	if len(nameB) > 0 {
		namePtr = &nameB[0]
	}

	encoded := encodeUTF16(value)
	var dataPtr *byte
	if len(encoded) > 0 {
		dataPtr = &encoded[0]
	}
	errno := _win32_reg_set_value(int32(h), namePtr, int32(len(nameB)), REG_SZ, dataPtr, uint32(len(encoded)))
	return errFromErrno(errno)
}

// RegSetDWORD writes a REG_DWORD value.
func RegSetDWORD(h Handle, name string, value uint32) error {
	nameB := []byte(name)
	var namePtr *byte
	if len(nameB) > 0 {
		namePtr = &nameB[0]
	}

	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], value)
	errno := _win32_reg_set_value(int32(h), namePtr, int32(len(nameB)), REG_DWORD, &buf[0], 4)
	return errFromErrno(errno)
}

// RegDeleteValue deletes a named value from an open registry key.
func RegDeleteValue(h Handle, name string) error {
	b := []byte(name)
	var namePtr *byte
	if len(b) > 0 {
		namePtr = &b[0]
	}
	return errFromErrno(_win32_reg_delete_value(int32(h), namePtr, int32(len(b))))
}

// RegEnumKeys enumerates all subkey names under an open registry key.
// Subkey names are returned as UTF-8 strings (the host converts from UTF-16).
func RegEnumKeys(h Handle) ([]string, error) {
	var keys []string
	var buf [256]byte

	for index := uint32(0); ; index++ {
		nameLen := uint32(len(buf))
		errno := _win32_reg_enum_key(int32(h), index, &buf[0], &nameLen)
		if errno != 0 {
			// Non-zero errno signals end of enumeration or a real error.
			// errno 259 is ERROR_NO_MORE_ITEMS.
			if errno == 259 {
				break
			}
			return nil, errFromErrno(errno)
		}
		keys = append(keys, string(buf[:nameLen]))
	}
	return keys, nil
}

// decodeUTF16 converts a UTF-16LE byte slice to a Go string, stripping any
// trailing null characters.
func decodeUTF16(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	// Strip trailing null characters.
	for len(u16) > 0 && u16[len(u16)-1] == 0 {
		u16 = u16[:len(u16)-1]
	}
	return string(utf16.Decode(u16))
}

// encodeUTF16 converts a Go string to a UTF-16LE byte slice with a null terminator.
func encodeUTF16(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	u16 = append(u16, 0) // null terminator
	buf := make([]byte, len(u16)*2)
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(buf[i*2:], v)
	}
	return buf
}
