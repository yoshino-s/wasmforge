//go:build wasip1

package win32

import (
	"encoding/binary"
	"fmt"
)

// Extension function IDs matching the host-side constants.
const (
	ExtFuncOutput      = 0
	ExtFuncPrintf      = 1
	ExtFuncDataParse   = 2
	ExtFuncDataInt     = 3
	ExtFuncDataShort   = 4
	ExtFuncDataLength  = 5
	ExtFuncDataExtract = 6
	ExtFuncAddValue    = 7
	ExtFuncGetValue    = 8
	ExtFuncRemoveValue = 9
)

// Compatibility aliases for existing code that references the old names.
const (
	BeaconFuncOutput      = ExtFuncOutput
	BeaconFuncPrintf      = ExtFuncPrintf
	BeaconFuncDataParse   = ExtFuncDataParse
	BeaconFuncDataInt     = ExtFuncDataInt
	BeaconFuncDataShort   = ExtFuncDataShort
	BeaconFuncDataLength  = ExtFuncDataLength
	BeaconFuncDataExtract = ExtFuncDataExtract
	BeaconFuncAddValue    = ExtFuncAddValue
	BeaconFuncGetValue    = ExtFuncGetValue
	BeaconFuncRemoveValue = ExtFuncRemoveValue
)

// ExtGetFunc returns the native host address of an extension API callback function.
// This address can be written into a loaded object file's GOT for native-speed calls.
func ExtGetFunc(funcId int) (uint64, error) {
	var buf [8]byte
	errno := _win32_ext_get_func(uint32(funcId), &buf[0])
	if err := errFromErrno(errno); err != nil {
		return 0, fmt.Errorf("win32: ExtGetFunc(%d): %w", funcId, err)
	}
	return binary.LittleEndian.Uint64(buf[:]), nil
}

// ExtReadOutput reads all accumulated extension output from the host.
func ExtReadOutput() (string, error) {
	var actualLen uint32
	errno := _win32_ext_read_output(nil, 0, &actualLen)
	if err := errFromErrno(errno); err != nil {
		return "", fmt.Errorf("win32: ExtReadOutput (size): %w", err)
	}
	if actualLen == 0 {
		return "", nil
	}

	buf := make([]byte, actualLen)
	errno = _win32_ext_read_output(&buf[0], actualLen, &actualLen)
	if err := errFromErrno(errno); err != nil {
		return "", fmt.Errorf("win32: ExtReadOutput (read): %w", err)
	}
	return string(buf[:actualLen]), nil
}

// ExtResetOutput clears the accumulated extension output buffer.
func ExtResetOutput() error {
	errno := _win32_ext_reset_output()
	if err := errFromErrno(errno); err != nil {
		return fmt.Errorf("win32: ExtResetOutput: %w", err)
	}
	return nil
}

// Compatibility wrappers for existing code.
var (
	BeaconGetFunc     = ExtGetFunc
	BeaconReadOutput  = ExtReadOutput
	BeaconResetOutput = ExtResetOutput
)
