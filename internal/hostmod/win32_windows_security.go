//go:build windows

package hostmod

import (
	"context"
	"unsafe"

	"github.com/tetratelabs/wazero/api"
	"golang.org/x/sys/windows"
)

// Core Win32 security host functions (used by both Go WASM and NativeAOT).

// win32OpenProcessToken opens the access token associated with a process.
func win32OpenProcessToken(ctx context.Context, mod api.Module, procHandle int32, access, tokenPtr uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoEINVAL
	}

	entry := ht.get(procHandle)
	if entry == nil {
		return errnoEBADF
	}

	var token windows.Token
	if err := windows.OpenProcessToken(
		windows.Handle(entry.winHandle),
		access,
		&token,
	); err != nil {
		return win32Errno(err)
	}

	id := ht.register(&win32HandleEntry{
		kind:      handleWin32,
		winHandle: uintptr(token),
	})

	if !writeInt32(mod, tokenPtr, id) {
		token.Close()
		return errnoEFAULT
	}
	return errnoSuccess
}

// win32GetTokenInfo retrieves information about an access token.
func win32GetTokenInfo(ctx context.Context, mod api.Module, token int32, infoClass, bufPtr, bufLen, neededPtr uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoEINVAL
	}

	entry := ht.get(token)
	if entry == nil {
		return errnoEBADF
	}

	buf := make([]byte, bufLen)
	var needed uint32

	var bufPtr8 *byte
	if len(buf) > 0 {
		bufPtr8 = &buf[0]
	}

	err := windows.GetTokenInformation(
		windows.Token(entry.winHandle),
		infoClass,
		bufPtr8,
		bufLen,
		&needed,
	)

	if !writeUint32(mod, neededPtr, needed) {
		return errnoEFAULT
	}

	if err != nil {
		return win32Errno(err)
	}

	if bufLen > 0 && needed > 0 {
		n := needed
		if n > bufLen {
			n = bufLen
		}
		// Compact x64 struct layout to wasm32 for token info classes with
		// embedded pointers (TOKEN_OWNER, TOKEN_GROUPS, etc.). The native
		// call wrote into our temp Go buffer with 8-byte pointers that point
		// into the buffer itself; convert to 4-byte WASM-relative pointers.
		data := compactTokenInfoBytes(buf[:n], infoClass, uintptr(unsafe.Pointer(bufPtr8)), bufPtr)
		if !writeBytes(mod, bufPtr, data) {
			return errnoEFAULT
		}
	}
	return errnoSuccess
}

// win32OpenSCManager opens a connection to the service control manager.
func win32OpenSCManager(ctx context.Context, mod api.Module, machinePtr, machineLen, access, handlePtr uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoEINVAL
	}

	var machineName *uint16
	if machineLen > 0 {
		machineBytes, ok := readBytes(mod, machinePtr, machineLen)
		if !ok {
			return errnoEFAULT
		}
		ptr, err := windows.UTF16PtrFromString(string(machineBytes))
		if err != nil {
			return errnoEINVAL
		}
		machineName = ptr
	}

	scm, err := windows.OpenSCManager(machineName, nil, access)
	if err != nil {
		return win32Errno(err)
	}

	id := ht.register(&win32HandleEntry{
		kind:      handleWin32,
		winHandle: uintptr(scm),
	})

	if !writeInt32(mod, handlePtr, id) {
		windows.CloseServiceHandle(scm)
		return errnoEFAULT
	}
	return errnoSuccess
}

// win32QueryServiceStatus queries the status of a service.
// statusPtr points to a 28-byte SERVICE_STATUS structure in WASM memory.
func win32QueryServiceStatus(ctx context.Context, mod api.Module, svcHandle int32, statusPtr uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoEINVAL
	}

	entry := ht.get(svcHandle)
	if entry == nil {
		return errnoEBADF
	}

	var status windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(windows.Handle(entry.winHandle), &status); err != nil {
		return win32Errno(err)
	}

	// Marshal SERVICE_STATUS (7 DWORD fields = 28 bytes) into WASM memory.
	fields := []uint32{
		status.ServiceType,
		status.CurrentState,
		status.ControlsAccepted,
		status.Win32ExitCode,
		status.ServiceSpecificExitCode,
		status.CheckPoint,
		status.WaitHint,
	}
	for i, f := range fields {
		if !writeUint32(mod, statusPtr+uint32(i)*4, f) {
			return errnoEFAULT
		}
	}
	return errnoSuccess
}
