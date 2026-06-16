//go:build windows

package hostmod

import (
	"context"
	"syscall"
	"unsafe"

	"github.com/tetratelabs/wazero/api"
	"golang.org/x/sys/windows"
)

// modadvapi32 and its procs are loaded directly because golang.org/x/sys/windows
// does not export RegSetValueExW or RegDeleteValueW wrappers (they are unexported
// in the windows/registry sub-package). Direct SyscallN is required.
var (
	modadvapi32         = windows.NewLazyDLL("advapi32.dll")
	procRegSetValueExW  = modadvapi32.NewProc("RegSetValueExW")
	procRegDeleteValueW = modadvapi32.NewProc("RegDeleteValueW")
)

// win32RegOpenKey opens a registry key.
// hkey is a predefined root key constant (e.g., HKEY_LOCAL_MACHINE = 0x80000002).
func win32RegOpenKey(ctx context.Context, mod api.Module, hkey int32, subkeyPtr, subkeyLen, access, handlePtr uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoEINVAL
	}

	subkeyBytes, ok := readBytes(mod, subkeyPtr, subkeyLen)
	if !ok {
		return errnoEFAULT
	}
	subkey, err := windows.UTF16PtrFromString(string(subkeyBytes))
	if err != nil {
		return errnoEINVAL
	}

	var result windows.Handle
	if err := windows.RegOpenKeyEx(
		windows.Handle(uintptr(uint32(hkey))),
		subkey,
		0,
		access,
		&result,
	); err != nil {
		return win32Errno(err)
	}

	id := ht.register(&win32HandleEntry{
		kind:      handleWin32,
		winHandle: uintptr(result),
	})

	if !writeInt32(mod, handlePtr, id) {
		windows.RegCloseKey(result)
		return errnoEFAULT
	}
	return errnoSuccess
}

// win32RegCloseKey closes a registry key handle.
func win32RegCloseKey(ctx context.Context, mod api.Module, handle int32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoEINVAL
	}

	entry := ht.remove(handle)
	if entry == nil || entry.kind != handleWin32 {
		return errnoEBADF
	}

	if err := windows.RegCloseKey(windows.Handle(entry.winHandle)); err != nil {
		return win32Errno(err)
	}
	return errnoSuccess
}

// win32RegQueryValue queries a named value from a registry key.
// If the provided buffer is too small, ERROR_MORE_DATA is mapped to errnoERANGE
// and the required size is written back to dataBufLenPtr so the caller can retry.
func win32RegQueryValue(ctx context.Context, mod api.Module, handle int32, namePtr, nameLen, typePtr, dataPtr, dataLenPtr uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoEINVAL
	}

	entry := ht.get(handle)
	if entry == nil {
		return errnoEBADF
	}

	nameBytes, ok := readBytes(mod, namePtr, nameLen)
	if !ok {
		return errnoEFAULT
	}
	valueName, err := windows.UTF16PtrFromString(string(nameBytes))
	if err != nil {
		return errnoEINVAL
	}

	bufLen, ok := readUint32(mod, dataLenPtr)
	if !ok {
		return errnoEFAULT
	}

	var valType uint32
	var dataSize uint32 = bufLen

	var dataBuf []byte
	if bufLen > 0 {
		dataBuf = make([]byte, bufLen)
	}

	var dataPtr8 *byte
	if len(dataBuf) > 0 {
		dataPtr8 = &dataBuf[0]
	}

	err = windows.RegQueryValueEx(
		windows.Handle(entry.winHandle),
		valueName,
		nil,
		&valType,
		dataPtr8,
		&dataSize,
	)
	if err != nil {
		if err == windows.ERROR_MORE_DATA {
			// Write back the required buffer size so the caller can retry.
			writeUint32(mod, dataLenPtr, dataSize)
		}
		return win32Errno(err)
	}

	if !writeUint32(mod, typePtr, valType) {
		return errnoEFAULT
	}
	if !writeUint32(mod, dataLenPtr, dataSize) {
		return errnoEFAULT
	}
	if len(dataBuf) > 0 && dataSize > 0 {
		if !writeBytes(mod, dataPtr, dataBuf[:dataSize]) {
			return errnoEFAULT
		}
	}
	return errnoSuccess
}

// win32RegSetValue sets a named value in a registry key.
func win32RegSetValue(ctx context.Context, mod api.Module, handle int32, namePtr, nameLen, vtype, dataPtr, dataLen uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoEINVAL
	}

	entry := ht.get(handle)
	if entry == nil {
		return errnoEBADF
	}

	nameBytes, ok := readBytes(mod, namePtr, nameLen)
	if !ok {
		return errnoEFAULT
	}
	valueName, err := windows.UTF16PtrFromString(string(nameBytes))
	if err != nil {
		return errnoEINVAL
	}

	var data []byte
	if dataLen > 0 {
		data, ok = readBytes(mod, dataPtr, dataLen)
		if !ok {
			return errnoEFAULT
		}
	}

	var dataPtr8 *byte
	if len(data) > 0 {
		dataPtr8 = &data[0]
	}

	r, _, _ := syscall.SyscallN(procRegSetValueExW.Addr(),
		entry.winHandle,
		uintptr(unsafe.Pointer(valueName)),
		0,
		uintptr(vtype),
		uintptr(unsafe.Pointer(dataPtr8)),
		uintptr(dataLen),
	)
	if r != 0 {
		return win32Errno(syscall.Errno(r))
	}
	return errnoSuccess
}

// win32RegDeleteValue deletes a named value from a registry key.
func win32RegDeleteValue(ctx context.Context, mod api.Module, handle int32, namePtr, nameLen uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoEINVAL
	}

	entry := ht.get(handle)
	if entry == nil {
		return errnoEBADF
	}

	nameBytes, ok := readBytes(mod, namePtr, nameLen)
	if !ok {
		return errnoEFAULT
	}
	valueName, err := windows.UTF16PtrFromString(string(nameBytes))
	if err != nil {
		return errnoEINVAL
	}

	r, _, _ := syscall.SyscallN(procRegDeleteValueW.Addr(),
		entry.winHandle,
		uintptr(unsafe.Pointer(valueName)),
	)
	if r != 0 {
		return win32Errno(syscall.Errno(r))
	}
	return errnoSuccess
}

// win32RegEnumKey enumerates subkeys of a registry key.
func win32RegEnumKey(ctx context.Context, mod api.Module, handle int32, index, namePtr, nameLenPtr uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoEINVAL
	}

	entry := ht.get(handle)
	if entry == nil {
		return errnoEBADF
	}

	nameBufLen, ok := readUint32(mod, nameLenPtr)
	if !ok {
		return errnoEFAULT
	}
	if nameBufLen == 0 {
		return errnoEINVAL
	}

	nameBuf := make([]uint16, nameBufLen)
	nameLen := nameBufLen

	if err := windows.RegEnumKeyEx(
		windows.Handle(entry.winHandle),
		index,
		&nameBuf[0],
		&nameLen,
		nil,
		nil,
		nil,
		nil,
	); err != nil {
		return win32Errno(err)
	}

	name := windows.UTF16ToString(nameBuf[:nameLen])
	nameBytes := []byte(name)

	if !writeUint32(mod, nameLenPtr, uint32(len(nameBytes))) {
		return errnoEFAULT
	}
	if uint32(len(nameBytes)) > 0 {
		if !writeBytes(mod, namePtr, nameBytes) {
			return errnoEFAULT
		}
	}
	return errnoSuccess
}
