//go:build !windows

package hostmod

import (
	"context"

	"github.com/tetratelabs/wazero/api"
)

// win32Available returns 0 on non-Windows platforms (Win32 is not available).
func win32Available(ctx context.Context, mod api.Module) uint32 {
	return 0
}

// win32LoadLibrary always returns errnoENOSYS on non-Windows platforms.
func win32LoadLibrary(ctx context.Context, mod api.Module, namePtr, nameLen, handlePtr uint32) uint32 {
	return errnoENOSYS
}

// win32GetProcAddress always returns errnoENOSYS on non-Windows platforms.
func win32GetProcAddress(ctx context.Context, mod api.Module, libHandle int32, namePtr, nameLen, procPtr uint32) uint32 {
	return errnoENOSYS
}

// win32Call always returns errnoENOSYS on non-Windows platforms.
func win32Call(ctx context.Context, mod api.Module, proc int32, nargs, argsPtr, retPtr uint32) uint32 {
	return errnoENOSYS
}

// win32FreeLibrary always returns errnoENOSYS on non-Windows platforms.
func win32FreeLibrary(ctx context.Context, mod api.Module, handle int32) uint32 {
	return errnoENOSYS
}

// win32RegOpenKey always returns errnoENOSYS on non-Windows platforms.
func win32RegOpenKey(ctx context.Context, mod api.Module, hkey int32, subkeyPtr, subkeyLen, access, handlePtr uint32) uint32 {
	return errnoENOSYS
}

// win32RegCloseKey always returns errnoENOSYS on non-Windows platforms.
func win32RegCloseKey(ctx context.Context, mod api.Module, handle int32) uint32 {
	return errnoENOSYS
}

// win32RegQueryValue always returns errnoENOSYS on non-Windows platforms.
func win32RegQueryValue(ctx context.Context, mod api.Module, handle int32, namePtr, nameLen, typePtr, dataPtr, dataLenPtr uint32) uint32 {
	return errnoENOSYS
}

// win32RegSetValue always returns errnoENOSYS on non-Windows platforms.
func win32RegSetValue(ctx context.Context, mod api.Module, handle int32, namePtr, nameLen, vtype, dataPtr, dataLen uint32) uint32 {
	return errnoENOSYS
}

// win32RegDeleteValue always returns errnoENOSYS on non-Windows platforms.
func win32RegDeleteValue(ctx context.Context, mod api.Module, handle int32, namePtr, nameLen uint32) uint32 {
	return errnoENOSYS
}

// win32RegEnumKey always returns errnoENOSYS on non-Windows platforms.
func win32RegEnumKey(ctx context.Context, mod api.Module, handle int32, index, namePtr, nameLenPtr uint32) uint32 {
	return errnoENOSYS
}

// win32GetComputerName always returns errnoENOSYS on non-Windows platforms.
func win32GetComputerName(ctx context.Context, mod api.Module, bufPtr, bufLenPtr uint32) uint32 {
	return errnoENOSYS
}

// win32CreateProcess always returns errnoENOSYS on non-Windows platforms.
func win32CreateProcess(ctx context.Context, mod api.Module, cmdlinePtr, cmdlineLen, flags, pidPtr, handlePtr uint32) uint32 {
	return errnoENOSYS
}

// win32OpenProcess always returns errnoENOSYS on non-Windows platforms.
func win32OpenProcess(ctx context.Context, mod api.Module, access, pid, handlePtr uint32) uint32 {
	return errnoENOSYS
}

// win32TerminateProcess always returns errnoENOSYS on non-Windows platforms.
func win32TerminateProcess(ctx context.Context, mod api.Module, handle int32, exitCode uint32) uint32 {
	return errnoENOSYS
}

// win32CloseHandle always returns errnoENOSYS on non-Windows platforms.
func win32CloseHandle(ctx context.Context, mod api.Module, handle int32) uint32 {
	return errnoENOSYS
}

// win32CreateFile always returns errnoENOSYS on non-Windows platforms.
func win32CreateFile(ctx context.Context, mod api.Module, pathPtr, pathLen, access, share, creation, flags, handlePtr uint32) uint32 {
	return errnoENOSYS
}

// win32ReadFile always returns errnoENOSYS on non-Windows platforms.
func win32ReadFile(ctx context.Context, mod api.Module, handle int32, bufPtr, bufLen, nreadPtr uint32) uint32 {
	return errnoENOSYS
}

// win32WriteFile always returns errnoENOSYS on non-Windows platforms.
func win32WriteFile(ctx context.Context, mod api.Module, handle int32, bufPtr, bufLen, nwrittenPtr uint32) uint32 {
	return errnoENOSYS
}

// win32GetFileAttrs always returns errnoENOSYS on non-Windows platforms.
func win32GetFileAttrs(ctx context.Context, mod api.Module, pathPtr, pathLen, attrsPtr uint32) uint32 {
	return errnoENOSYS
}

// win32SetFileAttrs always returns errnoENOSYS on non-Windows platforms.
func win32SetFileAttrs(ctx context.Context, mod api.Module, pathPtr, pathLen, attrs uint32) uint32 {
	return errnoENOSYS
}

// win32OpenProcessToken always returns errnoENOSYS on non-Windows platforms.
func win32OpenProcessToken(ctx context.Context, mod api.Module, procHandle int32, access, tokenPtr uint32) uint32 {
	return errnoENOSYS
}

// win32GetTokenInfo always returns errnoENOSYS on non-Windows platforms.
func win32GetTokenInfo(ctx context.Context, mod api.Module, token int32, infoClass, bufPtr, bufLen, neededPtr uint32) uint32 {
	return errnoENOSYS
}

// win32OpenSCManager always returns errnoENOSYS on non-Windows platforms.
func win32OpenSCManager(ctx context.Context, mod api.Module, machinePtr, machineLen, access, handlePtr uint32) uint32 {
	return errnoENOSYS
}

// win32QueryServiceStatus always returns errnoENOSYS on non-Windows platforms.
func win32QueryServiceStatus(ctx context.Context, mod api.Module, svcHandle int32, statusPtr uint32) uint32 {
	return errnoENOSYS
}

// NativeAOT-specific stubs (SDDL, LSA, RPC, WMI) are in
// nativeaot_security_stub.go behind the "nativeaot" build tag.

// win32SyscallN always returns errnoENOSYS on non-Windows platforms.
func win32SyscallN(ctx context.Context, mod api.Module, proc int32, nargs int32, argsPtr, ret1Ptr, ret2Ptr, lastErrPtr uint32) uint32 {
	return errnoENOSYS
}

func win32FindFiles(ctx context.Context, mod api.Module, rootPtr, rootLen, patternPtr, patternLen uint32, maxDepth, maxMatches int32, bufPtr, bufCap, countPtr uint32) uint32 {
	return errnoENOSYS
}
