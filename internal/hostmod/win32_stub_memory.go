//go:build !windows

package hostmod

import (
	"context"

	"github.com/tetratelabs/wazero/api"
)

// win32VirtualAlloc always returns errnoENOSYS on non-Windows platforms.
func win32VirtualAlloc(ctx context.Context, mod api.Module, size, allocType, protect, handlePtr uint32) uint32 {
	return errnoENOSYS
}

// win32VirtualProtect always returns errnoENOSYS on non-Windows platforms.
func win32VirtualProtect(ctx context.Context, mod api.Module, handle int32, newProtect, oldProtectPtr uint32) uint32 {
	return errnoENOSYS
}

// win32VirtualFree always returns errnoENOSYS on non-Windows platforms.
func win32VirtualFree(ctx context.Context, mod api.Module, handle int32) uint32 {
	return errnoENOSYS
}

// win32HMemWrite always returns errnoENOSYS on non-Windows platforms.
func win32HMemWrite(ctx context.Context, mod api.Module, handle int32, offset, dataPtr, dataLen uint32) uint32 {
	return errnoENOSYS
}

// win32HMemRead always returns errnoENOSYS on non-Windows platforms.
func win32HMemRead(ctx context.Context, mod api.Module, handle int32, offset, bufPtr, bufLen uint32) uint32 {
	return errnoENOSYS
}

// win32HMemWrite32 always returns errnoENOSYS on non-Windows platforms.
func win32HMemWrite32(ctx context.Context, mod api.Module, handle int32, offset, value uint32) uint32 {
	return errnoENOSYS
}

// win32HMemWrite64 always returns errnoENOSYS on non-Windows platforms.
func win32HMemWrite64(ctx context.Context, mod api.Module, handle int32, offset, valPtr uint32) uint32 {
	return errnoENOSYS
}

// win32HMemRead32 always returns errnoENOSYS on non-Windows platforms.
func win32HMemRead32(ctx context.Context, mod api.Module, handle int32, offset, valPtr uint32) uint32 {
	return errnoENOSYS
}

// win32HMemRead64 always returns errnoENOSYS on non-Windows platforms.
func win32HMemRead64(ctx context.Context, mod api.Module, handle int32, offset, valPtr uint32) uint32 {
	return errnoENOSYS
}

// win32ProcFromHMem always returns errnoENOSYS on non-Windows platforms.
func win32ProcFromHMem(ctx context.Context, mod api.Module, hmemHandle int32, offset, procPtr uint32) uint32 {
	return errnoENOSYS
}

// win32ProcAddr always returns errnoENOSYS on non-Windows platforms.
func win32ProcAddr(ctx context.Context, mod api.Module, procHandle int32, addrPtr uint32) uint32 {
	return errnoENOSYS
}

// win32HMemAddr always returns errnoENOSYS on non-Windows platforms.
func win32HMemAddr(ctx context.Context, mod api.Module, handle int32, addrPtr uint32) uint32 {
	return errnoENOSYS
}
