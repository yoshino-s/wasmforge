//go:build !windows

package hostmod

import (
	"context"

	"github.com/tetratelabs/wazero/api"
)

// win32ExtGetFunc always returns errnoENOSYS on non-Windows platforms.
func win32ExtGetFunc(ctx context.Context, mod api.Module, funcId uint32, addrPtr uint32) uint32 {
	return errnoENOSYS
}

// win32ExtReadOutput always returns errnoENOSYS on non-Windows platforms.
func win32ExtReadOutput(ctx context.Context, mod api.Module, bufPtr, bufLen, actualLenPtr uint32) uint32 {
	return errnoENOSYS
}

// win32ExtResetOutput always returns errnoENOSYS on non-Windows platforms.
func win32ExtResetOutput(ctx context.Context, mod api.Module) uint32 {
	return errnoENOSYS
}

// win32NewCallback always returns errnoENOSYS on non-Windows platforms.
func win32NewCallback(ctx context.Context, mod api.Module, namePtr, nameLen, addrPtr uint32) uint32 {
	return errnoENOSYS
}
