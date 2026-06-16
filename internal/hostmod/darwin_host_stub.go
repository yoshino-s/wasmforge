//go:build !darwin

package hostmod

import (
	"context"

	"github.com/tetratelabs/wazero/api"
)

// darwinAvailable returns 0 on non-darwin platforms (darwin APIs not available).
func darwinAvailable(ctx context.Context, mod api.Module) uint32 {
	return 0
}

// darwinLoad always returns errnoENOSYS on non-darwin platforms.
func darwinLoad(ctx context.Context, mod api.Module, namePtr, nameLen, handlePtr uint32) uint32 {
	return errnoENOSYS
}

// darwinGetSymbol always returns errnoENOSYS on non-darwin platforms.
func darwinGetSymbol(ctx context.Context, mod api.Module, libHandle int32, namePtr, nameLen, symPtr uint32) uint32 {
	return errnoENOSYS
}

// darwinCall always returns errnoENOSYS on non-darwin platforms.
func darwinCall(ctx context.Context, mod api.Module, symHandle int32, nargs int32, argsPtr, retPtr uint32) uint32 {
	return errnoENOSYS
}

func darwinCallMasked(ctx context.Context, mod api.Module, symHandle int32, nargs int32, argsPtr uint32, ptrMask int32, retPtr uint32) uint32 {
	return errnoENOSYS
}

// darwinCallRaw always returns errnoENOSYS on non-darwin platforms.
func darwinCallRaw(ctx context.Context, mod api.Module, symHandle int32, nargs int32, argsPtr, retPtr uint32) uint32 {
	return errnoENOSYS
}

// darwinMemRead always returns errnoENOSYS on non-darwin platforms.
func darwinMemRead(ctx context.Context, mod api.Module, addrPtr, offset, bufPtr, bufLen uint32) uint32 {
	return errnoENOSYS
}

// darwinMemWrite always returns errnoENOSYS on non-darwin platforms.
func darwinMemWrite(ctx context.Context, mod api.Module, addrPtr, offset, dataPtr, dataLen uint32) uint32 {
	return errnoENOSYS
}
