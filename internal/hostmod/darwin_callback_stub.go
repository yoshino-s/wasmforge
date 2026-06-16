//go:build !darwin

package hostmod

import (
	"context"

	"github.com/tetratelabs/wazero/api"
)

func darwinCallbackCreate(ctx context.Context, mod api.Module, nargs uint32, idPtr uint32) uint32 {
	return errnoENOSYS
}

func darwinCallbackAddr(ctx context.Context, mod api.Module, id uint32, addrPtr uint32) uint32 {
	return errnoENOSYS
}

func darwinCallbackWait(ctx context.Context, mod api.Module, id, argsPtr, argsCap, nargsPtr uint32) uint32 {
	return errnoENOSYS
}

func darwinCallbackReturn(ctx context.Context, mod api.Module, id uint32, result uint64) uint32 {
	return errnoENOSYS
}

func darwinCallbackFree(ctx context.Context, mod api.Module, id uint32) uint32 {
	return errnoENOSYS
}

func darwinReadCString(ctx context.Context, mod api.Module, hostAddrPtr, bufPtr, bufLen, actualLenPtr uint32) uint32 {
	return errnoENOSYS
}

func darwinBlockCreate(ctx context.Context, mod api.Module, cbID uint32, sigPtr, sigLen, blockIDPtr uint32) uint32 {
	return errnoENOSYS
}

func darwinBlockRelease(ctx context.Context, mod api.Module, blockID uint32) uint32 {
	return errnoENOSYS
}

func darwinBlockAddr(ctx context.Context, mod api.Module, blockID uint32, addrPtr uint32) uint32 {
	return errnoENOSYS
}
