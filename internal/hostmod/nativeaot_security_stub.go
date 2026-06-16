//go:build nativeaot && !windows

package hostmod

import (
	"context"

	"github.com/tetratelabs/wazero/api"
)

func win32EnumLogonSessions(ctx context.Context, mod api.Module, outBufPtr, outBufLen uint32) uint32 {
	return 0
}

func win32ParseSddlAcl(ctx context.Context, mod api.Module, sddlPtr, sddlLen, outBufPtr, outBufLen uint32) uint32 {
	return 0
}

func win32GetSddl(ctx context.Context, mod api.Module, pathPtr, outBufPtr, outBufLen uint32) uint32 {
	return 0
}

func win32EnumUserRights(ctx context.Context, mod api.Module, outBufPtr, outBufLen uint32) uint32 {
	return 0
}

func win32EnumRPCEndpoints(ctx context.Context, mod api.Module, outBufPtr, outBufLen uint32) uint32 {
	return 0
}

func win32WmiQuery(ctx context.Context, mod api.Module, queryPtr, queryLen, nsPtr, nsLen, outBufPtr, outBufLen uint32) uint32 {
	return 0
}

func win32WmiMethod(ctx context.Context, mod api.Module,
	nsPtr, nsLen, classPtr, classLen, methodPtr, methodLen,
	inJsonPtr, inJsonLen, outBufPtr, outBufLen uint32) uint32 {
	return 0
}

func win32EnumNetworkAdapters(ctx context.Context, mod api.Module, outBufPtr, outBufLen uint32) uint32 {
	return 0
}

func win32GetFileVersionInfo(ctx context.Context, mod api.Module, pathPtr, pathLen, outBufPtr, outBufLen uint32) uint32 {
	return 0
}

func win32LsaKerberosOp(ctx context.Context, mod api.Module, opPtr, opLen, luidLow, luidHigh, outBufPtr, outBufLen uint32) uint32 {
	return 0
}

func win32CheckModifiableKey(_ context.Context, mod api.Module, stack []uint64) {
	stack[0] = 0
}

func win32CheckModifiableService(_ context.Context, mod api.Module, stack []uint64) {
	stack[0] = 0
}

func win32EnumProcessModules(_ context.Context, mod api.Module, stack []uint64) {
	stack[0] = 0
}

