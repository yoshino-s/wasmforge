//go:build nativeaot && !windows

package hostmod

import (
	"context"

	"github.com/tetratelabs/wazero/api"
)

func win32Pbkdf2Sha1(ctx context.Context, mod api.Module, passwordPtr, passwordLen, saltPtr, saltLen, iterations, keyLen, outBufPtr, outBufLen uint32) uint32 {
	return 0
}

func win32Pbkdf2Sha256(ctx context.Context, mod api.Module, passwordPtr, passwordLen, saltPtr, saltLen, iterations, keyLen, outBufPtr, outBufLen uint32) uint32 {
	return 0
}

func win32Pbkdf2Sha512(ctx context.Context, mod api.Module, passwordPtr, passwordLen, saltPtr, saltLen, iterations, keyLen, outBufPtr, outBufLen uint32) uint32 {
	return 0
}

func win32HmacSha1(ctx context.Context, mod api.Module, keyPtr, keyLen, dataPtr, dataLen, outBufPtr, outBufLen uint32) uint32 {
	return 0
}

func win32HmacSha256(ctx context.Context, mod api.Module, keyPtr, keyLen, dataPtr, dataLen, outBufPtr, outBufLen uint32) uint32 {
	return 0
}

func win32AesCbcDecrypt(ctx context.Context, mod api.Module, keyPtr, keyLen, ivPtr, ivLen, dataPtr, dataLen, outBufPtr, outBufLen uint32) uint32 {
	return 0
}

// win32Sha1 removed in Phase B — WASM-side via wf_call(bcrypt.dll).

func win32Sha256(ctx context.Context, mod api.Module, dataPtr, dataLen, outBufPtr, outBufLen uint32) uint32 {
	return 0
}

// Generic crypto dispatcher stub for non-Windows targets.
func nativeaotCryptoOp(ctx context.Context, mod api.Module,
	opPtr, opLen, argsPtr, argsLen, outPtr, outCap uint32) uint32 {
	return 0
}
