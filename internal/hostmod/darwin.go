//go:build darwin

package hostmod

import (
	"context"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// registerDarwinFunctions adds all Darwin/macOS framework bridge host functions
// to the provided builder and returns the extended builder.
//
// The following functions are registered (with WASM export names):
//
//	darwin_available       ()                          → i32
//	darwin_load            (i32,i32,i32)               → i32
//	darwin_get_symbol      (i32,i32,i32,i32)           → i32
//	darwin_call            (i32,i32,i32,i32)           → i32
//	darwin_call_raw        (i32,i32,i32,i32)           → i32
//	darwin_mem_read        (i32,i32,i32,i32)           → i32
//	darwin_mem_write       (i32,i32,i32,i32)           → i32
func registerDarwinFunctions(b wazero.HostModuleBuilder) wazero.HostModuleBuilder {
	return b.
		// darwin_available: () → i32
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			stack[0] = uint64(darwinAvailable(ctx, mod))
		}), []api.ValueType{}, []api.ValueType{api.ValueTypeI32}).
		Export(export("darwin_available")).

		// darwin_load: name_ptr, name_len, handle_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			namePtr := uint32(stack[0])
			nameLen := uint32(stack[1])
			handlePtr := uint32(stack[2])
			stack[0] = uint64(darwinLoad(ctx, mod, namePtr, nameLen, handlePtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("name_ptr", "name_len", "handle_ptr").
		Export(export("darwin_load")).

		// darwin_get_symbol: lib_handle, name_ptr, name_len, sym_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			libHandle := int32(stack[0])
			namePtr := uint32(stack[1])
			nameLen := uint32(stack[2])
			symPtr := uint32(stack[3])
			stack[0] = uint64(darwinGetSymbol(ctx, mod, libHandle, namePtr, nameLen, symPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("lib_handle", "name_ptr", "name_len", "sym_ptr").
		Export(export("darwin_get_symbol")).

		// darwin_call: sym_handle, nargs, args_ptr, ret_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			symHandle := int32(stack[0])
			nargs := int32(stack[1])
			argsPtr := uint32(stack[2])
			retPtr := uint32(stack[3])
			stack[0] = uint64(darwinCall(ctx, mod, symHandle, nargs, argsPtr, retPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("sym_handle", "nargs", "args_ptr", "ret_ptr").
		Export(export("darwin_call")).

		// darwin_call_masked: sym_handle, nargs, args_ptr, ptr_mask, ret_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			symHandle := int32(stack[0])
			nargs := int32(stack[1])
			argsPtr := uint32(stack[2])
			ptrMask := int32(stack[3])
			retPtr := uint32(stack[4])
			stack[0] = uint64(darwinCallMasked(ctx, mod, symHandle, nargs, argsPtr, ptrMask, retPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("sym_handle", "nargs", "args_ptr", "ptr_mask", "ret_ptr").
		Export(export("darwin_call_masked")).

		// darwin_call_raw: sym_handle, nargs, args_ptr, ret_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			symHandle := int32(stack[0])
			nargs := int32(stack[1])
			argsPtr := uint32(stack[2])
			retPtr := uint32(stack[3])
			stack[0] = uint64(darwinCallRaw(ctx, mod, symHandle, nargs, argsPtr, retPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("sym_handle", "nargs", "args_ptr", "ret_ptr").
		Export(export("darwin_call_raw")).

		// darwin_mem_read: addr_ptr, offset, buf_ptr, buf_len → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			addrPtr := uint32(stack[0])
			offset := uint32(stack[1])
			bufPtr := uint32(stack[2])
			bufLen := uint32(stack[3])
			stack[0] = uint64(darwinMemRead(ctx, mod, addrPtr, offset, bufPtr, bufLen))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("addr_ptr", "offset", "buf_ptr", "buf_len").
		Export(export("darwin_mem_read")).

		// darwin_mem_write: addr_ptr, offset, data_ptr, data_len → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			addrPtr := uint32(stack[0])
			offset := uint32(stack[1])
			dataPtr := uint32(stack[2])
			dataLen := uint32(stack[3])
			stack[0] = uint64(darwinMemWrite(ctx, mod, addrPtr, offset, dataPtr, dataLen))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("addr_ptr", "offset", "data_ptr", "data_len").
		Export(export("darwin_mem_write")).

		// darwin_callback_create: nargs, id_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			nargs := uint32(stack[0])
			idPtr := uint32(stack[1])
			stack[0] = uint64(darwinCallbackCreate(ctx, mod, nargs, idPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("nargs", "id_ptr").
		Export(export("darwin_callback_create")).

		// darwin_callback_addr: id, addr_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			id := uint32(stack[0])
			addrPtr := uint32(stack[1])
			stack[0] = uint64(darwinCallbackAddr(ctx, mod, id, addrPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("id", "addr_ptr").
		Export(export("darwin_callback_addr")).

		// darwin_callback_wait: id, args_ptr, args_cap, nargs_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			id := uint32(stack[0])
			argsPtr := uint32(stack[1])
			argsCap := uint32(stack[2])
			nargsPtr := uint32(stack[3])
			stack[0] = uint64(darwinCallbackWait(ctx, mod, id, argsPtr, argsCap, nargsPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("id", "args_ptr", "args_cap", "nargs_ptr").
		Export(export("darwin_callback_wait")).

		// darwin_callback_return: id, result_lo, result_hi → errno
		// result is split into two i32 values for WASM compatibility.
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			id := uint32(stack[0])
			result := stack[1]
			stack[0] = uint64(darwinCallbackReturn(ctx, mod, id, result))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI64}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("id", "result").
		Export(export("darwin_callback_return")).

		// darwin_callback_free: id → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			id := uint32(stack[0])
			stack[0] = uint64(darwinCallbackFree(ctx, mod, id))
		}), []api.ValueType{api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("id").
		Export(export("darwin_callback_free")).

		// darwin_read_cstring: host_addr_ptr, buf_ptr, buf_len, actual_len_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			hostAddrPtr := uint32(stack[0])
			bufPtr := uint32(stack[1])
			bufLen := uint32(stack[2])
			actualLenPtr := uint32(stack[3])
			stack[0] = uint64(darwinReadCString(ctx, mod, hostAddrPtr, bufPtr, bufLen, actualLenPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("host_addr_ptr", "buf_ptr", "buf_len", "actual_len_ptr").
		Export(export("darwin_read_cstring")).

		// darwin_block_create: cb_id, sig_ptr, sig_len, block_id_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			cbID := uint32(stack[0])
			sigPtr := uint32(stack[1])
			sigLen := uint32(stack[2])
			blockIDPtr := uint32(stack[3])
			stack[0] = uint64(darwinBlockCreate(ctx, mod, cbID, sigPtr, sigLen, blockIDPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("cb_id", "sig_ptr", "sig_len", "block_id_ptr").
		Export(export("darwin_block_create")).

		// darwin_block_release: block_id → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			blockID := uint32(stack[0])
			stack[0] = uint64(darwinBlockRelease(ctx, mod, blockID))
		}), []api.ValueType{api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("block_id").
		Export(export("darwin_block_release")).

		// darwin_block_addr: block_id, addr_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			blockID := uint32(stack[0])
			addrPtr := uint32(stack[1])
			stack[0] = uint64(darwinBlockAddr(ctx, mod, blockID, addrPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("block_id", "addr_ptr").
		Export(export("darwin_block_addr"))
}
