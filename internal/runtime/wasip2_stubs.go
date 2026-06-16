//go:build nativeaot

// WASI Preview 2 stubs for NativeAOT-WASI modules.
// These are ONLY registered when the "nativeaot" build tag is active.
// Standard Go WASM modules use WASI Preview 1 and don't need P2 stubs.

package runtime

import (
	"context"
	"os"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// registerWASIP2Stubs registers stub host modules for WASI Preview 2 functions
// that NativeAOT-LLVM compiled WASM modules may import. The stubs provide
// enough no-op behavior to satisfy the linker/instantiator without crashing.
func registerWASIP2Stubs(ctx context.Context, rt wazero.Runtime, args []string) error {
	if err := registerIOPoll(ctx, rt); err != nil {
		return err
	}
	if err := registerIOStreams(ctx, rt); err != nil {
		return err
	}
	if err := registerSocketsUDP(ctx, rt); err != nil {
		return err
	}
	if err := registerSocketsTCP(ctx, rt); err != nil {
		return err
	}
	if err := registerMonotonicClock(ctx, rt); err != nil {
		return err
	}
	if err := registerIOError(ctx, rt); err != nil {
		return err
	}
	if err := registerHTTPTypes(ctx, rt); err != nil {
		return err
	}
	if err := registerHTTPOutgoing(ctx, rt); err != nil {
		return err
	}
	if err := registerSocketsInstanceNetwork(ctx, rt); err != nil {
		return err
	}
	if err := registerSocketsTCPCreate(ctx, rt); err != nil {
		return err
	}
	if err := registerSocketsUDPCreate(ctx, rt); err != nil {
		return err
	}
	if err := registerIPNameLookup(ctx, rt); err != nil {
		return err
	}

	// CLI / filesystem / wall-clock / random — needed by NativeAOT-WASI
	// binaries whose P2 imports survived the component-ld bypass.
	if err := registerCLIEnvironment(ctx, rt, args); err != nil {
		return err
	}
	if err := registerCLIExit(ctx, rt); err != nil {
		return err
	}
	if err := registerCLIStdStreams(ctx, rt); err != nil {
		return err
	}
	if err := registerCLITerminal(ctx, rt); err != nil {
		return err
	}
	if err := registerFilesystemTypes(ctx, rt); err != nil {
		return err
	}
	if err := registerFilesystemPreopens(ctx, rt); err != nil {
		return err
	}
	if err := registerWallClock(ctx, rt); err != nil {
		return err
	}
	return registerRandom(ctx, rt)
}

// registerIOError registers stubs for wasi:io/error@0.2.0.
func registerIOError(ctx context.Context, rt wazero.Runtime) error {
	_, err := rt.NewHostModuleBuilder("wasi:io/error@0.2.0").
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, _ api.Module, _ []uint64) {}),
			[]api.ValueType{api.ValueTypeI32}, []api.ValueType{}).
		Export("[resource-drop]error").
		Instantiate(ctx)
	return err
}

// registerHTTPTypes registers stubs for wasi:http/types@0.2.0.
// Signatures extracted from the WASM binary's import section.
func registerHTTPTypes(ctx context.Context, rt wazero.Runtime) error {
	noop1 := api.GoModuleFunc(func(_ context.Context, _ api.Module, _ []uint64) {})
	retZero1 := api.GoModuleFunc(func(_ context.Context, _ api.Module, stack []uint64) { stack[0] = 0 })

	i32 := api.ValueTypeI32
	b := rt.NewHostModuleBuilder("wasi:http/types@0.2.0")

	// (i32) → void: resource drops
	for _, n := range []string{
		"[resource-drop]fields", "[resource-drop]future-incoming-response",
		"[resource-drop]future-trailers", "[resource-drop]incoming-body",
		"[resource-drop]incoming-response", "[resource-drop]outgoing-body",
		"[resource-drop]outgoing-request",
	} {
		b = b.NewFunctionBuilder().WithGoModuleFunction(noop1, []api.ValueType{i32}, nil).Export(n)
	}

	// (i32) → i32
	for _, n := range []string{
		"[constructor]outgoing-request", "[method]future-incoming-response.subscribe",
		"[method]incoming-response.headers", "[method]incoming-response.status",
		"[static]incoming-body.finish",
	} {
		b = b.NewFunctionBuilder().WithGoModuleFunction(retZero1, []api.ValueType{i32}, []api.ValueType{i32}).Export(n)
	}

	// (i32, i32) → void
	for _, n := range []string{
		"[method]fields.entries", "[method]future-incoming-response.get",
		"[method]incoming-body.stream", "[method]incoming-response.consume",
		"[method]outgoing-body.write", "[method]outgoing-request.body",
	} {
		b = b.NewFunctionBuilder().WithGoModuleFunction(noop1, []api.ValueType{i32, i32}, nil).Export(n)
	}

	// (i32, i32, i32) → void
	b = b.NewFunctionBuilder().WithGoModuleFunction(noop1, []api.ValueType{i32, i32, i32}, nil).Export("[static]fields.from-list")

	// (i32, i32, i32, i32) → i32: setters
	for _, n := range []string{
		"[method]outgoing-request.set-authority",
		"[method]outgoing-request.set-method",
		"[method]outgoing-request.set-path-with-query",
	} {
		b = b.NewFunctionBuilder().WithGoModuleFunction(retZero1, []api.ValueType{i32, i32, i32, i32}, []api.ValueType{i32}).Export(n)
	}

	// (i32, i32, i32, i32, i32) → i32: set-scheme (has extra variant discriminant)
	b = b.NewFunctionBuilder().WithGoModuleFunction(retZero1, []api.ValueType{i32, i32, i32, i32, i32}, []api.ValueType{i32}).Export("[method]outgoing-request.set-scheme")

	// (i32, i32, i32, i32) → void: outgoing-body.finish
	b = b.NewFunctionBuilder().WithGoModuleFunction(noop1, []api.ValueType{i32, i32, i32, i32}, nil).Export("[static]outgoing-body.finish")

	_, err := b.Instantiate(ctx)
	return err
}

// registerHTTPOutgoing registers stubs for wasi:http/outgoing-handler@0.2.0.
func registerHTTPOutgoing(ctx context.Context, rt wazero.Runtime) error {
	_, err := rt.NewHostModuleBuilder("wasi:http/outgoing-handler@0.2.0").
		// handle: (i32, i32, i32, i32) → void — outgoing request handler, write error to result
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, mod api.Module, stack []uint64) {
			resultPtr := uint32(stack[3])
			if resultPtr != 0 {
				mod.Memory().WriteUint32Le(resultPtr, 1) // error variant
			}
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{}).
		Export("handle").
		Instantiate(ctx)
	return err
}

// registerIOPoll registers stubs for wasi:io/poll@0.2.0.
func registerIOPoll(ctx context.Context, rt wazero.Runtime) error {
	_, err := rt.NewHostModuleBuilder("wasi:io/poll@0.2.0").
		// [resource-drop]pollable: (i32) → void — drop a pollable handle, no-op
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, _ api.Module, _ []uint64) {}),
			[]api.ValueType{api.ValueTypeI32}, []api.ValueType{}).
		Export("[resource-drop]pollable").
		// poll: (i32, i32, i32) → void — write 0 to result pointer
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, mod api.Module, stack []uint64) {
			// stack[2] is the result pointer; write 0 (zero results ready)
			resultPtr := uint32(stack[2])
			if resultPtr != 0 {
				mod.Memory().WriteUint32Le(resultPtr, 0)
			}
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{}).
		Export("poll").
		// [method]pollable.block: (i32) → void — block until pollable is ready, no-op
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, _ api.Module, _ []uint64) {}),
			[]api.ValueType{api.ValueTypeI32}, []api.ValueType{}).
		Export("[method]pollable.block").
		// [method]pollable.ready: (i32) → i32 — check if pollable is ready, always return 1 (true)
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, _ api.Module, stack []uint64) {
			stack[0] = 1 // true — always ready
		}), []api.ValueType{api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		Export("[method]pollable.ready").
		Instantiate(ctx)
	return err
}

// registerIOStreams registers stubs for wasi:io/streams@0.2.0.
func registerIOStreams(ctx context.Context, rt wazero.Runtime) error {
	noop := api.GoModuleFunc(func(_ context.Context, _ api.Module, _ []uint64) {})
	retZeroI32 := api.GoModuleFunc(func(_ context.Context, _ api.Module, stack []uint64) { stack[0] = 0 })

	_, err := rt.NewHostModuleBuilder("wasi:io/streams@0.2.0").
		// [resource-drop]input-stream: (i32) → void
		NewFunctionBuilder().
		WithGoModuleFunction(noop, []api.ValueType{api.ValueTypeI32}, []api.ValueType{}).
		Export("[resource-drop]input-stream").
		// [resource-drop]output-stream: (i32) → void
		NewFunctionBuilder().
		WithGoModuleFunction(noop, []api.ValueType{api.ValueTypeI32}, []api.ValueType{}).
		Export("[resource-drop]output-stream").
		// [method]input-stream.subscribe: (i32) → i32
		NewFunctionBuilder().
		WithGoModuleFunction(retZeroI32, []api.ValueType{api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		Export("[method]input-stream.subscribe").
		// [method]output-stream.subscribe: (i32) → i32
		NewFunctionBuilder().
		WithGoModuleFunction(retZeroI32, []api.ValueType{api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		Export("[method]output-stream.subscribe").
		// [method]input-stream.read: (i32, i64, i32) → void — write error to result
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, mod api.Module, stack []uint64) {
			resultPtr := uint32(stack[2])
			if resultPtr != 0 {
				mod.Memory().WriteUint32Le(resultPtr, 1) // error
			}
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI64, api.ValueTypeI32}, []api.ValueType{}).
		Export("[method]input-stream.read").
		// [method]output-stream.write: (self, buf_ptr, buf_len, retptr) → void
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, m api.Module, stack []uint64) {
			self := uint32(stack[0])
			bufPtr := uint32(stack[1])
			bufLen := uint32(stack[2])
			retPtr := uint32(stack[3])
			if mem := m.Memory(); mem != nil {
				if data, ok := mem.Read(bufPtr, bufLen); ok {
					switch self {
					case 3:
						os.Stderr.Write(data)
					default:
						os.Stdout.Write(data)
					}
				}
				mem.WriteByte(retPtr, 0)
			}
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, nil).
		Export("[method]output-stream.write").
		// [method]output-stream.flush: (self, retptr) → void — write success
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, m api.Module, stack []uint64) {
			if mem := m.Memory(); mem != nil {
				mem.WriteByte(uint32(stack[1]), 0)
			}
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, nil).
		Export("[method]output-stream.flush").
		// [method]output-stream.check-write: (self, retptr) → void
		// retptr stores result<u64, stream-error>: 4-byte tag + 8-byte payload.
		// Write tag=0 (ok), payload = max u32 (advertise lots of write capacity).
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, m api.Module, stack []uint64) {
			retPtr := uint32(stack[1])
			if mem := m.Memory(); mem != nil {
				mem.WriteUint32Le(retPtr, 0)
				mem.WriteUint64Le(retPtr+8, 0x100000) // 1 MiB write capacity
			}
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, nil).
		Export("[method]output-stream.check-write").
		// [method]output-stream.blocking-flush: (i32, i32) → void
		NewFunctionBuilder().
		WithGoModuleFunction(noop, []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, nil).
		Export("[method]output-stream.blocking-flush").
		// [method]output-stream.blocking-write-and-flush: (self, buf_ptr, buf_len, retptr) → void
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, m api.Module, stack []uint64) {
			self := uint32(stack[0])
			bufPtr := uint32(stack[1])
			bufLen := uint32(stack[2])
			retPtr := uint32(stack[3])
			if mem := m.Memory(); mem != nil {
				if data, ok := mem.Read(bufPtr, bufLen); ok {
					switch self {
					case 2:
						os.Stdout.Write(data)
					case 3:
						os.Stderr.Write(data)
					default:
						os.Stdout.Write(data)
					}
				}
				mem.WriteByte(retPtr, 0) // success
			}
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, nil).
		Export("[method]output-stream.blocking-write-and-flush").
		// [method]output-stream.write-zeroes: (i32, i64, i32) → void
		NewFunctionBuilder().
		WithGoModuleFunction(noop, []api.ValueType{api.ValueTypeI32, api.ValueTypeI64, api.ValueTypeI32}, nil).
		Export("[method]output-stream.write-zeroes").
		// [method]output-stream.blocking-write-zeroes-and-flush: (i32, i64, i32) → void
		NewFunctionBuilder().
		WithGoModuleFunction(noop, []api.ValueType{api.ValueTypeI32, api.ValueTypeI64, api.ValueTypeI32}, nil).
		Export("[method]output-stream.blocking-write-zeroes-and-flush").
		// [method]output-stream.splice: (i32, i32, i64, i32) → void
		NewFunctionBuilder().
		WithGoModuleFunction(noop, []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI64, api.ValueTypeI32}, nil).
		Export("[method]output-stream.splice").
		// [method]output-stream.blocking-splice: (i32, i32, i64, i32) → void
		NewFunctionBuilder().
		WithGoModuleFunction(noop, []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI64, api.ValueTypeI32}, nil).
		Export("[method]output-stream.blocking-splice").
		// [method]input-stream.blocking-read: (i32, i64, i32) → void
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, mod api.Module, stack []uint64) {
			resultPtr := uint32(stack[2])
			if resultPtr != 0 {
				mod.Memory().WriteUint32Le(resultPtr, 1) // error
			}
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI64, api.ValueTypeI32}, []api.ValueType{}).
		Export("[method]input-stream.blocking-read").
		// [method]input-stream.skip: (i32, i64, i32) → void
		NewFunctionBuilder().
		WithGoModuleFunction(noop, []api.ValueType{api.ValueTypeI32, api.ValueTypeI64, api.ValueTypeI32}, nil).
		Export("[method]input-stream.skip").
		// [method]input-stream.blocking-skip: (i32, i64, i32) → void
		NewFunctionBuilder().
		WithGoModuleFunction(noop, []api.ValueType{api.ValueTypeI32, api.ValueTypeI64, api.ValueTypeI32}, nil).
		Export("[method]input-stream.blocking-skip").
		Instantiate(ctx)
	return err
}

// registerSocketsUDP registers stubs for wasi:sockets/udp@0.2.0.
func registerSocketsUDP(ctx context.Context, rt wazero.Runtime) error {
	noop := api.GoModuleFunc(func(_ context.Context, _ api.Module, _ []uint64) {})
	retZero := api.GoModuleFunc(func(_ context.Context, _ api.Module, stack []uint64) { stack[0] = 0 })
	i32 := api.ValueTypeI32
	i64 := api.ValueTypeI64

	b := rt.NewHostModuleBuilder("wasi:sockets/udp@0.2.0")

	// resource drops: (i32) → void
	for _, n := range []string{
		"[resource-drop]udp-socket",
		"[resource-drop]incoming-datagram-stream",
		"[resource-drop]outgoing-datagram-stream",
	} {
		b = b.NewFunctionBuilder().WithGoModuleFunction(noop, []api.ValueType{i32}, nil).Export(n)
	}

	// (i32) → i32: subscribe methods
	for _, n := range []string{
		"[method]udp-socket.subscribe",
		"[method]incoming-datagram-stream.subscribe",
		"[method]outgoing-datagram-stream.subscribe",
	} {
		b = b.NewFunctionBuilder().WithGoModuleFunction(retZero, []api.ValueType{i32}, []api.ValueType{i32}).Export(n)
	}

	// (i32, i32) → void: get-property methods
	for _, n := range []string{
		"[method]udp-socket.unicast-hop-limit",
		"[method]udp-socket.receive-buffer-size",
		"[method]udp-socket.send-buffer-size",
	} {
		b = b.NewFunctionBuilder().WithGoModuleFunction(noop, []api.ValueType{i32, i32}, nil).Export(n)
	}

	// (i32, i32, i32) → void: set-property methods (i32 value)
	for _, n := range []string{
		"[method]udp-socket.set-unicast-hop-limit",
	} {
		b = b.NewFunctionBuilder().WithGoModuleFunction(noop, []api.ValueType{i32, i32, i32}, nil).Export(n)
	}

	// (i32, i64, i32) → void: set-property methods (i64 value)
	for _, n := range []string{
		"[method]udp-socket.set-receive-buffer-size",
		"[method]udp-socket.set-send-buffer-size",
	} {
		b = b.NewFunctionBuilder().WithGoModuleFunction(noop, []api.ValueType{i32, i64, i32}, nil).Export(n)
	}

	// [method]udp-socket.stream: 15 i32 params → void
	b = b.NewFunctionBuilder().WithGoModuleFunction(noop,
		[]api.ValueType{i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32}, nil).
		Export("[method]udp-socket.stream")

	// [method]incoming-datagram-stream.receive: (i32, i64, i32) → void
	b = b.NewFunctionBuilder().WithGoModuleFunction(noop,
		[]api.ValueType{i32, i64, i32}, nil).
		Export("[method]incoming-datagram-stream.receive")

	// finish-bind / address-family / local-address / remote-address
	// take (self_handle, retptr) → 2 args.
	for _, n := range []string{
		"[method]udp-socket.finish-bind",
		"[method]udp-socket.local-address",
		"[method]udp-socket.remote-address",
		"[method]udp-socket.address-family",
		"[method]udp-socket.finish-stream",
		"[method]outgoing-datagram-stream.check-send",
	} {
		b = b.NewFunctionBuilder().WithGoModuleFunction(noop, []api.ValueType{i32, i32}, nil).Export(n)
	}

	// outgoing-datagram-stream.send: (self, list_ptr, list_len, retptr) = 4 args.
	b = b.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, m api.Module, stack []uint64) {
		if mem := m.Memory(); mem != nil {
			mem.WriteUint32Le(uint32(stack[3]), 0) // tag = 0 (ok)
		}
	}), []api.ValueType{i32, i32, i32, i32}, nil).
		Export("[method]outgoing-datagram-stream.send")

	// start-bind: 15 i32 args matching the ip-socket-address variant lowering
	// (self, network_handle, family_tag, 4×u8 ipv4 octets, port, ... + retptr).
	// We don't actually bind — just write a successful (tag=0) result so the
	// caller proceeds. Tools that rely on real socket I/O will hit later stubs
	// and fail gracefully.
	startBind15 := api.GoModuleFunc(func(_ context.Context, m api.Module, stack []uint64) {
		// Last argument is the retptr. Write tag=0 (ok variant) so the caller
		// thinks the bind succeeded.
		if mem := m.Memory(); mem != nil {
			retptr := uint32(stack[14])
			mem.WriteUint32Le(retptr, 0)
		}
	})
	b = b.NewFunctionBuilder().WithGoModuleFunction(startBind15,
		[]api.ValueType{i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32}, nil).
		Export("[method]udp-socket.start-bind")

	_, err := b.Instantiate(ctx)
	return err
}

// registerSocketsTCP registers stubs for wasi:sockets/tcp@0.2.0.
func registerSocketsTCP(ctx context.Context, rt wazero.Runtime) error {
	noop := api.GoModuleFunc(func(_ context.Context, _ api.Module, _ []uint64) {})
	retZero := api.GoModuleFunc(func(_ context.Context, _ api.Module, stack []uint64) { stack[0] = 0 })
	i32 := api.ValueTypeI32
	i64 := api.ValueTypeI64

	b := rt.NewHostModuleBuilder("wasi:sockets/tcp@0.2.0")

	// [resource-drop]tcp-socket: (i32) → void
	b = b.NewFunctionBuilder().WithGoModuleFunction(noop, []api.ValueType{i32}, nil).
		Export("[resource-drop]tcp-socket")

	// (i32, i32) → void: get-property and two-param methods
	for _, n := range []string{
		"[method]tcp-socket.finish-connect",
		"[method]tcp-socket.hop-limit",
		"[method]tcp-socket.receive-buffer-size",
		"[method]tcp-socket.send-buffer-size",
		"[method]tcp-socket.keep-alive-enabled",
		"[method]tcp-socket.keep-alive-idle-time",
		"[method]tcp-socket.keep-alive-interval",
		"[method]tcp-socket.keep-alive-count",
	} {
		b = b.NewFunctionBuilder().WithGoModuleFunction(noop, []api.ValueType{i32, i32}, nil).Export(n)
	}

	// (i32, i32, i32) → void: set-property methods (i32 value) + shutdown
	for _, n := range []string{
		"[method]tcp-socket.set-keep-alive-enabled",
		"[method]tcp-socket.set-hop-limit",
		"[method]tcp-socket.set-keep-alive-count",
		"[method]tcp-socket.shutdown",
	} {
		b = b.NewFunctionBuilder().WithGoModuleFunction(noop, []api.ValueType{i32, i32, i32}, nil).Export(n)
	}

	// (i32, i64, i32) → void: set-property methods (i64 value)
	for _, n := range []string{
		"[method]tcp-socket.set-keep-alive-idle-time",
		"[method]tcp-socket.set-keep-alive-interval",
		"[method]tcp-socket.set-receive-buffer-size",
		"[method]tcp-socket.set-send-buffer-size",
	} {
		b = b.NewFunctionBuilder().WithGoModuleFunction(noop, []api.ValueType{i32, i64, i32}, nil).Export(n)
	}

	// (i32) → i32: subscribe, is-listening
	for _, n := range []string{
		"[method]tcp-socket.subscribe",
		"[method]tcp-socket.is-listening",
	} {
		b = b.NewFunctionBuilder().WithGoModuleFunction(retZero, []api.ValueType{i32}, []api.ValueType{i32}).Export(n)
	}

	// Address-returning / finish-* 2-arg methods.
	for _, n := range []string{
		"[method]tcp-socket.local-address",
		"[method]tcp-socket.remote-address",
		"[method]tcp-socket.address-family",
		"[method]tcp-socket.accept",
		"[method]tcp-socket.finish-listen",
		"[method]tcp-socket.finish-bind",
	} {
		b = b.NewFunctionBuilder().WithGoModuleFunction(noop, []api.ValueType{i32, i32}, nil).Export(n)
	}

	// start-listen — 2 args
	b = b.NewFunctionBuilder().WithGoModuleFunction(noop, []api.ValueType{i32, i32}, nil).Export("[method]tcp-socket.start-listen")
	// set-listen-backlog-size — 3 args: self, u64 size, retptr
	b = b.NewFunctionBuilder().WithGoModuleFunction(noop, []api.ValueType{i32, i64, i32}, nil).
		Export("[method]tcp-socket.set-listen-backlog-size")
	// listen-backlog-size — 2 args
	b = b.NewFunctionBuilder().WithGoModuleFunction(noop, []api.ValueType{i32, i32}, nil).
		Export("[method]tcp-socket.listen-backlog-size")

	// start-bind / start-connect: 15 i32 args (same shape as udp).
	startBindTcp := api.GoModuleFunc(func(_ context.Context, m api.Module, stack []uint64) {
		if mem := m.Memory(); mem != nil {
			mem.WriteUint32Le(uint32(stack[14]), 0)
		}
	})
	for _, n := range []string{
		"[method]tcp-socket.start-bind",
		"[method]tcp-socket.start-connect",
	} {
		b = b.NewFunctionBuilder().WithGoModuleFunction(startBindTcp,
			[]api.ValueType{i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32}, nil).
			Export(n)
	}

	_, err := b.Instantiate(ctx)
	return err
}

// registerMonotonicClock registers stubs for wasi:clocks/monotonic-clock@0.2.0.
func registerMonotonicClock(ctx context.Context, rt wazero.Runtime) error {
	_, err := rt.NewHostModuleBuilder("wasi:clocks/monotonic-clock@0.2.0").
		// subscribe-duration: (i64) → i32 — return dummy pollable handle 0
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, _ api.Module, stack []uint64) {
			stack[0] = 0
		}), []api.ValueType{api.ValueTypeI64}, []api.ValueType{api.ValueTypeI32}).
		Export("subscribe-duration").
		// now: () → i64 — return monotonic nanoseconds
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, _ api.Module, stack []uint64) {
			stack[0] = uint64(time.Now().UnixNano())
		}), nil, []api.ValueType{api.ValueTypeI64}).
		Export("now").
		// resolution: () → i64 — nanosecond resolution
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, _ api.Module, stack []uint64) {
			stack[0] = 1
		}), nil, []api.ValueType{api.ValueTypeI64}).
		Export("resolution").
		// subscribe-instant: (i64) → i32
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, _ api.Module, stack []uint64) {
			stack[0] = 0
		}), []api.ValueType{api.ValueTypeI64}, []api.ValueType{api.ValueTypeI32}).
		Export("subscribe-instant").
		Instantiate(ctx)
	return err
}

// registerSocketsInstanceNetwork registers stubs for wasi:sockets/instance-network@0.2.0.
func registerSocketsInstanceNetwork(ctx context.Context, rt wazero.Runtime) error {
	_, err := rt.NewHostModuleBuilder("wasi:sockets/instance-network@0.2.0").
		// instance-network: () → i32 — return dummy network handle
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, _ api.Module, stack []uint64) {
			stack[0] = 1 // dummy network handle
		}), nil, []api.ValueType{api.ValueTypeI32}).
		Export("instance-network").
		Instantiate(ctx)
	return err
}

// registerSocketsTCPCreate registers stubs for wasi:sockets/tcp-create-socket@0.2.0.
func registerSocketsTCPCreate(ctx context.Context, rt wazero.Runtime) error {
	_, err := rt.NewHostModuleBuilder("wasi:sockets/tcp-create-socket@0.2.0").
		// create-tcp-socket: (i32, i32) → void — write error variant to result ptr
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, mod api.Module, stack []uint64) {
			resultPtr := uint32(stack[1])
			if resultPtr != 0 {
				mod.Memory().WriteUint32Le(resultPtr, 1) // error
			}
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, nil).
		Export("create-tcp-socket").
		Instantiate(ctx)
	return err
}

// registerSocketsUDPCreate registers stubs for wasi:sockets/udp-create-socket@0.2.0.
func registerSocketsUDPCreate(ctx context.Context, rt wazero.Runtime) error {
	_, err := rt.NewHostModuleBuilder("wasi:sockets/udp-create-socket@0.2.0").
		// create-udp-socket: (i32, i32) → void — write error variant to result ptr
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, mod api.Module, stack []uint64) {
			resultPtr := uint32(stack[1])
			if resultPtr != 0 {
				mod.Memory().WriteUint32Le(resultPtr, 1) // error
			}
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, nil).
		Export("create-udp-socket").
		Instantiate(ctx)
	return err
}

// registerIPNameLookup registers stubs for wasi:sockets/ip-name-lookup@0.2.0.
func registerIPNameLookup(ctx context.Context, rt wazero.Runtime) error {
	noop := api.GoModuleFunc(func(_ context.Context, _ api.Module, _ []uint64) {})
	retZero := api.GoModuleFunc(func(_ context.Context, _ api.Module, stack []uint64) { stack[0] = 0 })
	i32 := api.ValueTypeI32

	_, err := rt.NewHostModuleBuilder("wasi:sockets/ip-name-lookup@0.2.0").
		// resolve-addresses: (i32, i32, i32, i32) → void
		NewFunctionBuilder().
		WithGoModuleFunction(noop, []api.ValueType{i32, i32, i32, i32}, nil).
		Export("resolve-addresses").
		// [method]resolve-address-stream.resolve-next-address: (i32, i32) → void
		NewFunctionBuilder().
		WithGoModuleFunction(noop, []api.ValueType{i32, i32}, nil).
		Export("[method]resolve-address-stream.resolve-next-address").
		// [method]resolve-address-stream.subscribe: (i32) → i32
		NewFunctionBuilder().
		WithGoModuleFunction(retZero, []api.ValueType{i32}, []api.ValueType{i32}).
		Export("[method]resolve-address-stream.subscribe").
		// [resource-drop]resolve-address-stream: (i32) → void
		NewFunctionBuilder().
		WithGoModuleFunction(noop, []api.ValueType{i32}, nil).
		Export("[resource-drop]resolve-address-stream").
		Instantiate(ctx)
	return err
}

// ────────────────────────────────────────────────────────────────────────
// Additional CLI / Filesystem / Wall-clock stubs needed by NativeAOT-WASI
// binaries that import WASI Preview 2 modules directly (i.e. when the
// component-ld bypass produces a P1 module from a NativeAOT publish but
// the import list still references P2 modules).
//
// Behaviour is the minimum needed to load the module — calls into these
// stubs either return 0/-1 or trap; real I/O is expected to go through
// wasmforge's existing P1 WASI bridge or through the dedicated nativeaot
// host functions registered separately.
// ────────────────────────────────────────────────────────────────────────

func registerCLIEnvironment(ctx context.Context, rt wazero.Runtime, args []string) error {
	// get-environment: empty list — env vars are not provided to the WASM.
	emptyList := api.GoModuleFunc(func(_ context.Context, m api.Module, stack []uint64) {
		if mem := m.Memory(); mem != nil {
			mem.WriteUint64Le(uint32(stack[0]), 0)
		}
	})

	// get-arguments: write the user-provided argv as a Canonical-ABI list of
	// (ptr, len) string tuples into guest memory.
	//
	// NativeAOT-WASI (and standard C startup) assume argc >= 1 with argv[0]
	// being the program name. wasi-libc P2's __main_void synthesizes argv
	// from this list — if it's empty, argc=0 and NativeAOT's
	//   string[] userArgs = new string[argc - 1];
	// blows up the heap. So when no args were supplied at all, we fall back
	// to a single synthetic "wasmforge-app" entry.
	//
	// When args ARE supplied we hand them through verbatim. This is what lets
	// `seatbelt-wf.exe OSInfo` reach Seatbelt's command dispatcher with the
	// real argv instead of the dummy program name.
	argvForGuest := args
	if len(argvForGuest) == 0 {
		argvForGuest = []string{"wasmforge-app"}
	}
	argList := api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
		retptr := uint32(stack[0])
		mem := m.Memory()
		if mem == nil {
			return
		}
		realloc := m.ExportedFunction("cabi_realloc")
		// Allocate the (ptr, len) tuple array — 8 bytes per entry.
		tupleBytes := uint64(8 * len(argvForGuest))
		var tupleBase uint32
		if realloc != nil {
			if res, err := realloc.Call(ctx, 0, 0, 4, tupleBytes); err == nil && len(res) > 0 {
				tupleBase = uint32(res[0])
			}
		}
		if tupleBase == 0 {
			// Fallback path (cabi_realloc unavailable): place the tuple array
			// 16 bytes past retptr and pack strings after it. Only safe for
			// tiny argv counts but matches the previous one-arg fallback.
			tupleBase = retptr + 16
		}
		strCursor := tupleBase + uint32(tupleBytes)
		for i, s := range argvForGuest {
			b := []byte(s)
			var strBuf uint32
			if realloc != nil {
				if res, err := realloc.Call(ctx, 0, 0, 1, uint64(len(b))); err == nil && len(res) > 0 {
					strBuf = uint32(res[0])
				}
			}
			if strBuf == 0 {
				strBuf = strCursor
				strCursor += uint32(len(b))
			}
			mem.Write(strBuf, b)
			tupleOff := tupleBase + uint32(i*8)
			mem.WriteUint32Le(tupleOff, strBuf)
			mem.WriteUint32Le(tupleOff+4, uint32(len(b)))
		}
		mem.WriteUint32Le(retptr, tupleBase)
		mem.WriteUint32Le(retptr+4, uint32(len(argvForGuest)))
	})

	_, err := rt.NewHostModuleBuilder("wasi:cli/environment@0.2.0").
		NewFunctionBuilder().
		WithGoModuleFunction(emptyList, []api.ValueType{api.ValueTypeI32}, nil).
		Export("get-environment").
		NewFunctionBuilder().
		WithGoModuleFunction(argList, []api.ValueType{api.ValueTypeI32}, nil).
		Export("get-arguments").
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, m api.Module, stack []uint64) {
			if mem := m.Memory(); mem != nil {
				mem.WriteByte(uint32(stack[0]), 0)
			}
		}), []api.ValueType{api.ValueTypeI32}, nil).
		Export("initial-cwd").
		Instantiate(ctx)
	return err
}

func registerCLIExit(ctx context.Context, rt wazero.Runtime) error {
	_, err := rt.NewHostModuleBuilder("wasi:cli/exit@0.2.0").
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, _ api.Module, _ []uint64) {}),
			[]api.ValueType{api.ValueTypeI32}, nil).
		Export("exit").
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, _ api.Module, stack []uint64) {
			stack[0] = 0
		}), []api.ValueType{api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		Export("exit-with-code").
		Instantiate(ctx)
	return err
}

// CLI std{in,out,err}: a no-arg call returns a "stream handle" (i32).
// Return non-zero distinct handles (0 is null sentinel; wasi-libc aborts on null).
func registerCLIStdStreams(ctx context.Context, rt wazero.Runtime) error {
	streams := []struct {
		mod    string
		fn     string
		handle uint64
	}{
		{"wasi:cli/stdin@0.2.0", "get-stdin", 1},
		{"wasi:cli/stdout@0.2.0", "get-stdout", 2},
		{"wasi:cli/stderr@0.2.0", "get-stderr", 3},
	}
	for _, s := range streams {
		h := s.handle
		_, err := rt.NewHostModuleBuilder(s.mod).
			NewFunctionBuilder().
			WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, _ api.Module, stack []uint64) {
				stack[0] = h
			}), nil, []api.ValueType{api.ValueTypeI32}).
			Export(s.fn).
			Instantiate(ctx)
		if err != nil {
			return err
		}
	}
	return nil
}

func registerCLITerminal(ctx context.Context, rt wazero.Runtime) error {
	regModule := func(name, fn, dropName string) error {
		_, err := rt.NewHostModuleBuilder(name).
			// resource-drop: (i32) → void (drops a handle, no return)
			NewFunctionBuilder().
			WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, _ api.Module, _ []uint64) {}),
				[]api.ValueType{api.ValueTypeI32}, nil).
			Export(dropName).
			// get-terminal-*: (out_ptr i32) → void — canonical ABI writes option to out_ptr
			NewFunctionBuilder().
			WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, m api.Module, stack []uint64) {
				// Write option discriminant 0 (= none) at out_ptr.
				if mem := m.Memory(); mem != nil {
					mem.WriteByte(uint32(stack[0]), 0)
				}
			}), []api.ValueType{api.ValueTypeI32}, nil).
			Export(fn).
			Instantiate(ctx)
		return err
	}
	for _, t := range []struct{ mod, fn, drop string }{
		{"wasi:cli/terminal-input@0.2.0", "get-terminal-input", "[resource-drop]terminal-input"},
		{"wasi:cli/terminal-output@0.2.0", "get-terminal-output", "[resource-drop]terminal-output"},
		{"wasi:cli/terminal-stdin@0.2.0", "get-terminal-stdin", "[resource-drop]terminal-input"},
		{"wasi:cli/terminal-stdout@0.2.0", "get-terminal-stdout", "[resource-drop]terminal-output"},
		{"wasi:cli/terminal-stderr@0.2.0", "get-terminal-stderr", "[resource-drop]terminal-output"},
	} {
		if err := regModule(t.mod, t.fn, t.drop); err != nil {
			return err
		}
	}
	return nil
}

func registerFilesystemTypes(ctx context.Context, rt wazero.Runtime) error {
	i32, i64 := api.ValueTypeI32, api.ValueTypeI64
	b := rt.NewHostModuleBuilder("wasi:filesystem/types@0.2.0")

	// pureNoop: function that does nothing — used for [resource-drop] handlers
	// where the i32 arg is a resource handle, NOT an out_ptr.
	pureNoop := api.GoModuleFunc(func(_ context.Context, _ api.Module, _ []uint64) {})

	// outptrErr: stub function whose last i32 param IS an out_ptr; writes a
	// result-error discriminant (1) there so callers don't read garbage.
	outptrErr := func(name string, params []api.ValueType, results []api.ValueType) {
		b.NewFunctionBuilder().
			WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, m api.Module, stack []uint64) {
				for i := range results {
					stack[i] = 0
				}
				if len(results) == 0 && len(params) > 0 && params[len(params)-1] == i32 {
					if mem := m.Memory(); mem != nil {
						mem.WriteByte(uint32(stack[len(params)-1]), 1)
					}
				}
			}), params, results).
			Export(name)
	}
	noop := outptrErr // alias used below for non-resource-drop methods

	// Resource drops — (handle: i32) → void. Must NOT touch the handle as an address.
	b.NewFunctionBuilder().
		WithGoModuleFunction(pureNoop, []api.ValueType{i32}, nil).
		Export("[resource-drop]descriptor")
	b.NewFunctionBuilder().
		WithGoModuleFunction(pureNoop, []api.ValueType{i32}, nil).
		Export("[resource-drop]directory-entry-stream")

	// Stream creation methods: (self: i32, [offset: i64,] out_ptr: i32) → void
	noop("[method]descriptor.read-via-stream", []api.ValueType{i32, i64, i32}, nil)
	noop("[method]descriptor.write-via-stream", []api.ValueType{i32, i64, i32}, nil)
	noop("[method]descriptor.append-via-stream", []api.ValueType{i32, i32}, nil)

	// Advisory / sync / size operations: (self: i32, [args...,] out_ptr: i32) → void
	noop("[method]descriptor.advise", []api.ValueType{i32, i64, i64, i32, i32}, nil)
	noop("[method]descriptor.sync-data", []api.ValueType{i32, i32}, nil)
	noop("[method]descriptor.sync", []api.ValueType{i32, i32}, nil)
	noop("[method]descriptor.get-flags", []api.ValueType{i32, i32}, nil)
	noop("[method]descriptor.get-type", []api.ValueType{i32, i32}, nil)
	noop("[method]descriptor.set-size", []api.ValueType{i32, i64, i32}, nil)
	noop("[method]descriptor.set-times", []api.ValueType{i32, i32, i64, i32, i64, i32}, nil)
	noop("[method]descriptor.set-times-at", []api.ValueType{i32, i32, i32, i64, i32, i64, i32, i32, i32}, nil)

	// I/O at offset: (self, buf_ptr, buf_len, [offset,] out_ptr) → void
	noop("[method]descriptor.read", []api.ValueType{i32, i64, i64, i32}, nil)
	// descriptor.write: pretend success and report `bufLen` bytes written.
	b.NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, m api.Module, stack []uint64) {
			bufLen := uint32(stack[2])
			retPtr := uint32(stack[4])
			if mem := m.Memory(); mem != nil {
				mem.WriteByte(retPtr, 0)
				mem.WriteUint64Le(retPtr+8, uint64(bufLen))
			}
		}), []api.ValueType{i32, i32, i32, i64, i32}, nil).
		Export("[method]descriptor.write")

	// Directory operations
	noop("[method]descriptor.read-directory", []api.ValueType{i32, i32}, nil)
	noop("[method]descriptor.create-directory-at", []api.ValueType{i32, i32, i32, i32}, nil)
	noop("[method]descriptor.remove-directory-at", []api.ValueType{i32, i32, i32, i32}, nil)
	noop("[method]descriptor.rename-at", []api.ValueType{i32, i32, i32, i32, i32, i32, i32}, nil)
	noop("[method]descriptor.symlink-at", []api.ValueType{i32, i32, i32, i32, i32, i32}, nil)
	noop("[method]descriptor.unlink-file-at", []api.ValueType{i32, i32, i32, i32}, nil)
	noop("[method]descriptor.link-at", []api.ValueType{i32, i32, i32, i32, i32, i32, i32, i32}, nil)
	noop("[method]descriptor.readlink-at", []api.ValueType{i32, i32, i32, i32}, nil)

	// Stat / metadata
	noop("[method]descriptor.stat", []api.ValueType{i32, i32}, nil)
	noop("[method]descriptor.stat-at", []api.ValueType{i32, i32, i32, i32, i32}, nil)
	noop("[method]descriptor.metadata-hash", []api.ValueType{i32, i32}, nil)
	noop("[method]descriptor.metadata-hash-at", []api.ValueType{i32, i32, i32, i32, i32}, nil)

	// open-at: 7-tuple per wasm-objdump: (i32, i32, i32, i32, i32, i32, i32) → void
	noop("[method]descriptor.open-at", []api.ValueType{i32, i32, i32, i32, i32, i32, i32}, nil)

	// is-same-object: (a, b) → i32
	noop("[method]descriptor.is-same-object", []api.ValueType{i32, i32}, []api.ValueType{i32})

	// directory-entry-stream.read-directory-entry: (self, out_ptr) → void
	noop("[method]directory-entry-stream.read-directory-entry", []api.ValueType{i32, i32}, nil)

	// filesystem-error-code: (err: i32, out_ptr: i32) → void
	noop("filesystem-error-code", []api.ValueType{i32, i32}, nil)

	_, err := b.Instantiate(ctx)
	return err
}

func registerFilesystemPreopens(ctx context.Context, rt wazero.Runtime) error {
	_, err := rt.NewHostModuleBuilder("wasi:filesystem/preopens@0.2.0").
		NewFunctionBuilder().
		// get-directories: (retptr i32) → void
		// Returns an empty list<tuple<descriptor, string>>. wasi-libc's
		// __wasilibc_populate_preopens reads (ptr, len) at retptr; if we
		// leave it uninitialized the function aborts the entire WASM
		// module on first filesystem call. Writing a real empty list
		// lets wasi-libc proceed with zero preopens — directory access
		// falls back to the host bridge (sys_listdir / fs_listdir).
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, m api.Module, stack []uint64) {
			retptr := uint32(stack[0])
			mem := m.Memory()
			if mem == nil {
				return
			}
			mem.WriteUint32Le(retptr, 0)     // ptr = 0
			mem.WriteUint32Le(retptr+4, 0)   // len = 0
		}),
			[]api.ValueType{api.ValueTypeI32}, nil).
		Export("get-directories").
		Instantiate(ctx)
	return err
}

func registerWallClock(ctx context.Context, rt wazero.Runtime) error {
	_, err := rt.NewHostModuleBuilder("wasi:clocks/wall-clock@0.2.0").
		// now: (retptr i32) → void — writes datetime { u64 seconds, u32 nanoseconds }
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, m api.Module, stack []uint64) {
			if mem := m.Memory(); mem != nil {
				now := time.Now()
				mem.WriteUint64Le(uint32(stack[0]), uint64(now.Unix()))
				mem.WriteUint32Le(uint32(stack[0])+8, uint32(now.Nanosecond()))
			}
		}), []api.ValueType{api.ValueTypeI32}, nil).
		Export("now").
		// resolution: () → i64 — datetime is reported as nanoseconds-since-epoch resolution
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, _ api.Module, stack []uint64) {
			stack[0] = 1
		}), nil, []api.ValueType{api.ValueTypeI64}).
		Export("resolution").
		Instantiate(ctx)
	return err
}

func registerRandom(ctx context.Context, rt wazero.Runtime) error {
	_, err := rt.NewHostModuleBuilder("wasi:random/random@0.2.0").
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, _ api.Module, stack []uint64) {
			stack[0] = uint64(time.Now().UnixNano()) ^ 0x9E3779B97F4A7C15
		}), nil, []api.ValueType{api.ValueTypeI64}).
		Export("get-random-u64").
		// get-random-bytes(len: u64) -> list<u8>
		// Lowered import: (len: i64, retptr: i32) -> void
		// retptr receives (buf_ptr: i32, buf_len: i32). Buffer must live in guest
		// memory — allocate via cabi_realloc and fill with bytes.
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			length := uint32(stack[0])
			retptr := uint32(stack[1])
			mem := mod.Memory()
			if mem == nil {
				return
			}
			if length == 0 {
				mem.WriteUint32Le(retptr, 0)
				mem.WriteUint32Le(retptr+4, 0)
				return
			}
			var bufPtr uint32
			if realloc := mod.ExportedFunction("cabi_realloc"); realloc != nil {
				res, err := realloc.Call(ctx, 0, 0, 1, uint64(length))
				if err == nil && len(res) > 0 {
					bufPtr = uint32(res[0])
				}
			}
			if bufPtr == 0 {
				// No realloc available — return empty list rather than OOB-writing
				// past retptr. Caller may misbehave but won't corrupt the stack frame.
				mem.WriteUint32Le(retptr, 0)
				mem.WriteUint32Le(retptr+4, 0)
				return
			}
			seed := uint64(time.Now().UnixNano())
			buf := make([]byte, length)
			for i := range buf {
				seed ^= seed << 13
				seed ^= seed >> 7
				seed ^= seed << 17
				buf[i] = byte(seed)
			}
			mem.Write(bufPtr, buf)
			mem.WriteUint32Le(retptr, bufPtr)
			mem.WriteUint32Le(retptr+4, length)
		}), []api.ValueType{api.ValueTypeI64, api.ValueTypeI32}, nil).
		Export("get-random-bytes").
		Instantiate(ctx)
	return err
}
