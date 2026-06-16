package hostmod

import (
	"context"
	"syscall"

	"github.com/praetorian-inc/wasmforge/internal/names"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// Context keys for passing the FD table and config to host functions.
type contextKey int

const (
	ctxKeyFDTable contextKey = iota
	ctxKeyConfig
	ctxKeyWin32Handles
	ctxKeyShadowMap
)

// WithFDTable stores the FD table in the context.
func WithFDTable(ctx context.Context, ft *fdTable) context.Context {
	return context.WithValue(ctx, ctxKeyFDTable, ft)
}

// getFDTable retrieves the FD table from the context.
func getFDTable(ctx context.Context) *fdTable {
	ft, _ := ctx.Value(ctxKeyFDTable).(*fdTable)
	return ft
}

// Config holds configuration for the host module.
type Config struct {
	RawSockets bool // Allow raw socket creation.
	Win32APIs  bool // Enable Win32 API bridge functions (Windows only).
	DarwinAPIs bool // Enable Darwin/macOS framework bridge functions (macOS only).
	Verbose    bool // Enable verbose debug logging for syscalls.
}

// WithConfig stores the config in the context.
func WithConfig(ctx context.Context, cfg *Config) context.Context {
	return context.WithValue(ctx, ctxKeyConfig, cfg)
}

func getConfig(ctx context.Context) *Config {
	cfg, _ := ctx.Value(ctxKeyConfig).(*Config)
	return cfg
}

// WithWin32Handles creates a new Win32 handle table and stores it in the context.
func WithWin32Handles(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKeyWin32Handles, newWin32HandleTable())
}

// getWin32Handles retrieves the Win32 handle table from the context.
func getWin32Handles(ctx context.Context) *win32HandleTable {
	ht, _ := ctx.Value(ctxKeyWin32Handles).(*win32HandleTable)
	return ht
}

// WithShadowMap creates a new shadow map and stores it in the context.
func WithShadowMap(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKeyShadowMap, newShadowMap())
}

// getShadowMap retrieves the shadow map from the context.
func getShadowMap(ctx context.Context) *shadowMap {
	sm, _ := ctx.Value(ctxKeyShadowMap).(*shadowMap)
	return sm
}

// Errno constants matching WASI and Linux conventions.
const (
	errnoSuccess     uint32 = 0
	errnoEBADF       uint32 = 8
	errnoEFAULT      uint32 = 21
	errnoEINVAL      uint32 = 28
	errnoEAGAIN      uint32 = 6
	errnoEINPROGRESS uint32 = 26
	errnoEPERM       uint32 = 63
	errnoEAI         uint32 = 70 // DNS resolution failure
	errnoENOSYS      uint32 = 52 // Function not implemented
	errnoERANGE      uint32 = 34 // Result too large / buffer too small
	errnoECHILD      uint32 = 10 // No child process
	errnoYIELD       uint32 = 255 // Cooperative yield — guest should Gosched and retry
)

// errnoFromError converts a Go error to a WASI errno value.
func errnoFromError(err error) uint32 {
	if err == nil {
		return errnoSuccess
	}
	if errno, ok := err.(syscall.Errno); ok {
		// On Windows, Go's syscall functions return raw Winsock error codes
		// (e.g., 10035 for WSAEWOULDBLOCK) that don't match Go's synthetic
		// POSIX constants (e.g., syscall.EWOULDBLOCK = 0x2000007F). Check
		// raw Winsock codes first via platform-specific classifyWinsockError.
		if wasiErr, matched := classifyWinsockError(errno); matched {
			return wasiErr
		}
		// Standard POSIX errno check. On Linux EAGAIN==EWOULDBLOCK; on
		// Windows these are synthetic values that may or may not match.
		if errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK {
			return errnoEAGAIN
		}
		// Map common errnos to WASI errnos.
		switch errno {
		case syscall.EBADF:
			return errnoEBADF
		case syscall.EFAULT:
			return errnoEFAULT
		case syscall.EINVAL:
			return errnoEINVAL
		case syscall.EINPROGRESS:
			return errnoEINPROGRESS
		case syscall.EPERM, syscall.EACCES:
			return errnoEPERM
		case syscall.ECONNREFUSED:
			return 61 // WASI ECONNREFUSED
		case syscall.ECONNRESET:
			return 15 // WASI ECONNRESET
		case syscall.ECONNABORTED:
			return 13 // WASI ECONNABORTED
		case syscall.EADDRINUSE:
			return 3 // WASI EADDRINUSE
		case syscall.EADDRNOTAVAIL:
			return 4 // WASI EADDRNOTAVAIL
		case syscall.ENETUNREACH:
			return 40 // WASI ENETUNREACH
		case syscall.ETIMEDOUT:
			return 73 // WASI ETIMEDOUT
		case syscall.ENOTCONN:
			return 53 // WASI ENOTCONN
		case syscall.EISCONN:
			return 30 // WASI EISCONN
		case syscall.EALREADY:
			return 5 // WASI EALREADY
		case syscall.ENOTSUP:
			return 58 // WASI ENOTSUP
		default:
			return errnoEINVAL
		}
	}
	return errnoEINVAL
}

// NewFDTable creates a new FD table for socket management.
func NewFDTable() *fdTable {
	return newFDTable()
}

// export returns the anonymized export name for the given original name.
func export(original string) string {
	if n, ok := names.Exports[original]; ok {
		return n
	}
	return original
}

// Register registers all host functions with the given wazero runtime.
func Register(r wazero.Runtime) wazero.HostModuleBuilder {
	builder := r.NewHostModuleBuilder(names.ModuleName).
		// TCP socket lifecycle
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			domain := int32(stack[0])
			socktype := int32(stack[1])
			protocol := int32(stack[2])
			fdPtr := uint32(stack[3])
			stack[0] = uint64(sockOpen(ctx, mod, domain, socktype, protocol, fdPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("domain", "socktype", "protocol", "fd_ptr").
		Export(export("sock_open")).

		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			fd := int32(stack[0])
			addrPtr := uint32(stack[1])
			addrLen := uint32(stack[2])
			stack[0] = uint64(sockBind(ctx, mod, fd, addrPtr, addrLen))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("fd", "addr_ptr", "addr_len").
		Export(export("sock_bind")).

		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			fd := int32(stack[0])
			backlog := int32(stack[1])
			stack[0] = uint64(sockListen(ctx, mod, fd, backlog))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("fd", "backlog").
		Export(export("sock_listen")).

		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			fd := int32(stack[0])
			addrPtr := uint32(stack[1])
			addrLen := uint32(stack[2])
			stack[0] = uint64(sockConnect(ctx, mod, fd, addrPtr, addrLen))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("fd", "addr_ptr", "addr_len").
		Export(export("sock_connect")).

		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			fd := int32(stack[0])
			flags := int32(stack[1])
			newFDPtr := uint32(stack[2])
			addrPtr := uint32(stack[3])
			addrLenPtr := uint32(stack[4])
			stack[0] = uint64(sockAccept(ctx, mod, fd, flags, newFDPtr, addrPtr, addrLenPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("fd", "flags", "newfd_ptr", "addr_ptr", "addr_len_ptr").
		Export(export("sock_accept")).

		// Non-blocking I/O
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			fd := int32(stack[0])
			bufPtr := uint32(stack[1])
			bufLen := uint32(stack[2])
			nreadPtr := uint32(stack[3])
			stack[0] = uint64(sockRead(ctx, mod, fd, bufPtr, bufLen, nreadPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("fd", "buf_ptr", "buf_len", "nread_ptr").
		Export(export("sock_read")).

		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			fd := int32(stack[0])
			bufPtr := uint32(stack[1])
			bufLen := uint32(stack[2])
			nwrittenPtr := uint32(stack[3])
			stack[0] = uint64(sockWrite(ctx, mod, fd, bufPtr, bufLen, nwrittenPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("fd", "buf_ptr", "buf_len", "nwritten_ptr").
		Export(export("sock_write")).

		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			fd := int32(stack[0])
			stack[0] = uint64(sockClose(ctx, mod, fd))
		}), []api.ValueType{api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("fd").
		Export(export("sock_close")).

		// UDP
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			fd := int32(stack[0])
			bufPtr := uint32(stack[1])
			bufLen := uint32(stack[2])
			flags := int32(stack[3])
			addrPtr := uint32(stack[4])
			addrLen := uint32(stack[5])
			nsentPtr := uint32(stack[6])
			stack[0] = uint64(sockSendto(ctx, mod, fd, bufPtr, bufLen, flags, addrPtr, addrLen, nsentPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("fd", "buf_ptr", "buf_len", "flags", "addr_ptr", "addr_len", "nsent_ptr").
		Export(export("sock_sendto")).

		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			fd := int32(stack[0])
			bufPtr := uint32(stack[1])
			bufLen := uint32(stack[2])
			flags := int32(stack[3])
			addrPtr := uint32(stack[4])
			addrCap := uint32(stack[5])
			addrLenPtr := uint32(stack[6])
			nrecvPtr := uint32(stack[7])
			stack[0] = uint64(sockRecvfrom(ctx, mod, fd, bufPtr, bufLen, flags, addrPtr, addrCap, addrLenPtr, nrecvPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("fd", "buf_ptr", "buf_len", "flags", "addr_ptr", "addr_cap", "addr_len_ptr", "nrecv_ptr").
		Export(export("sock_recvfrom")).

		// Shutdown
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			fd := int32(stack[0])
			how := int32(stack[1])
			stack[0] = uint64(sockShutdown(ctx, mod, fd, how))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("fd", "how").
		Export(export("sock_shutdown")).

		// Socket options
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			fd := int32(stack[0])
			level := int32(stack[1])
			opt := int32(stack[2])
			valPtr := uint32(stack[3])
			valLen := uint32(stack[4])
			stack[0] = uint64(sockSetsockopt(ctx, mod, fd, level, opt, valPtr, valLen))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("fd", "level", "opt", "val_ptr", "val_len").
		Export(export("sock_setsockopt")).

		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			fd := int32(stack[0])
			level := int32(stack[1])
			opt := int32(stack[2])
			valPtr := uint32(stack[3])
			valLenPtr := uint32(stack[4])
			stack[0] = uint64(sockGetsockopt(ctx, mod, fd, level, opt, valPtr, valLenPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("fd", "level", "opt", "val_ptr", "val_len_ptr").
		Export(export("sock_getsockopt")).

		// Peer/local address
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			fd := int32(stack[0])
			addrPtr := uint32(stack[1])
			addrLenPtr := uint32(stack[2])
			stack[0] = uint64(sockGetpeername(ctx, mod, fd, addrPtr, addrLenPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("fd", "addr_ptr", "addr_len_ptr").
		Export(export("sock_getpeername")).

		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			fd := int32(stack[0])
			addrPtr := uint32(stack[1])
			addrLenPtr := uint32(stack[2])
			stack[0] = uint64(sockGetsockname(ctx, mod, fd, addrPtr, addrLenPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("fd", "addr_ptr", "addr_len_ptr").
		Export(export("sock_getsockname")).

		// DNS
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			namePtr := uint32(stack[0])
			nameLen := uint32(stack[1])
			svcPtr := uint32(stack[2])
			svcLen := uint32(stack[3])
			hints := uint32(stack[4])
			resultPtr := uint32(stack[5])
			maxResults := uint32(stack[6])
			nPtr := uint32(stack[7])
			stack[0] = uint64(sockGetaddrinfo(ctx, mod, namePtr, nameLen, svcPtr, svcLen, hints, resultPtr, maxResults, nPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("name_ptr", "name_len", "svc_ptr", "svc_len", "hints", "result_ptr", "max_results", "n_ptr").
		Export(export("sock_getaddrinfo")).

		// Raw sockets
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			domain := int32(stack[0])
			protocol := int32(stack[1])
			fdPtr := uint32(stack[2])
			stack[0] = uint64(rawSockOpen(ctx, mod, domain, protocol, fdPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("domain", "protocol", "fd_ptr").
		Export(export("raw_sock_open")).

		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			fd := int32(stack[0])
			bufPtr := uint32(stack[1])
			bufLen := uint32(stack[2])
			flags := int32(stack[3])
			destPtr := uint32(stack[4])
			destLen := uint32(stack[5])
			nsentPtr := uint32(stack[6])
			stack[0] = uint64(rawSockSend(ctx, mod, fd, bufPtr, bufLen, flags, destPtr, destLen, nsentPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("fd", "buf_ptr", "buf_len", "flags", "dest_ptr", "dest_len", "nsent_ptr").
		Export(export("raw_sock_send")).

		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			fd := int32(stack[0])
			bufPtr := uint32(stack[1])
			bufLen := uint32(stack[2])
			flags := int32(stack[3])
			srcPtr := uint32(stack[4])
			srcCap := uint32(stack[5])
			srcLenPtr := uint32(stack[6])
			nrecvPtr := uint32(stack[7])
			stack[0] = uint64(rawSockRecv(ctx, mod, fd, bufPtr, bufLen, flags, srcPtr, srcCap, srcLenPtr, nrecvPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("fd", "buf_ptr", "buf_len", "flags", "src_ptr", "src_cap", "src_len_ptr", "nrecv_ptr").
		Export(export("raw_sock_recv")).

		// OS host function proxies (always available).
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(osHostname),
			[]api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32},
			[]api.ValueType{api.ValueTypeI32}).
		WithParameterNames("buf_ptr", "buf_cap", "result_len_ptr").
		Export(export("os_hostname")).

		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(osGetwd),
			[]api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32},
			[]api.ValueType{api.ValueTypeI32}).
		WithParameterNames("buf_ptr", "buf_cap", "result_len_ptr").
		Export(export("os_getwd")).

		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(osChdir),
			[]api.ValueType{api.ValueTypeI32, api.ValueTypeI32},
			[]api.ValueType{api.ValueTypeI32}).
		WithParameterNames("path_ptr", "path_len").
		Export(export("os_chdir")).

		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(osUserCurrent),
			[]api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32},
			[]api.ValueType{api.ValueTypeI32}).
		WithParameterNames("buf_ptr", "buf_cap", "result_len_ptr").
		Export(export("os_user_current")).

		// PID host function.
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(osGetpid),
			[]api.ValueType{},
			[]api.ValueType{api.ValueTypeI32}).
		Export(export("os_getpid")).

		// Process list host function.
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(osProcessList),
			[]api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32},
			[]api.ValueType{api.ValueTypeI32}).
		WithParameterNames("buf_ptr", "buf_cap", "result_len_ptr").
		Export(export("os_process_list")).

		// NativeAOT-specific functions (os_list_dir, os_file_exists) are registered
		// separately in nativeaot.go behind the "nativeaot" build tag.

		// Process execution host functions.
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(osExec),
			[]api.ValueType{
				api.ValueTypeI32, api.ValueTypeI32, // argv_ptr, argv_len
				api.ValueTypeI32, api.ValueTypeI32, // env_ptr, env_len
				api.ValueTypeI32, api.ValueTypeI32, // dir_ptr, dir_len
				api.ValueTypeI32, api.ValueTypeI32, // stdin_ptr, stdin_len
				api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, // stdout_ptr, stdout_cap, stdout_len_ptr
				api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, // stderr_ptr, stderr_cap, stderr_len_ptr
				api.ValueTypeI32, // exitcode_ptr
			},
			[]api.ValueType{api.ValueTypeI32}).
		WithParameterNames("argv_ptr", "argv_len", "env_ptr", "env_len", "dir_ptr", "dir_len",
			"stdin_ptr", "stdin_len",
			"stdout_ptr", "stdout_cap", "stdout_len_ptr", "stderr_ptr", "stderr_cap", "stderr_len_ptr", "exitcode_ptr").
		Export(export("os_exec")).

		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(osStartProcess),
			[]api.ValueType{
				api.ValueTypeI32, api.ValueTypeI32, // argv_ptr, argv_len
				api.ValueTypeI32, api.ValueTypeI32, // env_ptr, env_len
				api.ValueTypeI32, api.ValueTypeI32, // dir_ptr, dir_len
				api.ValueTypeI32, // stdout_fd
				api.ValueTypeI32, // stderr_fd
				api.ValueTypeI32, // pid_ptr
			},
			[]api.ValueType{api.ValueTypeI32}).
		WithParameterNames("argv_ptr", "argv_len", "env_ptr", "env_len", "dir_ptr", "dir_len", "stdout_fd", "stderr_fd", "pid_ptr").
		Export(export("os_start_process")).

		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(osWait4),
			[]api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32},
			[]api.ValueType{api.ValueTypeI32}).
		WithParameterNames("pid", "status_ptr", "options", "rusage_ptr").
		Export(export("os_wait4")).

		// Network interface host functions.
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(netInterfaces),
			[]api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32},
			[]api.ValueType{api.ValueTypeI32}).
		WithParameterNames("buf_ptr", "buf_cap", "result_len_ptr").
		Export(export("net_interfaces")).

		// Pipe host functions.
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(osPipe),
			[]api.ValueType{api.ValueTypeI32, api.ValueTypeI32},
			[]api.ValueType{api.ValueTypeI32}).
		WithParameterNames("read_fd_ptr", "write_fd_ptr").
		Export(export("os_pipe")).

		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(pipeRead),
			[]api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32},
			[]api.ValueType{api.ValueTypeI32}).
		WithParameterNames("fd", "buf_ptr", "buf_len", "nread_ptr").
		Export(export("pipe_read")).

		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(pipeWrite),
			[]api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32},
			[]api.ValueType{api.ValueTypeI32}).
		WithParameterNames("fd", "buf_ptr", "buf_len", "nwritten_ptr").
		Export(export("pipe_write")).

		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(pipeClose),
			[]api.ValueType{api.ValueTypeI32},
			[]api.ValueType{api.ValueTypeI32}).
		WithParameterNames("fd").
		Export(export("pipe_close"))

	// Add Win32 API bridge functions.
	builder = registerWin32Functions(builder)

	// Add Darwin/macOS framework bridge functions.
	builder = registerDarwinFunctions(builder)

	// Add NativeAOT-specific functions (no-op when "nativeaot" build tag absent).
	builder = registerNativeAOTFunctions(builder)

	return builder
}
