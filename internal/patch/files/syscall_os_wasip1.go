// WasmForge additions to syscall for wasip1.
// Provides Getwd/Chdir via host functions and StartProcess/Wait4 via os_exec.
// Also provides path normalization for Windows-style paths.

//go:build wasip1

package syscall

import (
	"encoding/binary"
)

//go:wasmimport env sys_pid
func wasmforge_os_getpid() int32

//go:wasmimport env sys_procs
//go:noescape
func wasmforge_os_process_list(bufPtr *byte, bufCap uint32, resultLenPtr *uint32) uint32

//go:wasmimport env sys_getwd
//go:noescape
func wasmforge_os_getwd(bufPtr *byte, bufCap uint32, resultLenPtr *uint32) uint32

//go:wasmimport env sys_chdir
//go:noescape
func wasmforge_os_chdir(pathPtr *byte, pathLen uint32) uint32

//go:wasmimport env proc_exec
//go:noescape
func wasmforge_os_exec(
	argvPtr *byte, argvLen uint32,
	envPtr *byte, envLen uint32,
	dirPtr *byte, dirLen uint32,
	stdinPtr *byte, stdinLen uint32,
	stdoutPtr *byte, stdoutCap uint32, stdoutLenPtr *uint32,
	stderrPtr *byte, stderrCap uint32, stderrLenPtr *uint32,
	exitCodePtr *int32,
) uint32

//go:wasmimport env proc_start
//go:noescape
func wasmforge_os_start_process(
	argvPtr *byte, argvLen uint32,
	envPtr *byte, envLen uint32,
	dirPtr *byte, dirLen uint32,
	stdoutFD int32, stderrFD int32,
	pidPtr *int32,
) uint32

// WasmForgeGetwd returns the real host CWD via wasmforge host function.
func WasmForgeGetwd() (string, error) {
	var buf [4096]byte
	var resultLen uint32
	errno := wasmforge_os_getwd(&buf[0], uint32(len(buf)), &resultLen)
	if errno != 0 {
		return "", Errno(errno)
	}
	return normalizePath(string(buf[:resultLen])), nil
}

// WasmForgeChdir changes the real host CWD via wasmforge host function.
func WasmForgeChdir(path string) error {
	if path == "" {
		return EINVAL
	}
	p := []byte(path)
	errno := wasmforge_os_chdir(&p[0], uint32(len(p)))
	if errno != 0 {
		return Errno(errno)
	}
	return nil
}

// serializeStrings serializes a string slice for passing to host functions.
// Format: uint32(count), then for each: uint32(len), []byte(data).
func serializeStrings(strs []string) []byte {
	total := 4
	for _, s := range strs {
		total += 4 + len(s)
	}
	buf := make([]byte, total)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(len(strs)))
	offset := 4
	for _, s := range strs {
		binary.LittleEndian.PutUint32(buf[offset:offset+4], uint32(len(s)))
		offset += 4
		copy(buf[offset:], s)
		offset += len(s)
	}
	return buf
}

// WasmForgeExec executes a command synchronously and returns stdout, stderr, exit code.
func WasmForgeExec(argv []string, env []string, dir string, stdin []byte) (stdout, stderr []byte, exitCode int, err error) {
	if len(argv) == 0 {
		return nil, nil, -1, EINVAL
	}

	argvBuf := serializeStrings(argv)
	var envBuf []byte
	var envPtr *byte
	var envLen uint32
	if len(env) > 0 {
		envBuf = serializeStrings(env)
		envPtr = &envBuf[0]
		envLen = uint32(len(envBuf))
	}

	var dirPtr *byte
	var dirLen uint32
	if dir != "" {
		dirBytes := []byte(dir)
		dirPtr = &dirBytes[0]
		dirLen = uint32(len(dirBytes))
	}

	var stdinDataPtr *byte
	var stdinDataLen uint32
	if len(stdin) > 0 {
		stdinDataPtr = &stdin[0]
		stdinDataLen = uint32(len(stdin))
	}

	var stdoutBuf [65536]byte
	var stderrBuf [65536]byte
	var stdoutLen, stderrLen uint32
	var ec int32

	errno := wasmforge_os_exec(
		&argvBuf[0], uint32(len(argvBuf)),
		envPtr, envLen,
		dirPtr, dirLen,
		stdinDataPtr, stdinDataLen,
		&stdoutBuf[0], uint32(len(stdoutBuf)), &stdoutLen,
		&stderrBuf[0], uint32(len(stderrBuf)), &stderrLen,
		&ec,
	)
	if errno != 0 {
		return nil, nil, -1, Errno(errno)
	}

	return stdoutBuf[:stdoutLen], stderrBuf[:stderrLen], int(ec), nil
}

//go:wasmimport env proc_wait
//go:noescape
func wasmforge_os_wait4(
	pid int32,
	statusPtr *int32,
	options int32,
	rusagePtr int32,
) uint32

// _PROC_YIELD is returned by proc_wait when the process is still running.
// Separate constant from _ERRNO_YIELD in syscall_win32_wasip1.go to avoid
// redeclaration in builds that include both files.
const _PROC_YIELD = 255

// procYield is a scheduling point for the cooperative yield protocol.
// Uses channel-based yield because //go:linkname runtime.Gosched is blocked
// by Go 1.25's linker in the syscall package.
func procYield() {
	c := make(chan struct{}, 1)
	go func() { c <- struct{}{} }()
	<-c
}

// WasmForgeWait4 waits for a child process using the yield protocol.
// The host returns _PROC_YIELD while the process is still running;
// we yield and retry until the process exits.
func WasmForgeWait4(pid int, wstatus *WaitStatus, options int, rusage *Rusage) (wpid int, err error) {
	var status int32
	for {
		errno := wasmforge_os_wait4(int32(pid), &status, int32(options), 0)
		switch errno {
		case 0:
			// Success. Write status if caller provided pointer.
			if wstatus != nil {
				*wstatus = WaitStatus(status)
			}
			return pid, nil
		case _PROC_YIELD:
			// Process still running. Yield and retry.
			procYield()
			continue
		default:
			return 0, Errno(errno)
		}
	}
}

// WasmForgeStartProcess starts a process without waiting.
// stdoutFD and stderrFD are optional pipe FDs (>= 15000) to connect to the
// child process's stdout/stderr. Pass 0 to inherit the parent's streams.
func WasmForgeStartProcess(argv []string, env []string, dir string, stdoutFD, stderrFD int) (pid int, err error) {
	if len(argv) == 0 {
		return 0, EINVAL
	}

	argvBuf := serializeStrings(argv)
	var envPtr *byte
	var envLen uint32
	if len(env) > 0 {
		envBuf := serializeStrings(env)
		envPtr = &envBuf[0]
		envLen = uint32(len(envBuf))
	}

	var dirPtr *byte
	var dirLen uint32
	if dir != "" {
		dirBytes := []byte(dir)
		dirPtr = &dirBytes[0]
		dirLen = uint32(len(dirBytes))
	}

	var p int32
	errno := wasmforge_os_start_process(
		&argvBuf[0], uint32(len(argvBuf)),
		envPtr, envLen,
		dirPtr, dirLen,
		int32(stdoutFD), int32(stderrFD),
		&p,
	)
	if errno != 0 {
		return 0, Errno(errno)
	}

	return int(p), nil
}

// normalizePath converts Windows-style paths for use with WASI filesystem.
// C:\foo\bar → /c/foo/bar
func normalizePath(path string) string {
	if len(path) == 0 {
		return path
	}

	// Convert Windows drive paths: C:\foo → /c/foo
	if len(path) >= 2 && path[1] == ':' &&
		((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) {
		drive := path[0]
		if drive >= 'A' && drive <= 'Z' {
			drive = drive + ('a' - 'A')
		}
		path = "/" + string(drive) + path[2:]
	}

	// Convert backslashes to forward slashes.
	result := make([]byte, len(path))
	for i := 0; i < len(path); i++ {
		if path[i] == '\\' {
			result[i] = '/'
		} else {
			result[i] = path[i]
		}
	}
	return string(result)
}

// WasmForgeGetpid returns the real host process PID via wasmforge host function.
func WasmForgeGetpid() int {
	return int(wasmforge_os_getpid())
}

// WasmForgeProcessList returns JSON-encoded process list via wasmforge host function.
func WasmForgeProcessList() ([]byte, error) {
	var buf [1048576]byte // 1MB buffer for process list
	var resultLen uint32
	errno := wasmforge_os_process_list(&buf[0], uint32(len(buf)), &resultLen)
	if errno != 0 {
		return nil, Errno(errno)
	}
	out := make([]byte, resultLen)
	copy(out, buf[:resultLen])
	return out, nil
}
