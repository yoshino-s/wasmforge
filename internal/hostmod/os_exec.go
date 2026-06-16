package hostmod

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/tetratelabs/wazero/api"
)

// processEntry tracks a child process started via os_start_process.
type processEntry struct {
	cmd      *exec.Cmd
	done     chan struct{} // closed when process exits
	exitCode int32
	err      error
}

// processTable tracks child processes for Wait4 support.
// Package-level because there is only one WASM instance per process.
var (
	processTableMu sync.Mutex
	processTable   = map[int32]*processEntry{}
)

// osExec implements the wasmforge.os_exec host function.
// Executes a command on the host and writes stdout/stderr to WASM buffers.
//
// Guest ABI:
//
//	argv_ptr:       pointer to serialized argv (count:u32, then len-prefixed strings)
//	argv_len:       total byte length of serialized argv
//	env_ptr:        pointer to serialized env (count:u32, then len-prefixed strings)
//	env_len:        total byte length of serialized env (0 = inherit)
//	dir_ptr:        pointer to working directory string
//	dir_len:        length of working directory string (0 = inherit)
//	stdin_ptr:      pointer to stdin data to pipe to the process
//	stdin_len:      length of stdin data (0 = no stdin)
//	stdout_ptr:     pointer to stdout output buffer
//	stdout_cap:     capacity of stdout buffer
//	stdout_len_ptr: pointer to write actual stdout length
//	stderr_ptr:     pointer to stderr output buffer
//	stderr_cap:     capacity of stderr buffer
//	stderr_len_ptr: pointer to write actual stderr length
//	exitcode_ptr:   pointer to write exit code (int32)
//
// Returns WASI errno (0 = success, even if command returns non-zero exit code).
func osExec(_ context.Context, mod api.Module, stack []uint64) {
	argvPtr := uint32(stack[0])
	argvLen := uint32(stack[1])
	envPtr := uint32(stack[2])
	envLen := uint32(stack[3])
	dirPtr := uint32(stack[4])
	dirLen := uint32(stack[5])
	stdinPtr := uint32(stack[6])
	stdinLen := uint32(stack[7])
	stdoutPtr := uint32(stack[8])
	stdoutCap := uint32(stack[9])
	stdoutLenPtr := uint32(stack[10])
	stderrPtr := uint32(stack[11])
	stderrCap := uint32(stack[12])
	stderrLenPtr := uint32(stack[13])
	exitCodePtr := uint32(stack[14])

	// Parse argv.
	argv, ok := deserializeStrings(mod, argvPtr, argvLen)
	if !ok || len(argv) == 0 {
		stack[0] = uint64(errnoEINVAL)
		return
	}

	// Resolve the executable path for the host OS.
	// The WASM guest may produce WASI-normalized paths (e.g., /c/Users/foo/cmd.exe)
	// or absolute paths that don't exist on the host (e.g., CWD + bare command name).
	// Denormalize first, then fall back to basename PATH resolution if needed.
	argv[0] = resolveExecPath(argv[0])

	// Build command.
	cmd := exec.Command(argv[0], argv[1:]...)

	// Parse env if provided.
	if envLen > 0 {
		env, ok := deserializeStrings(mod, envPtr, envLen)
		if !ok {
			stack[0] = uint64(errnoEFAULT)
			return
		}
		cmd.Env = env
	}

	// Set working directory if provided.
	if dirLen > 0 {
		dirBuf, ok := readBytes(mod, dirPtr, dirLen)
		if !ok {
			stack[0] = uint64(errnoEFAULT)
			return
		}
		cmd.Dir = denormalizeWasiPath(string(dirBuf))
	}

	// Pipe stdin if provided.
	if stdinLen > 0 {
		stdinData, ok := readBytes(mod, stdinPtr, stdinLen)
		if !ok {
			stack[0] = uint64(errnoEFAULT)
			return
		}
		cmd.Stdin = bytes.NewReader(stdinData)
	}

	// Capture stdout and stderr.
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	// Run the command.
	exitCode := int32(0)
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = int32(exitErr.ExitCode())
		} else {
			// Command failed to start entirely.
			stack[0] = uint64(errnoFromError(err))
			return
		}
	}

	// Write stdout to WASM buffer (truncate if necessary).
	stdoutData := stdoutBuf.Bytes()
	if uint32(len(stdoutData)) > stdoutCap {
		stdoutData = stdoutData[:stdoutCap]
	}
	if len(stdoutData) > 0 {
		if !writeBytes(mod, stdoutPtr, stdoutData) {
			stack[0] = uint64(errnoEFAULT)
			return
		}
	}
	if !writeUint32(mod, stdoutLenPtr, uint32(len(stdoutData))) {
		stack[0] = uint64(errnoEFAULT)
		return
	}

	// Write stderr to WASM buffer (truncate if necessary).
	stderrData := stderrBuf.Bytes()
	if uint32(len(stderrData)) > stderrCap {
		stderrData = stderrData[:stderrCap]
	}
	if len(stderrData) > 0 {
		if !writeBytes(mod, stderrPtr, stderrData) {
			stack[0] = uint64(errnoEFAULT)
			return
		}
	}
	if !writeUint32(mod, stderrLenPtr, uint32(len(stderrData))) {
		stack[0] = uint64(errnoEFAULT)
		return
	}

	// Write exit code.
	if !writeInt32(mod, exitCodePtr, exitCode) {
		stack[0] = uint64(errnoEFAULT)
		return
	}

	stack[0] = uint64(errnoSuccess)
}

// osStartProcess implements the wasmforge.os_start_process host function.
// Starts a process without waiting for it to complete.
//
// Guest ABI:
//
//	argv_ptr:    pointer to serialized argv
//	argv_len:    total byte length of serialized argv
//	env_ptr:     pointer to serialized env
//	env_len:     total byte length of serialized env (0 = inherit)
//	dir_ptr:     pointer to working directory string
//	dir_len:     length of working directory string (0 = inherit)
//	stdout_fd:   guest pipe FD for child stdout (0 = inherit parent's)
//	stderr_fd:   guest pipe FD for child stderr (0 = inherit parent's)
//	pid_ptr:     pointer to write PID (int32)
//
// Returns WASI errno (0 = success).
func osStartProcess(ctx context.Context, mod api.Module, stack []uint64) {
	argvPtr := uint32(stack[0])
	argvLen := uint32(stack[1])
	envPtr := uint32(stack[2])
	envLen := uint32(stack[3])
	dirPtr := uint32(stack[4])
	dirLen := uint32(stack[5])
	stdoutFD := int32(stack[6])
	stderrFD := int32(stack[7])
	pidPtr := uint32(stack[8])

	// Parse argv.
	argv, ok := deserializeStrings(mod, argvPtr, argvLen)
	if !ok || len(argv) == 0 {
		stack[0] = uint64(errnoEINVAL)
		return
	}

	// Resolve the executable path for the host OS.
	argv[0] = resolveExecPath(argv[0])

	// Build command.
	cmd := exec.Command(argv[0], argv[1:]...)

	// Parse env if provided.
	if envLen > 0 {
		env, ok := deserializeStrings(mod, envPtr, envLen)
		if !ok {
			stack[0] = uint64(errnoEFAULT)
			return
		}
		cmd.Env = env
	}

	// Set working directory if provided.
	if dirLen > 0 {
		dirBuf, ok := readBytes(mod, dirPtr, dirLen)
		if !ok {
			stack[0] = uint64(errnoEFAULT)
			return
		}
		cmd.Dir = denormalizeWasiPath(string(dirBuf))
	}

	// Connect stdout/stderr to WASM pipe FDs if provided.
	// Pipe FDs >= basePipeFD are looked up in the PipeTable to get
	// the host-side *os.File for the child process's output streams.
	pt := getPipeTable(ctx)
	if pt != nil && stdoutFD >= basePipeFD {
		if f := pt.get(stdoutFD); f != nil {
			cmd.Stdout = f
		}
	}
	if pt != nil && stderrFD >= basePipeFD {
		if f := pt.get(stderrFD); f != nil {
			cmd.Stderr = f
		}
	}

	// Start the process.
	if err := cmd.Start(); err != nil {
		stack[0] = uint64(errnoFromError(err))
		return
	}

	// Write PID.
	pid := int32(cmd.Process.Pid)
	if !writeInt32(mod, pidPtr, pid) {
		stack[0] = uint64(errnoEFAULT)
		return
	}

	// Track the process so osWait4 can retrieve its exit status.
	entry := &processEntry{
		cmd:  cmd,
		done: make(chan struct{}),
	}
	processTableMu.Lock()
	processTable[pid] = entry
	processTableMu.Unlock()

	// Reap in background: store exit code and signal done.
	go func() {
		err := cmd.Wait()
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				entry.exitCode = int32(exitErr.ExitCode())
			} else {
				entry.exitCode = -1
				entry.err = err
			}
		}
		close(entry.done)
	}()

	stack[0] = uint64(errnoSuccess)
}

// osWait4 implements the wasmforge.os_wait4 host function.
// Waits for a child process started via os_start_process.
// Uses the cooperative yield protocol: returns errnoYIELD if the process
// is still running, so the WASM guest can yield and retry.
//
// Guest ABI:
//
//	pid:         PID to wait for
//	status_ptr:  pointer to write wait status (int32)
//	options:     wait options (WNOHANG = 1)
//	rusage_ptr:  pointer to rusage (unused, 0 = ignore)
//
// Returns WASI errno (0 = success, 10 = ECHILD, 255 = YIELD).
func osWait4(_ context.Context, mod api.Module, stack []uint64) {
	pid := int32(stack[0])
	statusPtr := uint32(stack[1])
	options := int32(stack[2])

	const WNOHANG = 1

	processTableMu.Lock()
	entry, found := processTable[pid]
	processTableMu.Unlock()

	if !found {
		stack[0] = uint64(errnoECHILD)
		return
	}

	// Check if process has exited.
	select {
	case <-entry.done:
		// Process exited. Encode exit code as wait status.
		// Linux wait status format: exit_code << 8 (normal exit).
		if statusPtr != 0 {
			status := entry.exitCode << 8
			writeInt32(mod, statusPtr, status)
		}
		// Remove from table to prevent leaks.
		processTableMu.Lock()
		delete(processTable, pid)
		processTableMu.Unlock()
		stack[0] = uint64(errnoSuccess)
	default:
		// Process still running.
		if options&WNOHANG != 0 {
			// Non-blocking: return 0 PID (no child exited yet).
			// Write 0 to status to indicate no change.
			if statusPtr != 0 {
				writeInt32(mod, statusPtr, 0)
			}
			stack[0] = uint64(errnoSuccess)
			return
		}
		// Blocking: throttled yield to prevent CPU spin.
		// Without this sleep, the guest retry loop burns 100% CPU
		// polling for process completion.
		time.Sleep(time.Millisecond)
		stack[0] = uint64(errnoYIELD)
	}
}

// denormalizeWasiPath converts WASI-normalized paths back to native Windows
// format. On wasip1, paths like C:\Users\foo are normalized to /c/Users/foo.
// When the host executes commands, it needs native paths.
// Only active on Windows hosts; no-op on other platforms.
func denormalizeWasiPath(p string) string {
	if runtime.GOOS != "windows" {
		return p
	}
	// /c/Users/foo → C:\Users\foo
	if len(p) >= 3 && p[0] == '/' && isLetter(p[1]) && p[2] == '/' {
		return strings.ToUpper(string(p[1])) + ":" + strings.ReplaceAll(p[2:], "/", "\\")
	}
	// /c → C:\
	if len(p) == 2 && p[0] == '/' && isLetter(p[1]) {
		return strings.ToUpper(string(p[1])) + ":\\"
	}
	return p
}

func isLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// resolveExecPath resolves an executable path received from the WASM guest
// into a path the host OS can execute. This handles two cases:
//
//  1. WASI-normalized paths (/c/Users/foo/cmd.exe) are denormalized to native
//     format (C:\Users\foo\cmd.exe).
//  2. If the denormalized path is absolute but doesn't exist on disk (common
//     when the guest expanded a bare command name like "cmd.exe" via
//     filepath.Abs, prepending the CWD), fall back to PATH resolution
//     using just the basename.
func resolveExecPath(p string) string {
	p = denormalizeWasiPath(p)

	// If the path is absolute and the file doesn't exist, try basename
	// resolution via the host's PATH. This handles the case where the WASM
	// guest expanded "cmd.exe" to "/c/Users/foo/cmd.exe" (via filepath.Abs
	// after LookPath failed on wasip1).
	if filepath.IsAbs(p) {
		if _, err := os.Stat(p); err != nil {
			base := filepath.Base(p)
			if resolved, lookErr := exec.LookPath(base); lookErr == nil {
				return resolved
			}
			// LookPath failed too — return the basename and let
			// exec.Command try its own resolution.
			return base
		}
	}
	return p
}

// deserializeStrings reads a length-prefixed string list from WASM memory.
// Format: uint32(count), then for each: uint32(len), []byte(data).
func deserializeStrings(mod api.Module, ptr, totalLen uint32) ([]string, bool) {
	if totalLen < 4 {
		return nil, false
	}

	data, ok := readBytes(mod, ptr, totalLen)
	if !ok {
		return nil, false
	}

	if len(data) < 4 {
		return nil, false
	}

	count := binary.LittleEndian.Uint32(data[0:4])
	offset := 4

	result := make([]string, 0, count)
	for i := uint32(0); i < count; i++ {
		if offset+4 > len(data) {
			return nil, false
		}
		slen := binary.LittleEndian.Uint32(data[offset : offset+4])
		offset += 4

		if offset+int(slen) > len(data) {
			return nil, false
		}
		result = append(result, string(data[offset:offset+int(slen)]))
		offset += int(slen)
	}

	return result, true
}
