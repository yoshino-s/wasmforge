// WasmForge fallback for os/exec on wasip1.
// On wasip1, os.Pipe() returns ENOSYS which prevents Cmd.Start() from working.
// This fallback uses the wasmforge os_exec host function for synchronous
// execution with stdin/stdout/stderr capture.

//go:build wasip1

package exec

import (
	"errors"
	"io"
	"strconv"
	"syscall"
)

// wasmforgeRunFallback runs the command using WasmForgeExec host function.
// On wasip1, os.Pipe() returns ENOSYS which prevents Cmd.Start() from working.
// This bypasses the pipe-based stdout/stderr capture and uses the wasmforge
// os_exec host function for synchronous execution.
//
// Notes:
// - Returns errors.New("exit status N"), not *exec.ExitError, so callers
//   using errors.As with ExitError will not type-match.
func wasmforgeRunFallback(c *Cmd) error {
	argv := c.Args
	if len(argv) == 0 {
		argv = []string{c.Path}
	}

	// Read stdin data if c.Stdin is set.
	var stdinData []byte
	if c.Stdin != nil {
		var err error
		stdinData, err = io.ReadAll(c.Stdin)
		if err != nil {
			return err
		}
	}

	// When c.Env is nil, pass nil to WasmForgeExec so the host inherits
	// its own native environment (with correct PATH, SYSTEMROOT, etc.).
	// Only pass explicit env when the caller set it.
	stdout, stderr, exitCode, err := syscall.WasmForgeExec(argv, c.Env, c.Dir, stdinData)
	if err != nil {
		return err
	}

	if c.Stdout != nil && len(stdout) > 0 {
		if _, werr := c.Stdout.Write(stdout); werr != nil {
			return werr
		}
	}
	if c.Stderr != nil && len(stderr) > 0 {
		if _, werr := c.Stderr.Write(stderr); werr != nil {
			return werr
		}
	}

	if exitCode != 0 {
		return errors.New("exit status " + strconv.Itoa(exitCode))
	}
	return nil
}
