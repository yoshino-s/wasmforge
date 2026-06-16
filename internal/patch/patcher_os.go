package patch

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// removeWasip1FromSysBsd removes wasip1 from os/sys_bsd.go's build tag
// to avoid duplicate hostname() definitions (our patch provides it).
func removeWasip1FromSysBsd(gorootSrc string) error {
	path := filepath.Join(gorootSrc, "os", "sys_bsd.go")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	content := string(data)

	newContent := strings.Replace(content,
		"//go:build darwin || dragonfly || freebsd || (js && wasm) || netbsd || openbsd || wasip1",
		"//go:build darwin || dragonfly || freebsd || (js && wasm) || netbsd || openbsd",
		1)
	if newContent == content {
		return fmt.Errorf("sys_bsd.go: build tag pattern not found (possible Go version mismatch)")
	}

	return os.WriteFile(path, []byte(newContent), 0o644)
}

// removeWasip1FromInterfaceStub removes wasip1 from net/interface_stub.go's
// build tag to avoid duplicate interfaceTable/interfaceAddrTable definitions.
func removeWasip1FromInterfaceStub(gorootSrc string) error {
	path := filepath.Join(gorootSrc, "net", "interface_stub.go")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	content := string(data)

	newContent := strings.Replace(content,
		"//go:build js || wasip1",
		"//go:build js",
		1)
	if newContent == content {
		return fmt.Errorf("interface_stub.go: build tag pattern not found (possible Go version mismatch)")
	}

	return os.WriteFile(path, []byte(newContent), 0o644)
}

// excludeWasip1FromBSDInterface adds !wasip1 to net/interface_bsd.go and
// net/interface_darwin.go to prevent routebsd from being pulled into wasip1 builds.
// Our interface_host.go provides the wasip1 implementation.
func excludeWasip1FromBSDInterface(gorootSrc string) error {
	files := []string{
		filepath.Join(gorootSrc, "net", "interface_bsd.go"),
		filepath.Join(gorootSrc, "net", "interface_darwin.go"),
	}
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			continue // file may not exist on all platforms
		}
		content := string(data)
		// Add !wasip1 to the existing build constraint.
		if strings.Contains(content, "//go:build") && !strings.Contains(content, "!wasip1") {
			// Wrap existing constraint: //go:build X → //go:build !wasip1 && (X)
			lines := strings.Split(content, "\n")
			for i, line := range lines {
				if strings.HasPrefix(strings.TrimSpace(line), "//go:build ") {
					constraint := strings.TrimPrefix(strings.TrimSpace(line), "//go:build ")
					lines[i] = "//go:build !wasip1 && (" + constraint + ")"
					break
				}
			}
			content = strings.Join(lines, "\n")
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				return fmt.Errorf("patching %s: %w", filepath.Base(path), err)
			}
		}
	}
	return nil
}

// excludeWasip1FromLookupStubs adds !wasip1 to os/user/ files that conflict
// with our lookup_wasip1.go patch.
func excludeWasip1FromLookupStubs(gorootSrc string) error {
	// lookup_stubs.go: (!cgo && !darwin && !windows && !plan9) || android || (osusergo && !windows && !plan9)
	{
		path := filepath.Join(gorootSrc, "os", "user", "lookup_stubs.go")
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		content := string(data)
		newContent := strings.Replace(content,
			"//go:build (!cgo && !darwin && !windows && !plan9) || android || (osusergo && !windows && !plan9)",
			"//go:build (!cgo && !darwin && !windows && !plan9 && !wasip1) || android || (osusergo && !windows && !plan9 && !wasip1)",
			1)
		if newContent == content {
			return fmt.Errorf("lookup_stubs.go: build tag pattern not found (possible Go version mismatch)")
		}
		if err := os.WriteFile(path, []byte(newContent), 0o644); err != nil {
			return err
		}
	}

	// lookup_unix.go: ((unix && !android) || (js && wasm) || wasip1) && ((!cgo && !darwin) || osusergo)
	{
		path := filepath.Join(gorootSrc, "os", "user", "lookup_unix.go")
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		content := string(data)
		newContent := strings.Replace(content,
			"//go:build ((unix && !android) || (js && wasm) || wasip1) && ((!cgo && !darwin) || osusergo)",
			"//go:build ((unix && !android) || (js && wasm)) && ((!cgo && !darwin) || osusergo)",
			1)
		if newContent == content {
			return fmt.Errorf("lookup_unix.go: build tag pattern not found (possible Go version mismatch)")
		}
		if err := os.WriteFile(path, []byte(newContent), 0o644); err != nil {
			return err
		}
	}

	// listgroups_unix.go: remove wasip1 from the build constraint.
	// Go 1.25.3 changed from "unix && !android" to explicit OS list.
	{
		path := filepath.Join(gorootSrc, "os", "user", "listgroups_unix.go")
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		content := string(data)
		// Try the Go 1.25.3 format first (explicit OS list).
		newContent := strings.Replace(content,
			"//go:build ((darwin || dragonfly || freebsd || (js && wasm) || wasip1 || (!android && linux) || netbsd || openbsd || solaris) && ((!cgo && !darwin) || osusergo)) || aix || illumos",
			"//go:build ((darwin || dragonfly || freebsd || (js && wasm) || (!android && linux) || netbsd || openbsd || solaris) && ((!cgo && !darwin) || osusergo)) || aix || illumos",
			1)
		if newContent == content {
			// Fall back to older Go format (unix && !android).
			newContent = strings.Replace(content,
				"//go:build (((unix && !android) || (js && wasm) || wasip1) && ((!cgo && !darwin) || osusergo)) || aix",
				"//go:build (((unix && !android) || (js && wasm)) && ((!cgo && !darwin) || osusergo)) || aix",
				1)
		}
		if newContent == content {
			return fmt.Errorf("listgroups_unix.go: build tag pattern not found (possible Go version mismatch)")
		}
		if err := os.WriteFile(path, []byte(newContent), 0o644); err != nil {
			return err
		}
	}

	return nil
}

// patchGetpid replaces the hardcoded Getpid() in syscall_wasip1.go with a
// call to the wasmforge host function that returns the real host process PID.
func patchGetpid(gorootSrc string) error {
	path := filepath.Join(gorootSrc, "syscall", "syscall_wasip1.go")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	content := string(data)

	newContent := strings.Replace(content,
		`func Getpid() int {
	return 3
}`,
		`func Getpid() int {
	return WasmForgeGetpid()
}`,
		1)
	if newContent == content {
		return fmt.Errorf("patchGetpid: Getpid pattern not found in syscall_wasip1.go (possible Go version mismatch)")
	}

	return os.WriteFile(path, []byte(newContent), 0o644)
}

// patchGetwdChdir replaces the Getwd and Chdir implementations in fs_wasip1.go
// to use wasmforge host functions for real host CWD, while keeping the original
// WASI VFS cwd for file operations.
func patchGetwdChdir(gorootSrc string) error {
	path := filepath.Join(gorootSrc, "syscall", "fs_wasip1.go")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	content := string(data)

	// Replace Getwd to call wasmforge host function.
	newContent := strings.Replace(content,
		`func Getwd() (string, error) {
	return cwd, nil
}`,
		`func Getwd() (string, error) {
	return WasmForgeGetwd()
}`,
		1)
	if newContent == content {
		return fmt.Errorf("patchGetwdChdir: Getwd pattern not found in fs_wasip1.go")
	}
	content = newContent

	// Replace Chdir: update both the WASI VFS cwd and the real host CWD.
	oldChdir := `func Chdir(path string) error {
	if path == "" {
		return EINVAL
	}

	dir := "/"
	if !isAbs(path) {
		dir = cwd
	}
	path = joinPath(dir, path)

	var stat Stat_t
	dirFd, pathPtr, pathLen := preparePath(path)
	errno := path_filestat_get(dirFd, LOOKUP_SYMLINK_FOLLOW, pathPtr, pathLen, unsafe.Pointer(&stat))
	if errno != 0 {
		return errnoErr(errno)
	}
	if stat.Filetype != FILETYPE_DIRECTORY {
		return ENOTDIR
	}
	cwd = path
	return nil
}`

	newChdir := `func Chdir(path string) error {
	if path == "" {
		return EINVAL
	}

	// Change the real host CWD.
	if err := WasmForgeChdir(path); err != nil {
		return err
	}

	dir := "/"
	if !isAbs(path) {
		dir = cwd
	}
	path = joinPath(dir, path)

	var stat Stat_t
	dirFd, pathPtr, pathLen := preparePath(path)
	errno := path_filestat_get(dirFd, LOOKUP_SYMLINK_FOLLOW, pathPtr, pathLen, unsafe.Pointer(&stat))
	if errno != 0 {
		// WASI VFS stat may fail for paths outside mounted dirs — that's OK
		// since we already changed the real host CWD. Update internal tracking.
		cwd = path
		return nil
	}
	if stat.Filetype != FILETYPE_DIRECTORY {
		return ENOTDIR
	}
	cwd = path
	return nil
}`

	newContent = strings.Replace(content, oldChdir, newChdir, 1)
	if newContent == content {
		return fmt.Errorf("patchGetwdChdir: Chdir pattern not found in fs_wasip1.go")
	}

	return os.WriteFile(path, []byte(newContent), 0o644)
}

// patchStartProcessWait4 replaces the ENOSYS stubs for StartProcess and Wait4
// in syscall_wasip1.go with host function proxies.
func patchStartProcessWait4(gorootSrc string) error {
	path := filepath.Join(gorootSrc, "syscall", "syscall_wasip1.go")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	content := string(data)

	// Replace StartProcess.
	newContent := strings.Replace(content,
		`func StartProcess(argv0 string, argv []string, attr *ProcAttr) (pid int, handle uintptr, err error) {
	return 0, 0, ENOSYS
}`,
		`func StartProcess(argv0 string, argv []string, attr *ProcAttr) (pid int, handle uintptr, err error) {
	fullArgv := append([]string{argv0}, argv...)
	var env []string
	var dir string
	var stdoutFD, stderrFD int
	if attr != nil {
		env = attr.Env
		dir = attr.Dir
		// Pass stdout/stderr pipe FDs to the host so the child process
		// output can be captured via WASM pipes (e.g., for execute-assembly).
		if len(attr.Files) > 1 {
			stdoutFD = int(attr.Files[1])
		}
		if len(attr.Files) > 2 {
			stderrFD = int(attr.Files[2])
		}
	}
	p, err := WasmForgeStartProcess(fullArgv, env, dir, stdoutFD, stderrFD)
	if err != nil {
		return 0, 0, err
	}
	return p, uintptr(p), nil
}`,
		1)
	if newContent == content {
		return fmt.Errorf("patchStartProcessWait4: StartProcess pattern not found in syscall_wasip1.go")
	}
	content = newContent

	// Replace Wait4 to call WasmForgeWait4 with yield-retry protocol.
	newContent = strings.Replace(content,
		`func Wait4(pid int, wstatus *WaitStatus, options int, rusage *Rusage) (wpid int, err error) {
	return 0, ENOSYS
}`,
		`func Wait4(pid int, wstatus *WaitStatus, options int, rusage *Rusage) (wpid int, err error) {
	return WasmForgeWait4(pid, wstatus, options, rusage)
}`,
		1)
	if newContent == content {
		return fmt.Errorf("patchStartProcessWait4: Wait4 pattern not found in syscall_wasip1.go")
	}

	return os.WriteFile(path, []byte(newContent), 0o644)
}

// patchPreparePath adds path normalization to the preparePath function
// in fs_wasip1.go, converting Windows-style paths (C:\foo) to WASI paths (/c/foo).
func patchPreparePath(gorootSrc string) error {
	path := filepath.Join(gorootSrc, "syscall", "fs_wasip1.go")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	content := string(data)

	// Add normalizePath call at the beginning of preparePath.
	newContent := strings.Replace(content,
		`func preparePath(path string) (int32, *byte, size) {
	var dirFd = int32(-1)
	var dirName string

	dir := "/"
	if !isAbs(path) {
		dir = cwd
	}`,
		`func preparePath(path string) (int32, *byte, size) {
	path = normalizePath(path)

	var dirFd = int32(-1)
	var dirName string

	dir := "/"
	if !isAbs(path) {
		dir = cwd
	}`,
		1)
	if newContent == content {
		return fmt.Errorf("patchPreparePath: preparePath pattern not found in fs_wasip1.go")
	}

	return os.WriteFile(path, []byte(newContent), 0o644)
}

// patchOsGetwd modifies os/getwd.go's Getwd() to directly call syscall.Getwd()
// on wasip1, bypassing the stat(".") validation that fails in the WASM VFS.
// We can't use runtime.GOOS because it's rewritten to the target platform.
// Instead, we add "wasip1" to the fast-path check alongside windows/plan9.
func patchOsGetwd(gorootSrc string) error {
	path := filepath.Join(gorootSrc, "os", "getwd.go")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	content := string(data)

	// Add wasip1 to the fast-path that directly calls syscall.Getwd().
	// The original checks for windows/plan9 — we add GOWASMARCH check which
	// is always set on wasip1. But actually, we need a compile-time check.
	// Simplest: replace the GOOS check to also match a const we can set.
	newContent := strings.Replace(content,
		`if runtime.GOOS == "windows" || runtime.GOOS == "plan9" {
		// Use syscall.Getwd directly for
		//   - plan9: see reasons in CL 89575;
		//   - windows: syscall implementation is sufficient,
		//     and we should not rely on $PWD.
		dir, err = syscall.Getwd()
		return dir, NewSyscallError("getwd", err)
	}`,
		`if runtime.GOOS == "windows" || runtime.GOOS == "plan9" || runtime.GOARCH == "wasm" {
		// Use syscall.Getwd directly for wasip1 (wasmforge host function),
		// windows, and plan9 where stat(".") may not work.
		dir, err = syscall.Getwd()
		return dir, NewSyscallError("getwd", err)
	}`,
		1)
	if newContent == content {
		return fmt.Errorf("patchOsGetwd: Getwd fast-path pattern not found in os/getwd.go")
	}

	return os.WriteFile(path, []byte(newContent), 0o644)
}

// patchExecRun modifies os/exec/exec.go's Cmd.Run() to fall back to
// wasmforgeRunFallback when Start() fails. On wasip1, os.Pipe() returns
// ENOSYS which prevents Start() from working. The fallback uses the
// wasmforge os_exec host function for synchronous execution.
func patchExecRun(gorootSrc string) error {
	path := filepath.Join(gorootSrc, "os", "exec", "exec.go")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	content := string(data)

	// Always use the synchronous fallback for Run(). On wasip1, Start()
	// now succeeds (pipes work, StartProcess works), but the internal
	// pipe-copy goroutines that exec.Cmd.Start() spawns fail because
	// os.(*File).Read() goes through WASI fd_read (not our patched
	// syscall.Read), so pipe FDs >= 15000 return EBADF. The fallback
	// uses the host os_exec function which captures output internally.
	// cmd.Start()+cmd.Wait() (used by Sliver's startExecuteChild) still
	// works because it doesn't depend on internal pipe reads.
	newContent := strings.Replace(content,
		`func (c *Cmd) Run() error {
	if err := c.Start(); err != nil {
		return err
	}
	return c.Wait()
}`,
		`func (c *Cmd) Run() error {
	return wasmforgeRunFallback(c)
}`,
		1)
	if newContent == content {
		return fmt.Errorf("patchExecRun: Cmd.Run() pattern not found in os/exec/exec.go (possible Go version mismatch)")
	}

	if err := os.WriteFile(path, []byte(newContent), 0o644); err != nil {
		return err
	}

	// Write the non-wasip1 stub directly (not embedded, to avoid build tag
	// conflicts in the embedder context where !wasip1 is always true).
	stubPath := filepath.Join(gorootSrc, "os", "exec", "exec_other.go")
	stub := `//go:build !wasip1

package exec

import "errors"

func wasmforgeRunFallback(c *Cmd) error {
	return errors.New("wasmforge exec fallback not available")
}
`
	return os.WriteFile(stubPath, []byte(stub), 0o644)
}

// patchExecLookPath replaces the wasm LookPath stub in os/exec/lp_wasm.go
// with an implementation that passes the file path through unchanged.
// The original stub unconditionally returns ErrNotFound ("Wasm can not
// execute processes"), which blocks exec.Command().Start() by setting
// lookPathErr. WasmForge CAN execute processes via host functions, and
// the host-side resolveExecPath() handles PATH resolution and WASI path
// denormalization.
func patchExecLookPath(gorootSrc string) error {
	path := filepath.Join(gorootSrc, "os", "exec", "lp_wasm.go")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	content := string(data)

	// Try the old lowercase pattern (Go ≤1.25.3).
	newContent := strings.Replace(content,
		`func lookPath(file string) (string, error) {
	// Wasm can not execute processes, so act as if there are no executables at all.
	return "", &Error{file, ErrNotFound}
}`,
		`func lookPath(file string) (string, error) {
	// WasmForge: pass through the path — host-side resolveExecPath() handles
	// PATH resolution and WASI path denormalization.
	return file, nil
}`,
		1)
	if newContent == content {
		// Try the new exported uppercase pattern (Go ≥1.25.5).
		newContent = strings.Replace(content,
			`func LookPath(file string) (string, error) {
	// Wasm can not execute processes, so act as if there are no executables at all.
	return "", &Error{file, ErrNotFound}
}`,
			`func LookPath(file string) (string, error) {
	// WasmForge: pass through the path — host-side resolveExecPath() handles
	// PATH resolution and WASI path denormalization.
	return file, nil
}`,
			1)
	}
	if newContent == content {
		return fmt.Errorf("patchExecLookPath: lookPath/LookPath pattern not found in os/exec/lp_wasm.go (possible Go version mismatch)")
	}

	return os.WriteFile(path, []byte(newContent), 0o644)
}

// patchOsPipeWasm replaces the ENOSYS stub in os/pipe_wasm.go with an
// implementation that calls syscall.Pipe() and wraps the returned FDs
// as os.File objects. The original hard-returns ENOSYS without calling
// syscall.Pipe, so our syscall-level patch never runs.
func patchOsPipeWasm(gorootSrc string) error {
	path := filepath.Join(gorootSrc, "os", "pipe_wasm.go")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	content := string(data)

	newContent := strings.Replace(content,
		`func Pipe() (r *File, w *File, err error) {
	// Neither GOOS=js nor GOOS=wasip1 have pipes.
	return nil, nil, NewSyscallError("pipe", syscall.ENOSYS)
}`,
		`func Pipe() (r *File, w *File, err error) {
	var p [2]int
	e := syscall.Pipe(p[0:])
	if e != nil {
		return nil, nil, NewSyscallError("pipe", e)
	}
	return NewFile(uintptr(p[0]), "|0"), NewFile(uintptr(p[1]), "|1"), nil
}`,
		1)
	if newContent == content {
		return fmt.Errorf("patchOsPipeWasm: Pipe() pattern not found in os/pipe_wasm.go (possible Go version mismatch)")
	}

	return os.WriteFile(path, []byte(newContent), 0o644)
}

// patchSyscallPipe replaces the ENOSYS stub for Pipe in fs_wasip1.go with
// a call to WasmForgePipe, which creates real OS pipes via host functions.
func patchSyscallPipe(gorootSrc string) error {
	path := filepath.Join(gorootSrc, "syscall", "fs_wasip1.go")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	content := string(data)

	newContent := strings.Replace(content,
		`func Pipe(fd []int) error {
	return ENOSYS
}`,
		`func Pipe(fd []int) error {
	return WasmForgePipe(fd)
}`,
		1)
	if newContent == content {
		return fmt.Errorf("patchSyscallPipe: Pipe pattern not found in fs_wasip1.go")
	}

	return os.WriteFile(path, []byte(newContent), 0o644)
}

// patchSyscallReadWriteClose patches Read, Write, and Close in fs_wasip1.go
// to detect WasmForge pipe FDs (>= 15000) and route them to pipe host
// functions instead of WASI fd_read/fd_write/fd_close.
func patchSyscallReadWriteClose(gorootSrc string) error {
	path := filepath.Join(gorootSrc, "syscall", "fs_wasip1.go")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	content := string(data)

	// Patch Read to route pipe FDs to host function.
	newContent := strings.Replace(content,
		`func Read(fd int, b []byte) (int, error) {
	var nread size
	errno := fd_read(int32(fd), makeIOVec(b), 1, &nread)
	runtime.KeepAlive(b)
	return int(nread), errnoErr(errno)
}`,
		`func Read(fd int, b []byte) (int, error) {
	if IsWasmForgePipeFD(fd) {
		return WasmForgePipeRead(fd, b)
	}
	var nread size
	errno := fd_read(int32(fd), makeIOVec(b), 1, &nread)
	runtime.KeepAlive(b)
	return int(nread), errnoErr(errno)
}`,
		1)
	if newContent == content {
		return fmt.Errorf("patchSyscallReadWriteClose: Read pattern not found in fs_wasip1.go")
	}
	content = newContent

	// Patch Write to route pipe FDs to host function.
	newContent = strings.Replace(content,
		`func Write(fd int, b []byte) (int, error) {
	var nwritten size
	errno := fd_write(int32(fd), makeIOVec(b), 1, &nwritten)
	runtime.KeepAlive(b)
	return int(nwritten), errnoErr(errno)
}`,
		`func Write(fd int, b []byte) (int, error) {
	if IsWasmForgePipeFD(fd) {
		return WasmForgePipeWrite(fd, b)
	}
	var nwritten size
	errno := fd_write(int32(fd), makeIOVec(b), 1, &nwritten)
	runtime.KeepAlive(b)
	return int(nwritten), errnoErr(errno)
}`,
		1)
	if newContent == content {
		return fmt.Errorf("patchSyscallReadWriteClose: Write pattern not found in fs_wasip1.go")
	}
	content = newContent

	// Patch Close to route pipe FDs to host function.
	newContent = strings.Replace(content,
		`func Close(fd int) error {
	errno := fd_close(int32(fd))
	return errnoErr(errno)
}`,
		`func Close(fd int) error {
	if IsWasmForgePipeFD(fd) {
		return WasmForgePipeClose(fd)
	}
	errno := fd_close(int32(fd))
	return errnoErr(errno)
}`,
		1)
	if newContent == content {
		return fmt.Errorf("patchSyscallReadWriteClose: Close pattern not found in fs_wasip1.go")
	}

	return os.WriteFile(path, []byte(newContent), 0o644)
}

// patchErrnoError patches syscall.Errno.Error() in syscall_wasip1.go so that
// Errno(0) returns "The operation completed successfully." instead of "errno 0".
// On real Windows, FormatMessage produces this exact string for error code 0.
// Programs like goffloader compare err.Error() against this string to detect
// success from syscall.Proc.Call (which always returns a non-nil Errno).
func patchErrnoError(gorootSrc string) error {
	path := filepath.Join(gorootSrc, "syscall", "syscall_wasip1.go")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	content := string(data)

	// Try the old pattern (Go ≤1.25.3): uses strconv.Itoa.
	newContent := strings.Replace(content,
		`func (e Errno) Error() string {
	if 0 <= int(e) && int(e) < len(errorstr) {
		s := errorstr[e]
		if s != "" {
			return s
		}
	}
	return "errno " + strconv.Itoa(int(e))
}`,
		`func (e Errno) Error() string {
	// WasmForge: Errno(0) returns the Windows-compatible success string so that
	// code comparing err.Error() against "The operation completed successfully."
	// (e.g., goffloader's VirtualProtect check) works correctly.
	if e == 0 {
		return "The operation completed successfully."
	}
	if 0 < int(e) && int(e) < len(errorstr) {
		s := errorstr[e]
		if s != "" {
			return s
		}
	}
	return "errno " + strconv.Itoa(int(e))
}`,
		1)
	if newContent == content {
		// Try the new pattern (Go ≥1.25.5): uses itoa.Itoa from internal/itoa.
		newContent = strings.Replace(content,
			`func (e Errno) Error() string {
	if 0 <= int(e) && int(e) < len(errorstr) {
		s := errorstr[e]
		if s != "" {
			return s
		}
	}
	return "errno " + itoa.Itoa(int(e))
}`,
			`func (e Errno) Error() string {
	// WasmForge: Errno(0) returns the Windows-compatible success string so that
	// code comparing err.Error() against "The operation completed successfully."
	// (e.g., goffloader's VirtualProtect check) works correctly.
	if e == 0 {
		return "The operation completed successfully."
	}
	if 0 < int(e) && int(e) < len(errorstr) {
		s := errorstr[e]
		if s != "" {
			return s
		}
	}
	return "errno " + itoa.Itoa(int(e))
}`,
			1)
	}
	if newContent == content {
		return fmt.Errorf("patchErrnoError: Errno.Error() pattern not found in syscall_wasip1.go (possible Go version mismatch)")
	}

	return os.WriteFile(path, []byte(newContent), 0o644)
}

// patchOsOpenWasip1 patches os/file_open_wasip1.go so that the absoluteness
// check recognises Windows-style drive paths (C:\...) as absolute. Without
// this, os.Open("C:\Temp\foo.exe") prepends the CWD and produces a garbage
// path like "/c/Windows/system32/C:\Temp\foo.exe" → EINVAL.
func patchOsOpenWasip1(gorootSrc string) error {
	path := filepath.Join(gorootSrc, "os", "file_open_wasip1.go")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	content := string(data)

	// Replace the absoluteness check with one that also handles Windows drive
	// letters and normalizes backslashes. We replace the section from the
	// empty-check through the CWD prepend.
	newContent := strings.Replace(content,
		`if filePath == "" {
		return -1, poll.SysFile{}, syscall.EINVAL
	}
	absPath := filePath
	// os.(*File).Chdir is emulated by setting the working directory to the
	// absolute path that this file was opened at, which is why we have to
	// resolve and capture it here.
	if filePath[0] != '/' {`,
		`if filePath == "" {
		return -1, poll.SysFile{}, syscall.EINVAL
	}
	// WasmForge: normalize Windows-style paths (C:\foo → /c/foo) before
	// the absoluteness check so drive-letter paths aren't treated as relative.
	if len(filePath) >= 2 && filePath[1] == ':' &&
		((filePath[0] >= 'A' && filePath[0] <= 'Z') || (filePath[0] >= 'a' && filePath[0] <= 'z')) {
		drive := filePath[0]
		if drive >= 'A' && drive <= 'Z' {
			drive = drive + ('a' - 'A')
		}
		filePath = "/" + string(drive) + filePath[2:]
	}
	for i := 0; i < len(filePath); i++ {
		if filePath[i] == '\\' {
			b := []byte(filePath)
			for j := i; j < len(b); j++ {
				if b[j] == '\\' {
					b[j] = '/'
				}
			}
			filePath = string(b)
			break
		}
	}
	absPath := filePath
	// os.(*File).Chdir is emulated by setting the working directory to the
	// absolute path that this file was opened at, which is why we have to
	// resolve and capture it here.
	if filePath[0] != '/' {`,
		1)
	if newContent == content {
		return fmt.Errorf("patchOsOpenWasip1: file_open_wasip1.go pattern not found (possible Go version mismatch)")
	}

	return os.WriteFile(path, []byte(newContent), 0o644)
}

// patchOsDevNull changes os.DevNull from "/dev/null" to "NUL" in the wasip1
// build of os/file_unix.go. On Windows hosts, the WASI filesystem has no
// /dev/ mount, so opening "/dev/null" fails with EBADF. exec.Cmd.Start()
// opens os.DevNull for nil stdin, causing "open /dev/null: Bad file number".
func patchOsDevNull(gorootSrc string) error {
	path := filepath.Join(gorootSrc, "os", "file_unix.go")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	content := string(data)

	newContent := strings.Replace(content,
		`const DevNull = "/dev/null"`,
		`const DevNull = "NUL"`,
		1)
	if newContent == content {
		return fmt.Errorf("patchOsDevNull: DevNull pattern not found in os/file_unix.go (possible Go version mismatch)")
	}

	return os.WriteFile(path, []byte(newContent), 0o644)
}
