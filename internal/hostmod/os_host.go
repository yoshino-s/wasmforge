package hostmod

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"

	"github.com/tetratelabs/wazero/api"
)

// osHostname implements the wasmforge.os_hostname host function.
// Writes the real host hostname to a WASM buffer.
//
// Guest ABI:
//
//	buf_ptr:        pointer to output buffer
//	buf_cap:        capacity of output buffer
//	result_len_ptr: pointer to write actual length of hostname
//
// Returns WASI errno (0 = success).
func osHostname(_ context.Context, mod api.Module, stack []uint64) {
	bufPtr := uint32(stack[0])
	bufCap := uint32(stack[1])
	resultLenPtr := uint32(stack[2])

	name, err := os.Hostname()
	if err != nil {
		stack[0] = uint64(errnoFromError(err))
		return
	}

	b := []byte(name)
	if uint32(len(b)) > bufCap {
		stack[0] = uint64(errnoERANGE)
		return
	}

	if !writeBytes(mod, bufPtr, b) {
		stack[0] = uint64(errnoEFAULT)
		return
	}
	if !writeUint32(mod, resultLenPtr, uint32(len(b))) {
		stack[0] = uint64(errnoEFAULT)
		return
	}

	stack[0] = uint64(errnoSuccess)
}

// osGetwd implements the wasmforge.os_getwd host function.
// Writes the real host current working directory to a WASM buffer.
//
// Guest ABI:
//
//	buf_ptr:        pointer to output buffer
//	buf_cap:        capacity of output buffer
//	result_len_ptr: pointer to write actual length of cwd
//
// Returns WASI errno (0 = success).
func osGetwd(_ context.Context, mod api.Module, stack []uint64) {
	bufPtr := uint32(stack[0])
	bufCap := uint32(stack[1])
	resultLenPtr := uint32(stack[2])

	cwd, err := os.Getwd()
	if err != nil {
		stack[0] = uint64(errnoFromError(err))
		return
	}

	b := []byte(cwd)
	if uint32(len(b)) > bufCap {
		stack[0] = uint64(errnoERANGE)
		return
	}

	if !writeBytes(mod, bufPtr, b) {
		stack[0] = uint64(errnoEFAULT)
		return
	}
	if !writeUint32(mod, resultLenPtr, uint32(len(b))) {
		stack[0] = uint64(errnoEFAULT)
		return
	}

	stack[0] = uint64(errnoSuccess)
}

// osChdir implements the wasmforge.os_chdir host function.
// Changes the real host current working directory.
//
// Guest ABI:
//
//	path_ptr: pointer to path string
//	path_len: length of path string
//
// Returns WASI errno (0 = success).
func osChdir(_ context.Context, mod api.Module, stack []uint64) {
	pathPtr := uint32(stack[0])
	pathLen := uint32(stack[1])

	pathBuf, ok := readBytes(mod, pathPtr, pathLen)
	if !ok {
		stack[0] = uint64(errnoEFAULT)
		return
	}

	err := os.Chdir(string(pathBuf))
	if err != nil {
		stack[0] = uint64(errnoFromError(err))
		return
	}

	stack[0] = uint64(errnoSuccess)
}

// userInfo is the JSON-serialized structure for os/user.Current() results.
type userInfo struct {
	UID      string `json:"uid"`
	GID      string `json:"gid"`
	Username string `json:"username"`
	Name     string `json:"name"`
	HomeDir  string `json:"home_dir"`
}

// osUserCurrent implements the wasmforge.os_user_current host function.
// Writes JSON-encoded user info to a WASM buffer.
//
// Guest ABI:
//
//	buf_ptr:        pointer to output buffer
//	buf_cap:        capacity of output buffer
//	result_len_ptr: pointer to write actual length of JSON
//
// Returns WASI errno (0 = success).
func osUserCurrent(_ context.Context, mod api.Module, stack []uint64) {
	bufPtr := uint32(stack[0])
	bufCap := uint32(stack[1])
	resultLenPtr := uint32(stack[2])

	u, err := user.Current()
	if err != nil {
		stack[0] = uint64(errnoFromError(err))
		return
	}

	info := userInfo{
		UID:      u.Uid,
		GID:      u.Gid,
		Username: u.Username,
		Name:     u.Name,
		HomeDir:  u.HomeDir,
	}

	b, err := json.Marshal(info)
	if err != nil {
		stack[0] = uint64(errnoEINVAL)
		return
	}

	if uint32(len(b)) > bufCap {
		stack[0] = uint64(errnoERANGE)
		return
	}

	if !writeBytes(mod, bufPtr, b) {
		stack[0] = uint64(errnoEFAULT)
		return
	}
	if !writeUint32(mod, resultLenPtr, uint32(len(b))) {
		stack[0] = uint64(errnoEFAULT)
		return
	}

	stack[0] = uint64(errnoSuccess)
}

// osGetpid implements the wasmforge.os_getpid host function.
// Returns the real host process PID.
//
// Guest ABI: no parameters. Returns PID as i32.
func osGetpid(_ context.Context, _ api.Module, stack []uint64) {
	stack[0] = uint64(os.Getpid())
}

// processInfo is the JSON-serialized structure for process list entries.
type processInfo struct {
	Pid  int32  `json:"pid"`
	Ppid int32  `json:"ppid"`
	UID  int32  `json:"uid"`
	Name string `json:"name"`
}

// osProcessList implements the wasmforge.os_process_list host function.
// Writes JSON-encoded list of running processes to a WASM buffer.
//
// Guest ABI:
//
//	buf_ptr:        pointer to output buffer
//	buf_cap:        capacity of output buffer
//	result_len_ptr: pointer to write actual length of JSON
//
// Returns WASI errno (0 = success).
func osProcessList(_ context.Context, mod api.Module, stack []uint64) {
	bufPtr := uint32(stack[0])
	bufCap := uint32(stack[1])
	resultLenPtr := uint32(stack[2])

	procs, err := listProcesses()
	if err != nil {
		stack[0] = uint64(errnoFromError(err))
		return
	}

	b, err := json.Marshal(procs)
	if err != nil {
		stack[0] = uint64(errnoEINVAL)
		return
	}

	if uint32(len(b)) > bufCap {
		stack[0] = uint64(errnoERANGE)
		return
	}

	if !writeBytes(mod, bufPtr, b) {
		stack[0] = uint64(errnoEFAULT)
		return
	}
	if !writeUint32(mod, resultLenPtr, uint32(len(b))) {
		stack[0] = uint64(errnoEFAULT)
		return
	}

	stack[0] = uint64(errnoSuccess)
}

// listProcesses enumerates running processes by calling `ps`.
func listProcesses() ([]processInfo, error) {
	cmd := exec.Command("ps", "-eo", "pid,ppid,uid,comm")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, err
	}

	var procs []processInfo
	for _, line := range strings.Split(out.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "PID") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		pid, _ := strconv.Atoi(fields[0])
		ppid, _ := strconv.Atoi(fields[1])
		uid, _ := strconv.Atoi(fields[2])
		name := strings.Join(fields[3:], " ")
		procs = append(procs, processInfo{
			Pid:  int32(pid),
			Ppid: int32(ppid),
			UID:  int32(uid),
			Name: name,
		})
	}
	return procs, nil
}
