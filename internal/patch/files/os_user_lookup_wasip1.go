// WasmForge replacement for os/user/lookup_stubs.go on wasip1.
// Provides real user info via wasmforge host function.

//go:build wasip1

package user

import (
	"encoding/json"
	"fmt"
	"strconv"
	"syscall"
)

//go:wasmimport env sys_user
//go:noescape
func wasmforge_os_user_current(bufPtr *byte, bufCap uint32, resultLenPtr *uint32) uint32

func current() (*User, error) {
	var buf [4096]byte
	var resultLen uint32
	errno := wasmforge_os_user_current(&buf[0], uint32(len(buf)), &resultLen)
	if errno != 0 {
		return nil, fmt.Errorf("wasmforge: os_user_current failed: %w", syscall.Errno(errno))
	}

	var info struct {
		UID      string `json:"uid"`
		GID      string `json:"gid"`
		Username string `json:"username"`
		Name     string `json:"name"`
		HomeDir  string `json:"home_dir"`
	}

	if err := json.Unmarshal(buf[:resultLen], &info); err != nil {
		return nil, fmt.Errorf("wasmforge: os_user_current: bad json: %w", err)
	}

	return &User{
		Uid:      info.UID,
		Gid:      info.GID,
		Username: info.Username,
		Name:     info.Name,
		HomeDir:  info.HomeDir,
	}, nil
}

func lookupUser(username string) (*User, error) {
	// Best effort: if username matches current user, return that.
	u, err := current()
	if err != nil {
		return nil, err
	}
	if u.Username == username {
		return u, nil
	}
	return nil, UnknownUserError(username)
}

func lookupUserId(uid string) (*User, error) {
	u, err := current()
	if err != nil {
		return nil, err
	}
	if u.Uid == uid {
		return u, nil
	}
	uidInt, _ := strconv.Atoi(uid)
	return nil, UnknownUserIdError(uidInt)
}

func lookupGroup(groupname string) (*Group, error) {
	return nil, fmt.Errorf("user: LookupGroup: not supported on wasip1")
}

func lookupGroupId(gid string) (*Group, error) {
	return nil, fmt.Errorf("user: LookupGroupId: not supported on wasip1")
}

func listGroups(u *User) ([]string, error) {
	return nil, fmt.Errorf("user: GroupIds: not supported on wasip1")
}
