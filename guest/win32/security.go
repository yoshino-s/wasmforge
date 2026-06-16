//go:build wasip1

package win32

import "fmt"

// Token access rights.
const (
	TOKEN_QUERY = uint32(0x0008)
)

// Token information class values.
const (
	TokenUser  = uint32(1)
	TokenOwner = uint32(4)
	TokenType  = uint32(8)
)

// OpenProcessToken opens the access token associated with a process handle.
func OpenProcessToken(process Handle, access uint32) (Handle, error) {
	var token int32
	errno := _win32_open_process_token(int32(process), access, &token)
	if err := errFromErrno(errno); err != nil {
		return 0, fmt.Errorf("win32: OpenProcessToken: %w", err)
	}
	return Handle(token), nil
}

// GetTokenInfo retrieves information about an access token. The caller provides
// buf as storage; the function returns the number of bytes needed. If buf is too
// small the caller should retry with a buffer of at least the returned size.
func GetTokenInfo(token Handle, infoClass uint32, buf []byte) (uint32, error) {
	var needed uint32
	var bufPtr *byte
	if len(buf) > 0 {
		bufPtr = &buf[0]
	}
	errno := _win32_get_token_info(int32(token), infoClass, bufPtr, uint32(len(buf)), &needed)
	if err := errFromErrno(errno); err != nil {
		return needed, fmt.Errorf("win32: GetTokenInfo class=%d: %w", infoClass, err)
	}
	return needed, nil
}

// OpenSCManager opens a connection to the service control manager on the
// specified machine. Pass an empty string for the local machine.
func OpenSCManager(machine string, access uint32) (Handle, error) {
	var machinePtr *byte
	machineLen := int32(0)
	if machine != "" {
		b := []byte(machine)
		machinePtr = &b[0]
		machineLen = int32(len(b))
	}
	var h int32
	errno := _win32_open_sc_manager(machinePtr, machineLen, access, &h)
	if err := errFromErrno(errno); err != nil {
		return 0, fmt.Errorf("win32: OpenSCManager %q: %w", machine, err)
	}
	return Handle(h), nil
}

// QueryServiceStatus returns the raw SERVICE_STATUS bytes for an open service handle.
// The SERVICE_STATUS structure is 28 bytes on both 32-bit and 64-bit Windows.
func QueryServiceStatus(svc Handle) ([]byte, error) {
	// SERVICE_STATUS is 7 DWORD fields = 28 bytes.
	buf := make([]byte, 28)
	errno := _win32_query_service_status(int32(svc), &buf[0])
	if err := errFromErrno(errno); err != nil {
		return nil, fmt.Errorf("win32: QueryServiceStatus: %w", err)
	}
	return buf, nil
}
