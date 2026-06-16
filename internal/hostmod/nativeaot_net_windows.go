//go:build nativeaot && windows

// NativeAOT-specific Windows network host functions.
// Provides TCP framing (Kerberos-style), DC name resolution, and LDAP search
// for .NET NativeAOT-WASI guest code that cannot use WASI P2 sockets.
// Only compiled when both the "nativeaot" and "windows" build tags are active.

package hostmod

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/tetratelabs/wazero/api"
)

// ldapReadWideStringArray reads a null-terminated array of wide string pointers
// as returned by ldap_get_valuesW and similar LDAP functions.
func ldapReadWideStringArray(ptr uintptr) []string {
	var result []string
	for i := uintptr(0); ; i++ {
		strPtr := *(*uintptr)(unsafe.Pointer(ptr + i*unsafe.Sizeof(uintptr(0))))
		if strPtr == 0 {
			break
		}
		result = append(result, ldapReadWideString(strPtr))
	}
	return result
}

// ldapReadWideString reads a null-terminated wide string from a host pointer.
func ldapReadWideString(ptr uintptr) string {
	return syscall.UTF16ToString((*[4096]uint16)(unsafe.Pointer(ptr))[:])
}

// win32LdapModify performs a single-attribute, single-value LDAP modify
// (ADD/DELETE/REPLACE) on the given DN using NEGOTIATE bind. Used by the
// managetemplate verb to update msPKI-Enrollment-Flag, set certificate
// template flags, and similar single-attribute writes.
//
// op_code: 0 = LDAP_MOD_ADD, 1 = LDAP_MOD_DELETE, 2 = LDAP_MOD_REPLACE.
// Pass valLen=0 to delete the attribute entirely (only legal with op=DELETE).
//
// Returns 0 on success, or the raw LDAP error code (>0) on failure.
func win32LdapModify(ctx context.Context, mod api.Module,
	serverPtr, serverLen, port,
	dnPtr, dnLen, attrPtr, attrLen, valPtr, valLen, opCode,
	userPtr, userLen, domainPtr, domainLen,
	passwordPtr, passwordLen uint32) uint32 {

	serverBytes, ok := readBytes(mod, serverPtr, serverLen)
	if !ok {
		return uint32(0x57) // ERROR_INVALID_PARAMETER
	}
	dnBytes, ok := readBytes(mod, dnPtr, dnLen)
	if !ok {
		return uint32(0x57)
	}
	attrBytes, ok := readBytes(mod, attrPtr, attrLen)
	if !ok {
		return uint32(0x57)
	}
	var valBytes []byte
	if valLen > 0 {
		valBytes, _ = readBytes(mod, valPtr, valLen)
	}
	var userBytes, domainBytes, passwordBytes []byte
	if userLen > 0 {
		userBytes, _ = readBytes(mod, userPtr, userLen)
	}
	if domainLen > 0 {
		domainBytes, _ = readBytes(mod, domainPtr, domainLen)
	}
	if passwordLen > 0 {
		passwordBytes, _ = readBytes(mod, passwordPtr, passwordLen)
	}

	wldap32 := syscall.NewLazyDLL("wldap32.dll")
	ldapInitW := wldap32.NewProc("ldap_initW")
	ldapSetOptionW := wldap32.NewProc("ldap_set_optionW")
	ldapBindSW := wldap32.NewProc("ldap_bind_sW")
	ldapModifySW := wldap32.NewProc("ldap_modify_sW")
	ldapUnbind := wldap32.NewProc("ldap_unbind")

	serverUTF16, err := syscall.UTF16PtrFromString(string(serverBytes))
	if err != nil {
		return uint32(0x57)
	}

	ld, _, _ := ldapInitW.Call(uintptr(unsafe.Pointer(serverUTF16)), uintptr(port))
	if ld == 0 {
		return uint32(0x51) // ERROR_NETWORK_UNREACHABLE
	}
	defer ldapUnbind.Call(ld)

	// Protocol v3, no referrals, SASL signing + sealing — same as LdapSearch.
	var version uint32 = 3
	ldapSetOptionW.Call(ld, 0x11, uintptr(unsafe.Pointer(&version)))
	var referrals uint32 = 0
	ldapSetOptionW.Call(ld, 0x08, uintptr(unsafe.Pointer(&referrals)))
	enabled := uintptr(1)
	ldapSetOptionW.Call(ld, 0x95, uintptr(unsafe.Pointer(&enabled)))
	ldapSetOptionW.Call(ld, 0x96, uintptr(unsafe.Pointer(&enabled)))

	const ldapAuthNegotiate = 0x0486
	var bindCredArg uintptr
	var userUTF16, domainUTF16, passwordUTF16 *uint16
	hasCreds := len(userBytes) > 0 || len(passwordBytes) > 0
	if hasCreds {
		type secWinntAuthIdentityW struct {
			User           *uint16
			UserLength     uint32
			_              uint32
			Domain         *uint16
			DomainLength   uint32
			_              uint32
			Password       *uint16
			PasswordLength uint32
			Flags          uint32
		}
		if len(userBytes) > 0 {
			userUTF16, _ = syscall.UTF16PtrFromString(string(userBytes))
		}
		if len(domainBytes) > 0 {
			domainUTF16, _ = syscall.UTF16PtrFromString(string(domainBytes))
		}
		if len(passwordBytes) > 0 {
			passwordUTF16, _ = syscall.UTF16PtrFromString(string(passwordBytes))
		}
		ident := secWinntAuthIdentityW{
			User:           userUTF16,
			UserLength:     uint32(len([]rune(string(userBytes)))),
			Domain:         domainUTF16,
			DomainLength:   uint32(len([]rune(string(domainBytes)))),
			Password:       passwordUTF16,
			PasswordLength: uint32(len([]rune(string(passwordBytes)))),
			Flags:          2,
		}
		bindCredArg = uintptr(unsafe.Pointer(&ident))
		_ = userUTF16
		_ = domainUTF16
		_ = passwordUTF16
	}
	ret, _, _ := ldapBindSW.Call(ld, 0, bindCredArg, ldapAuthNegotiate)
	if ret != 0 {
		fmt.Fprintf(os.Stderr, "[runtime] win32LdapModify: ldap_bind_sW failed: 0x%x\n", ret)
		return uint32(ret)
	}

	// Build LDAPModW { mod_op; mod_type; mod_values }.
	// modValues is a null-terminated array of wide-string pointers.
	dnUTF16, err := syscall.UTF16PtrFromString(string(dnBytes))
	if err != nil {
		return uint32(0x57)
	}
	attrUTF16, err := syscall.UTF16PtrFromString(string(attrBytes))
	if err != nil {
		return uint32(0x57)
	}
	var valUTF16 *uint16
	if len(valBytes) > 0 {
		valUTF16, _ = syscall.UTF16PtrFromString(string(valBytes))
	}
	var modValues [2]uintptr
	if valUTF16 != nil {
		modValues[0] = uintptr(unsafe.Pointer(valUTF16))
	}
	type ldapModW struct {
		ModOp     uint32
		_         uint32 // x64 pad after a 32-bit field followed by 8-byte ptr
		ModType   *uint16
		ModValues *uintptr // points to modValues[0] or NULL
	}
	m := ldapModW{
		ModOp:   opCode, // 0=ADD, 1=DELETE, 2=REPLACE
		ModType: attrUTF16,
	}
	if valUTF16 != nil {
		m.ModValues = &modValues[0]
	}
	mods := [2]uintptr{uintptr(unsafe.Pointer(&m)), 0}

	ret, _, _ = ldapModifySW.Call(
		ld,
		uintptr(unsafe.Pointer(dnUTF16)),
		uintptr(unsafe.Pointer(&mods[0])),
	)
	_ = dnUTF16
	_ = attrUTF16
	_ = valUTF16
	if ret != 0 {
		fmt.Fprintf(os.Stderr, "[runtime] win32LdapModify: ldap_modify_sW failed: 0x%x\n", ret)
		return uint32(ret)
	}
	return 0
}
