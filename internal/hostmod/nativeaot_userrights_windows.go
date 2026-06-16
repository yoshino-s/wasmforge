//go:build nativeaot && windows

package hostmod

// osEnumUserRightAssignments: stack[0]=buf_ptr, stack[1]=buf_cap, stack[2]=count_ptr → bytes_written.
// Emits NUL-separated UTF-8 records, one per right that has at least one assignee.
// Record format: "PrivilegeName|SID1,SID2,..." (pipe and comma delimited).
// The C# side splits on '|' for privilege/holders, then ',' for individual SIDs.

import (
	"context"
	"strings"
	"syscall"
	"unsafe"

	"github.com/tetratelabs/wazero/api"
)

// allPrivileges mirrors Seatbelt's UserRightAssignmentsCommand._allPrivileges list.
var allPrivileges = []string{
	"SeAssignPrimaryTokenPrivilege",
	"SeAuditPrivilege",
	"SeBackupPrivilege",
	"SeBatchLogonRight",
	"SeChangeNotifyPrivilege",
	"SeCreateGlobalPrivilege",
	"SeCreatePagefilePrivilege",
	"SeCreatePermanentPrivilege",
	"SeCreateSymbolicLinkPrivilege",
	"SeCreateTokenPrivilege",
	"SeDebugPrivilege",
	"SeDenyBatchLogonRight",
	"SeDenyInteractiveLogonRight",
	"SeDenyNetworkLogonRight",
	"SeDenyRemoteInteractiveLogonRight",
	"SeDenyServiceLogonRight",
	"SeEnableDelegationPrivilege",
	"SeImpersonatePrivilege",
	"SeIncreaseBasePriorityPrivilege",
	"SeIncreaseQuotaPrivilege",
	"SeIncreaseWorkingSetPrivilege",
	"SeInteractiveLogonRight",
	"SeLoadDriverPrivilege",
	"SeLockMemoryPrivilege",
	"SeMachineAccountPrivilege",
	"SeManageVolumePrivilege",
	"SeNetworkLogonRight",
	"SeProfileSingleProcessPrivilege",
	"SeRelabelPrivilege",
	"SeRemoteInteractiveLogonRight",
	"SeRemoteShutdownPrivilege",
	"SeRestorePrivilege",
	"SeSecurityPrivilege",
	"SeServiceLogonRight",
	"SeShutdownPrivilege",
	"SeSyncAgentPrivilege",
	"SeSystemEnvironmentPrivilege",
	"SeSystemProfilePrivilege",
	"SeSystemtimePrivilege",
	"SeTakeOwnershipPrivilege",
	"SeTcbPrivilege",
	"SeTimeZonePrivilege",
	"SeTrustedCredManAccessPrivilege",
	"SeUndockPrivilege",
	"SeUnsolicitedInputPrivilege",
}

// LSA_ENUMERATION_INFORMATION is a single SID pointer as returned by
// LsaEnumerateAccountsWithUserRight. On x64 the struct is exactly 8 bytes.
type lsaEnumInfo struct {
	Sid uintptr
}

func osEnumUserRightAssignments(_ context.Context, mod api.Module, stack []uint64) {
	bufPtr := uint32(stack[0])
	bufCap := uint32(stack[1])
	countPtr := uint32(stack[2])

	advapi32, err := syscall.LoadDLL("advapi32.dll")
	if err != nil {
		writeUint32(mod, countPtr, 0)
		stack[0] = 0
		return
	}
	defer advapi32.Release()

	pLsaOpenPolicy, err := advapi32.FindProc("LsaOpenPolicy")
	if err != nil {
		writeUint32(mod, countPtr, 0)
		stack[0] = 0
		return
	}
	pLsaEnum, err := advapi32.FindProc("LsaEnumerateAccountsWithUserRight")
	if err != nil {
		writeUint32(mod, countPtr, 0)
		stack[0] = 0
		return
	}
	pLsaFree, err := advapi32.FindProc("LsaFreeMemory")
	if err != nil {
		writeUint32(mod, countPtr, 0)
		stack[0] = 0
		return
	}
	pLsaClose, err := advapi32.FindProc("LsaClose")
	if err != nil {
		writeUint32(mod, countPtr, 0)
		stack[0] = 0
		return
	}
	pConvertSid, _ := advapi32.FindProc("ConvertSidToStringSidW")

	// LSA_OBJECT_ATTRIBUTES (all zeros is valid for a local policy open).
	var objAttrs [48]byte
	*(*uint32)(unsafe.Pointer(&objAttrs[0])) = 48 // Length field

	const POLICY_VIEW_LOCAL_INFORMATION = 0x00000001
	const POLICY_LOOKUP_NAMES = 0x00000800

	var polHandle uintptr
	ret, _, _ := pLsaOpenPolicy.Call(
		0, // SystemName = nil (local machine)
		uintptr(unsafe.Pointer(&objAttrs[0])),
		POLICY_VIEW_LOCAL_INFORMATION|POLICY_LOOKUP_NAMES,
		uintptr(unsafe.Pointer(&polHandle)),
	)
	if ret != 0 || polHandle == 0 {
		writeUint32(mod, countPtr, 0)
		stack[0] = 0
		return
	}
	defer pLsaClose.Call(polHandle)

	var buf []byte
	count := uint32(0)

	for _, privName := range allPrivileges {
		// Build LSA_UNICODE_STRING for the privilege name.
		// Layout: Length(uint16) MaximumLength(uint16) [pad4] Buffer(*uint16)
		u16, err := syscall.UTF16FromString(privName)
		if err != nil {
			continue
		}
		// Length and MaximumLength are in bytes, NOT including the NUL terminator.
		charCount := len(u16) - 1 // exclude NUL
		type lsaUnicodeString struct {
			Length        uint16
			MaximumLength uint16
			_             [4]byte // padding to align Buffer on 8-byte boundary
			Buffer        uintptr
		}
		lsaStr := lsaUnicodeString{
			Length:        uint16(charCount * 2),
			MaximumLength: uint16(charCount * 2),
			Buffer:        uintptr(unsafe.Pointer(&u16[0])),
		}

		var enumBuf uintptr
		var enumCount uint32
		r1, _, _ := pLsaEnum.Call(
			polHandle,
			uintptr(unsafe.Pointer(&lsaStr)),
			uintptr(unsafe.Pointer(&enumBuf)),
			uintptr(unsafe.Pointer(&enumCount)),
		)

		// STATUS_NO_MORE_ENTRIES (0xC000001A) or STATUS_OBJECT_NAME_NOT_FOUND
		// (0xC0000034) mean no accounts — skip silently.
		if r1 != 0 || enumBuf == 0 || enumCount == 0 {
			if enumBuf != 0 {
				pLsaFree.Call(enumBuf)
			}
			continue
		}

		// Collect SID strings.
		var sids []string
		const infoSize = 8 // sizeof(LSA_ENUMERATION_INFORMATION) on x64
		for i := uint32(0); i < enumCount; i++ {
			entry := (*lsaEnumInfo)(unsafe.Pointer(enumBuf + uintptr(i)*infoSize))
			if entry.Sid == 0 {
				continue
			}
			sidStr := sidToString(entry.Sid, pConvertSid)
			if sidStr != "" {
				sids = append(sids, sidStr)
			}
		}
		pLsaFree.Call(enumBuf)

		if len(sids) == 0 {
			continue
		}

		record := privName + "|" + strings.Join(sids, ",")
		if len(record) > 4096 {
			record = record[:4096]
		}
		entry := []byte(record)
		if uint32(len(buf)+len(entry)+1) > bufCap {
			break
		}
		buf = append(buf, entry...)
		buf = append(buf, 0)
		count++
	}

	if len(buf) > 0 {
		writeBytes(mod, bufPtr, buf)
	}
	writeUint32(mod, countPtr, count)
	stack[0] = uint64(len(buf))
}

// sidToString converts a raw SID pointer to its string form (e.g., "S-1-5-32-544").
// Returns empty string on any error.
func sidToString(sidPtr uintptr, pConvertSid *syscall.Proc) string {
	if sidPtr == 0 || pConvertSid == nil {
		return ""
	}
	var strPtr *uint16
	r1, _, _ := pConvertSid.Call(
		sidPtr,
		uintptr(unsafe.Pointer(&strPtr)),
	)
	if r1 == 0 || strPtr == nil {
		return ""
	}
	// Build string from UTF-16 pointer.
	n := 0
	for {
		c := *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(strPtr)) + uintptr(n)*2))
		if c == 0 {
			break
		}
		n++
		if n > 256 {
			break
		}
	}
	u16 := unsafe.Slice(strPtr, n)
	result := string(utf16Decode(u16))
	// Free the string allocated by ConvertSidToStringSidW via LocalFree.
	kernel32, err := syscall.LoadDLL("kernel32.dll")
	if err == nil {
		if pLocalFree, err2 := kernel32.FindProc("LocalFree"); err2 == nil {
			pLocalFree.Call(uintptr(unsafe.Pointer(strPtr)))
		}
		kernel32.Release()
	}
	return result
}
