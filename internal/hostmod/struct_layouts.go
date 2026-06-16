//go:build windows

package hostmod

import (
	"encoding/binary"

	"github.com/tetratelabs/wazero/api"
)

// structField describes a single field within a Win32 struct, capturing the
// difference between x64 and wasm32 layouts. Only structs with embedded
// pointers have different layouts; pure-scalar structs have identical x64
// and wasm32 representations and don't need entries here.
type structField struct {
	x64Offset  uint32 // Field offset in x64 layout.
	x64Size    uint32 // Field size on x64 (8 for pointers, 4/8 for scalars).
	wasm32Size uint32 // Field size on wasm32 (4 for pointers, same for scalars).
	isPointer  bool   // If true, compact 8-byte x64 slot to 4-byte wasm32.
}

// structLayout describes the x64 and wasm32 sizes for a Win32 struct,
// plus the field-by-field mapping needed for compaction.
type structLayout struct {
	name       string        // Struct name (for debug logging).
	x64Size    uint32        // Total size on x64 (with padding).
	wasm32Size uint32        // Total size on wasm32.
	fields     []structField // Field descriptors for compaction.
}

// knownStructLayouts maps Win32 struct names to their layout descriptors.
// Only add entries here as testing reveals layout issues — do NOT auto-generate
// the entire Win32 struct corpus (YAGNI).
var knownStructLayouts = map[string]structLayout{
	// SID_AND_ATTRIBUTES — used in TOKEN_GROUPS.Groups[] and TOKEN_PRIVILEGES.
	// x64: PSID (8 bytes) + DWORD Attributes (4 bytes) + 4 padding = 16
	// wasm32: PSID (4 bytes) + DWORD Attributes (4 bytes) = 8
	"SID_AND_ATTRIBUTES": {
		name: "SID_AND_ATTRIBUTES", x64Size: 16, wasm32Size: 8,
		fields: []structField{
			{x64Offset: 0, x64Size: 8, wasm32Size: 4, isPointer: true},  // PSID
			{x64Offset: 8, x64Size: 4, wasm32Size: 4, isPointer: false}, // Attributes
		},
	},

	// TOKEN_OWNER — single PSID field, written by GetTokenInformation(TokenOwner).
	// x64: PSID (8 bytes) = 8
	// wasm32: PSID (4 bytes) = 4
	"TOKEN_OWNER": {
		name: "TOKEN_OWNER", x64Size: 8, wasm32Size: 4,
		fields: []structField{
			{x64Offset: 0, x64Size: 8, wasm32Size: 4, isPointer: true}, // Owner (PSID)
		},
	},

	// TOKEN_PRIMARY_GROUP — single PSID field.
	// x64: PSID (8 bytes) = 8
	// wasm32: PSID (4 bytes) = 4
	"TOKEN_PRIMARY_GROUP": {
		name: "TOKEN_PRIMARY_GROUP", x64Size: 8, wasm32Size: 4,
		fields: []structField{
			{x64Offset: 0, x64Size: 8, wasm32Size: 4, isPointer: true}, // PrimaryGroup (PSID)
		},
	},

	// TOKEN_DEFAULT_DACL — single PACL field.
	// x64: PACL (8 bytes) = 8
	// wasm32: PACL (4 bytes) = 4
	"TOKEN_DEFAULT_DACL": {
		name: "TOKEN_DEFAULT_DACL", x64Size: 8, wasm32Size: 4,
		fields: []structField{
			{x64Offset: 0, x64Size: 8, wasm32Size: 4, isPointer: true}, // DefaultDacl (PACL)
		},
	},

	// LUID_AND_ATTRIBUTES — used in TOKEN_PRIVILEGES.Privileges[].
	// No pointers, same layout on both platforms.
	// x64: LUID (8 bytes) + DWORD Attributes (4 bytes) = 12
	// wasm32: LUID (8 bytes) + DWORD Attributes (4 bytes) = 12
	"LUID_AND_ATTRIBUTES": {
		name: "LUID_AND_ATTRIBUTES", x64Size: 12, wasm32Size: 12,
		fields: []structField{
			{x64Offset: 0, x64Size: 8, wasm32Size: 8, isPointer: false}, // LUID
			{x64Offset: 8, x64Size: 4, wasm32Size: 4, isPointer: false}, // Attributes
		},
	},
}

// compactStruct rewrites a single struct instance in WASM memory from x64
// layout to wasm32 layout. This is done in-place: x64 data is read from
// the current WASM bytes, then wasm32 data is written starting at the same
// address. Since wasm32Size <= x64Size, the write never exceeds the read
// footprint.
//
// For pointer fields, the lower 32 bits of the x64 8-byte slot are kept
// (these are WASM mirror addresses from compactPointerWidth or direct
// WASM buffer offsets, both < 4GB).
func compactStruct(mem api.Memory, wasmAddr uint32, layout structLayout) {
	// Read the full x64 region.
	x64Data, ok := mem.Read(wasmAddr, layout.x64Size)
	if !ok {
		return
	}
	// Make a copy to avoid aliasing issues during in-place rewrite.
	src := make([]byte, len(x64Data))
	copy(src, x64Data)

	wasm32Offset := uint32(0)
	for _, f := range layout.fields {
		if f.x64Offset+f.x64Size > uint32(len(src)) {
			break // Truncated data, stop.
		}
		fieldData := src[f.x64Offset : f.x64Offset+f.x64Size]

		if f.isPointer {
			// Truncate 8-byte pointer to lower 4 bytes (WASM address).
			mem.Write(wasmAddr+wasm32Offset, fieldData[:4])
		} else {
			mem.Write(wasmAddr+wasm32Offset, fieldData[:f.wasm32Size])
		}
		wasm32Offset += f.wasm32Size
	}

	// Zero out the remaining bytes (x64Size - wasm32Size) to prevent
	// stale data from being read.
	if layout.wasm32Size < layout.x64Size {
		zeros := make([]byte, layout.x64Size-layout.wasm32Size)
		mem.Write(wasmAddr+layout.wasm32Size, zeros)
	}

	mirrorDebugLog("compactStruct: %s at 0x%x (x64=%d -> wasm32=%d)",
		layout.name, wasmAddr, layout.x64Size, layout.wasm32Size)
}

// compactStructArray rewrites an array of structs from x64 layout to wasm32.
// The source uses x64 stride for reading; the destination uses wasm32 stride
// for writing. Works in-place since wasm32 stride <= x64 stride.
func compactStructArray(mem api.Memory, wasmAddr uint32, layout structLayout, count int) {
	if count <= 0 || layout.x64Size == layout.wasm32Size {
		return // No compaction needed.
	}

	for i := 0; i < count; i++ {
		srcOffset := wasmAddr + uint32(i)*layout.x64Size
		dstOffset := wasmAddr + uint32(i)*layout.wasm32Size

		// Read from x64 position.
		x64Data, ok := mem.Read(srcOffset, layout.x64Size)
		if !ok {
			break
		}
		src := make([]byte, len(x64Data))
		copy(src, x64Data)

		// Write compacted fields at wasm32 position.
		wasm32Off := uint32(0)
		for _, f := range layout.fields {
			if f.x64Offset+f.x64Size > uint32(len(src)) {
				break
			}
			fieldData := src[f.x64Offset : f.x64Offset+f.x64Size]
			if f.isPointer {
				mem.Write(dstOffset+wasm32Off, fieldData[:4])
			} else {
				mem.Write(dstOffset+wasm32Off, fieldData[:f.wasm32Size])
			}
			wasm32Off += f.wasm32Size
		}
	}

	// Zero trailing bytes after the compacted array.
	compactedEnd := wasmAddr + uint32(count)*layout.wasm32Size
	originalEnd := wasmAddr + uint32(count)*layout.x64Size
	if compactedEnd < originalEnd {
		zeros := make([]byte, originalEnd-compactedEnd)
		mem.Write(compactedEnd, zeros)
	}

	mirrorDebugLog("compactStructArray: %s at 0x%x count=%d (x64_stride=%d -> wasm32_stride=%d)",
		layout.name, wasmAddr, count, layout.x64Size, layout.wasm32Size)
}

// Token information class constants (from x/sys/windows).
const (
	tokenUser             = 1
	tokenGroups           = 2
	tokenPrivileges       = 3
	tokenOwner            = 4
	tokenPrimaryGroup     = 5
	tokenDefaultDacl      = 6
)

// compactTokenInfoInPlace rewrites a GetTokenInformation output buffer in WASM
// memory from x64 layout to wasm32 layout. This handles both pointer value
// fixup (host address → WASM address) and struct layout compaction (8-byte
// pointer slots → 4-byte).
//
// wasmBufAddr is the WASM address of the output buffer.
// infoClass is the TOKEN_INFORMATION_CLASS value.
// dataLen is the number of bytes written by the native API.
// wasmMemBase is the host base address of WASM linear memory (for pointer fixup).
//
// Called from win32SyscallN Step 6.5 for GetTokenInformation calls.
func compactTokenInfoInPlace(mem api.Memory, wasmBufAddr uint32, infoClass uint32, dataLen uint32, wasmMemBase uintptr) {
	switch infoClass {
	case tokenOwner:
		compactSinglePointerStruct(mem, wasmBufAddr, dataLen, wasmMemBase, "TOKEN_OWNER")

	case tokenPrimaryGroup:
		compactSinglePointerStruct(mem, wasmBufAddr, dataLen, wasmMemBase, "TOKEN_PRIMARY_GROUP")

	case tokenDefaultDacl:
		compactSinglePointerStruct(mem, wasmBufAddr, dataLen, wasmMemBase, "TOKEN_DEFAULT_DACL")

	case tokenUser:
		// TOKEN_USER = { SID_AND_ATTRIBUTES User }
		// Single SID_AND_ATTRIBUTES (not an array).
		if dataLen < 16 { // x64 SID_AND_ATTRIBUTES = 16 bytes
			return
		}
		compactSidAndAttributes(mem, wasmBufAddr, 1, wasmMemBase)

	case tokenGroups:
		// TOKEN_GROUPS = { DWORD GroupCount; SID_AND_ATTRIBUTES Groups[ANYSIZE_ARRAY] }
		// On x64: GroupCount at offset 0 (4 bytes), 4 bytes padding, Groups at offset 8.
		// On wasm32: GroupCount at offset 0 (4 bytes), Groups at offset 4 (no padding).
		if dataLen < 8 {
			return
		}
		countBytes, ok := mem.Read(wasmBufAddr, 4)
		if !ok {
			return
		}
		groupCount := int(binary.LittleEndian.Uint32(countBytes))
		if groupCount <= 0 || groupCount > 1000 {
			return // Sanity check.
		}

		// x64 layout: Groups array starts at offset 8 (after 4-byte count + 4-byte padding).
		// wasm32 layout: Groups array starts at offset 4 (after 4-byte count, no padding).
		x64ArrayStart := wasmBufAddr + 8
		wasm32ArrayStart := wasmBufAddr + 4

		// Compact the array elements in-place (x64 stride → wasm32 stride).
		compactSidAndAttributes(mem, x64ArrayStart, groupCount, wasmMemBase)

		// Move the compacted array from x64ArrayStart to wasm32ArrayStart.
		// The compacted array size is groupCount * 8 bytes.
		compactedSize := uint32(groupCount) * 8
		compactedData, ok := mem.Read(x64ArrayStart, compactedSize)
		if !ok {
			return
		}
		buf := make([]byte, len(compactedData))
		copy(buf, compactedData)
		mem.Write(wasm32ArrayStart, buf)

		// Zero the gap between end of wasm32 data and end of x64 data.
		wasm32End := wasm32ArrayStart + compactedSize
		x64End := x64ArrayStart + uint32(groupCount)*16
		if wasm32End < x64End {
			zeros := make([]byte, x64End-wasm32End)
			mem.Write(wasm32End, zeros)
		}

		mirrorDebugLog("compactTokenInfo: TOKEN_GROUPS count=%d at 0x%x", groupCount, wasmBufAddr)

	case tokenPrivileges:
		// TOKEN_PRIVILEGES contains LUID_AND_ATTRIBUTES — no pointers,
		// same layout on x64 and wasm32. No compaction needed.
		return

	default:
		// Unknown info class — leave as-is.
		return
	}
}

// compactSinglePointerStruct handles TOKEN_OWNER, TOKEN_PRIMARY_GROUP, and
// TOKEN_DEFAULT_DACL — structs with a single pointer field.
// x64: 8-byte pointer. wasm32: 4-byte pointer.
func compactSinglePointerStruct(mem api.Memory, wasmAddr uint32, dataLen uint32, wasmMemBase uintptr, name string) {
	if dataLen < 8 {
		return
	}
	ptrBytes, ok := mem.Read(wasmAddr, 8)
	if !ok {
		return
	}
	hostPtr := binary.LittleEndian.Uint64(ptrBytes)

	// Convert host address to WASM address.
	wasmPtr := fixPointerToWasm(hostPtr, wasmMemBase)

	// Write as 4-byte WASM pointer.
	var out [4]byte
	binary.LittleEndian.PutUint32(out[:], wasmPtr)
	mem.Write(wasmAddr, out[:])

	// Zero remaining bytes (8 - 4 = 4).
	mem.Write(wasmAddr+4, make([]byte, 4))

	mirrorDebugLog("compactTokenInfo: %s at 0x%x hostPtr=0x%x -> wasmPtr=0x%x",
		name, wasmAddr, hostPtr, wasmPtr)
}

// compactSidAndAttributes compacts an array of SID_AND_ATTRIBUTES structs
// from x64 layout (16 bytes each) to wasm32 layout (8 bytes each).
// The array starts at wasmAddr and has count elements.
func compactSidAndAttributes(mem api.Memory, wasmAddr uint32, count int, wasmMemBase uintptr) {
	layout := knownStructLayouts["SID_AND_ATTRIBUTES"]

	for i := 0; i < count; i++ {
		srcOff := wasmAddr + uint32(i)*layout.x64Size
		dstOff := wasmAddr + uint32(i)*layout.wasm32Size

		x64Data, ok := mem.Read(srcOff, layout.x64Size)
		if !ok {
			break
		}
		src := make([]byte, len(x64Data))
		copy(src, x64Data)

		// Field 0: PSID (8 bytes → 4 bytes, pointer fixup).
		hostPtr := binary.LittleEndian.Uint64(src[0:8])
		wasmPtr := fixPointerToWasm(hostPtr, wasmMemBase)
		var ptrBuf [4]byte
		binary.LittleEndian.PutUint32(ptrBuf[:], wasmPtr)
		mem.Write(dstOff, ptrBuf[:])

		// Field 1: Attributes (4 bytes, no change).
		mem.Write(dstOff+4, src[8:12])
	}

	// Zero trailing x64 space.
	compactedEnd := wasmAddr + uint32(count)*layout.wasm32Size
	originalEnd := wasmAddr + uint32(count)*layout.x64Size
	if compactedEnd < originalEnd {
		zeros := make([]byte, originalEnd-compactedEnd)
		mem.Write(compactedEnd, zeros)
	}
}

// fixPointerToWasm converts a host address to a WASM address. If the host
// address falls within WASM linear memory (wasmMemBase..wasmMemBase+4GB),
// it's converted by subtracting wasmMemBase. If it's a mirror address or
// already a small value, it's returned as-is (lower 32 bits).
func fixPointerToWasm(hostAddr uint64, wasmMemBase uintptr) uint32 {
	if hostAddr == 0 {
		return 0
	}
	base := uint64(wasmMemBase)
	// Self-referential pointer within WASM buffer?
	if base > 0 && hostAddr >= base && hostAddr < base+0x100000000 {
		return uint32(hostAddr - base)
	}
	// Already a small value (WASM address or mirror address).
	return uint32(hostAddr)
}

// fixNtQuerySystemInfoPointers walks the SYSTEM_PROCESS_INFORMATION linked
// list in the output buffer and converts ImageName.Buffer from host addresses
// (wasmMemBase + offset) to WASM addresses (just the offset).
//
// SYSTEM_PROCESS_INFORMATION layout (x64):
//
//	NextEntryOffset  uint32  @ 0
//	...
//	ImageName        UNICODE_STRING @ 56
//	  Length          uint16  @ 56
//	  MaximumLength   uint16  @ 58
//	  padding         [4]byte @ 60
//	  Buffer          *uint16 @ 64 (8 bytes — host pointer)
func fixNtQuerySystemInfoPointers(mem api.Memory, wasmBufAddr uint32, dataLen uint32, wasmMemBase uintptr) {
	offset := uint32(0)
	for offset < dataLen {
		// Read NextEntryOffset (4 bytes at current offset).
		neoBytes, ok := mem.Read(wasmBufAddr+offset, 4)
		if !ok {
			break
		}
		nextEntryOffset := binary.LittleEndian.Uint32(neoBytes)

		// ImageName.Buffer is at offset+64 in SYSTEM_PROCESS_INFORMATION (x64).
		bufPtrAddr := wasmBufAddr + offset + 64
		if bufPtrAddr+8 > wasmBufAddr+dataLen {
			break
		}
		ptrBytes, ok := mem.Read(bufPtrAddr, 8)
		if !ok {
			break
		}
		hostPtr := binary.LittleEndian.Uint64(ptrBytes)
		if hostPtr != 0 {
			wasmPtr := fixPointerToWasm(hostPtr, wasmMemBase)
			var out [8]byte
			binary.LittleEndian.PutUint64(out[:], uint64(wasmPtr))
			mem.Write(bufPtrAddr, out[:])
			mirrorDebugLog("fixNtQuerySystemInfo: entry@0x%x ImageName.Buffer host=0x%x -> wasm=0x%x",
				wasmBufAddr+offset, hostPtr, wasmPtr)
		}

		if nextEntryOffset == 0 {
			break // Last entry.
		}
		offset += nextEntryOffset
	}
}

// compactTokenInfoBytes rewrites a GetTokenInformation output buffer from x64
// layout to wasm32 layout in a byte slice (for the host function path where
// data is in a temp buffer before writeBytes). Returns the compacted slice.
//
// hostBufBase is the host address of buf[0] (for pointer fixup).
// wasmBufAddr is the WASM address where the data will be written.
func compactTokenInfoBytes(buf []byte, infoClass uint32, hostBufBase uintptr, wasmBufAddr uint32) []byte {
	switch infoClass {
	case tokenOwner, tokenPrimaryGroup, tokenDefaultDacl:
		if len(buf) < 8 {
			return buf
		}
		hostPtr := binary.LittleEndian.Uint64(buf[0:8])
		// Convert: host temp buffer addr → WASM buffer offset.
		var wasmPtr uint32
		if hostPtr >= uint64(hostBufBase) {
			offset := uint32(hostPtr - uint64(hostBufBase))
			wasmPtr = wasmBufAddr + offset
		}
		out := make([]byte, len(buf))
		copy(out, buf)
		binary.LittleEndian.PutUint32(out[0:4], wasmPtr)
		// Shift remaining data left by 4 bytes.
		copy(out[4:], buf[8:])
		return out

	case tokenUser:
		if len(buf) < 16 {
			return buf
		}
		out := make([]byte, len(buf))
		copy(out, buf)
		// SID_AND_ATTRIBUTES: PSID (8) + Attributes (4) + pad (4) = 16 on x64.
		hostPtr := binary.LittleEndian.Uint64(buf[0:8])
		var wasmPtr uint32
		if hostPtr >= uint64(hostBufBase) {
			offset := uint32(hostPtr - uint64(hostBufBase))
			wasmPtr = wasmBufAddr + offset
		}
		binary.LittleEndian.PutUint32(out[0:4], wasmPtr)
		copy(out[4:8], buf[8:12]) // Attributes
		// Shift SID data left.
		copy(out[8:], buf[16:])
		return out

	case tokenGroups:
		if len(buf) < 8 {
			return buf
		}
		out := make([]byte, len(buf))
		copy(out, buf)
		groupCount := int(binary.LittleEndian.Uint32(buf[0:4]))
		if groupCount <= 0 || groupCount > 1000 {
			return buf
		}
		// GroupCount stays at offset 0 (4 bytes).
		// x64: Groups at offset 8 (4 bytes padding). wasm32: Groups at offset 4.
		wOff := 4 // wasm32 write offset
		for i := 0; i < groupCount; i++ {
			rOff := 8 + i*16 // x64 read offset
			if rOff+16 > len(buf) {
				break
			}
			hostPtr := binary.LittleEndian.Uint64(buf[rOff : rOff+8])
			var wasmPtr uint32
			if hostPtr >= uint64(hostBufBase) {
				offset := uint32(hostPtr - uint64(hostBufBase))
				wasmPtr = wasmBufAddr + offset
			}
			binary.LittleEndian.PutUint32(out[wOff:wOff+4], wasmPtr)
			copy(out[wOff+4:wOff+8], buf[rOff+8:rOff+12]) // Attributes
			wOff += 8
		}
		// Zero rest.
		for i := wOff; i < len(out); i++ {
			out[i] = 0
		}
		return out

	default:
		return buf
	}
}
