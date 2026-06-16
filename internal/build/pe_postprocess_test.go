package build

import (
	"encoding/binary"
	"os"
	"testing"
)

// buildMinimalPE constructs a minimal valid PE32+ binary with one section
// (.text) and a single import (kernel32.dll → ExitProcess).
func buildMinimalPE() []byte {
	// Layout:
	// 0x000 DOS header (64 bytes, e_lfanew = 0x80)
	// 0x080 PE signature (4 bytes)
	// 0x084 COFF header (20 bytes)
	// 0x098 Optional header PE32+ (240 bytes)
	// 0x188 Section headers (2 * 40 = 80 bytes)
	// 0x1D8 ... padding to 0x200 (file alignment)
	// 0x200 .text section (512 bytes, at RVA 0x1000)
	// 0x400 .idata section (512 bytes, at RVA 0x2000) - imports

	fileAlign := uint32(0x200)
	secAlign := uint32(0x1000)

	pe := make([]byte, 0x600) // 3 * 512

	// --- DOS header ---
	pe[0] = 'M'
	pe[1] = 'Z'
	binary.LittleEndian.PutUint32(pe[0x3C:], 0x80) // e_lfanew

	// --- PE signature ---
	copy(pe[0x80:], "PE\x00\x00")

	// --- COFF header ---
	coffOff := 0x84
	binary.LittleEndian.PutUint16(pe[coffOff:], 0x8664)   // Machine: AMD64
	binary.LittleEndian.PutUint16(pe[coffOff+2:], 2)       // NumberOfSections
	binary.LittleEndian.PutUint16(pe[coffOff+16:], 240)    // SizeOfOptionalHeader
	binary.LittleEndian.PutUint16(pe[coffOff+18:], 0x0022) // Characteristics

	// --- Optional header (PE32+) ---
	optOff := 0x98
	binary.LittleEndian.PutUint16(pe[optOff:], 0x020B)          // Magic: PE32+
	binary.LittleEndian.PutUint32(pe[optOff+16:], 0x1000)       // AddressOfEntryPoint
	binary.LittleEndian.PutUint64(pe[optOff+24:], 0x140000000)  // ImageBase
	binary.LittleEndian.PutUint32(pe[optOff+32:], secAlign)     // SectionAlignment
	binary.LittleEndian.PutUint32(pe[optOff+36:], fileAlign)    // FileAlignment
	binary.LittleEndian.PutUint32(pe[optOff+56:], 0x3000)       // SizeOfImage
	binary.LittleEndian.PutUint32(pe[optOff+60:], 0x200)        // SizeOfHeaders
	binary.LittleEndian.PutUint32(pe[optOff+64:], 0)            // CheckSum = 0
	binary.LittleEndian.PutUint16(pe[optOff+68:], 3)            // Subsystem: CONSOLE
	binary.LittleEndian.PutUint32(pe[optOff+108:], 16)          // NumberOfRvaAndSizes

	// Data directory [1] = Import Directory
	importDirRVA := uint32(0x2000) // start of .idata section
	binary.LittleEndian.PutUint32(pe[optOff+120:], importDirRVA) // Import Dir RVA
	binary.LittleEndian.PutUint32(pe[optOff+124:], 40)           // Import Dir Size (2 descriptors: 1 real + 1 null)

	// --- Section headers ---
	secTableOff := optOff + 240

	// .text section
	copy(pe[secTableOff:], ".text\x00\x00\x00")
	binary.LittleEndian.PutUint32(pe[secTableOff+8:], 0x100)   // VirtualSize
	binary.LittleEndian.PutUint32(pe[secTableOff+12:], 0x1000) // VirtualAddress
	binary.LittleEndian.PutUint32(pe[secTableOff+16:], 0x200)  // SizeOfRawData
	binary.LittleEndian.PutUint32(pe[secTableOff+20:], 0x200)  // PointerToRawData
	binary.LittleEndian.PutUint32(pe[secTableOff+36:], 0x60000020) // CODE|MEM_EXECUTE|MEM_READ

	// .idata section
	idataSec := secTableOff + 40
	copy(pe[idataSec:], ".idata\x00\x00")
	binary.LittleEndian.PutUint32(pe[idataSec+8:], 0x100)   // VirtualSize
	binary.LittleEndian.PutUint32(pe[idataSec+12:], 0x2000) // VirtualAddress
	binary.LittleEndian.PutUint32(pe[idataSec+16:], 0x200)  // SizeOfRawData
	binary.LittleEndian.PutUint32(pe[idataSec+20:], 0x400)  // PointerToRawData
	binary.LittleEndian.PutUint32(pe[idataSec+36:], 0xC0000040) // DATA|MEM_READ|MEM_WRITE

	// --- .idata content ---
	// Build a minimal import directory for kernel32.dll → ExitProcess.
	//
	// Layout within .idata (at file offset 0x400, RVA 0x2000):
	// 0x00: IMAGE_IMPORT_DESCRIPTOR for kernel32.dll (20 bytes)
	// 0x14: NULL IMAGE_IMPORT_DESCRIPTOR (20 bytes)
	// 0x28: ILT entry (8 bytes) -> hint/name at RVA 0x2038
	// 0x30: ILT null terminator (8 bytes)
	// 0x38: Hint/Name: 0x0000 "ExitProcess\0" (14 bytes)
	// 0x46: DLL name: "kernel32.dll\0" (13 bytes)

	idata := 0x400
	iltRVA := importDirRVA + 0x28
	hintRVA := importDirRVA + 0x38
	dllNameRVA := importDirRVA + 0x46

	// Import descriptor for kernel32.dll
	binary.LittleEndian.PutUint32(pe[idata:], iltRVA)       // OriginalFirstThunk
	binary.LittleEndian.PutUint32(pe[idata+12:], dllNameRVA) // Name
	binary.LittleEndian.PutUint32(pe[idata+16:], iltRVA)     // FirstThunk (same as ILT for simplicity)
	// Null descriptor at idata+20 is already zero.

	// ILT entry -> hint/name
	binary.LittleEndian.PutUint64(pe[idata+0x28:], uint64(hintRVA))
	// ILT null at idata+0x30 is already zero.

	// Hint/Name: hint=0, name="ExitProcess"
	binary.LittleEndian.PutUint16(pe[idata+0x38:], 0)
	copy(pe[idata+0x3A:], "ExitProcess\x00")

	// DLL name
	copy(pe[idata+0x46:], "kernel32.dll\x00")

	return pe
}

func TestFixPEChecksum(t *testing.T) {
	pe := buildMinimalPE()

	// Verify checksum starts at 0.
	csOff := checksumFileOffset(pe)
	cs := binary.LittleEndian.Uint32(pe[csOff:])
	if cs != 0 {
		t.Fatalf("initial checksum = 0x%08X, want 0", cs)
	}

	// Fix the checksum.
	pe, err := fixPEChecksum(pe)
	if err != nil {
		t.Fatalf("fixPEChecksum: %v", err)
	}

	// Verify checksum is now non-zero.
	cs = binary.LittleEndian.Uint32(pe[csOff:])
	if cs == 0 {
		t.Error("checksum still 0 after fixPEChecksum")
	}

	// Verify: re-calculating with zeroed checksum should produce same result.
	savedCS := cs
	binary.LittleEndian.PutUint32(pe[csOff:], 0)
	pe, _ = fixPEChecksum(pe)
	cs2 := binary.LittleEndian.Uint32(pe[csOff:])
	if cs2 != savedCS {
		t.Errorf("checksum not idempotent: first=0x%08X, second=0x%08X", savedCS, cs2)
	}
}

func TestEnrichPEImports(t *testing.T) {
	pe := buildMinimalPE()

	// Read original import count.
	optOff := 0x98
	origImportRVA := binary.LittleEndian.Uint32(pe[optOff+120:])
	if origImportRVA == 0 {
		t.Fatal("test PE has no import directory")
	}

	// Enrich imports.
	enriched, ok, err := enrichPEImports(pe)
	if err != nil {
		t.Fatalf("enrichPEImports: %v", err)
	}
	if !ok {
		t.Fatal("enrichPEImports returned ok=false")
	}

	// Verify file grew (new section added).
	if len(enriched) <= len(pe) {
		t.Errorf("file did not grow: before=%d, after=%d", len(pe), len(enriched))
	}

	// Verify NumberOfSections increased.
	coffOff := 0x84
	origSections := binary.LittleEndian.Uint16(pe[coffOff+2:])
	newSections := binary.LittleEndian.Uint16(enriched[coffOff+2:])
	if newSections != origSections+1 {
		t.Errorf("sections: got %d, want %d", newSections, origSections+1)
	}

	// Verify Import Directory RVA changed.
	newImportRVA := binary.LittleEndian.Uint32(enriched[optOff+120:])
	if newImportRVA == origImportRVA {
		t.Error("import directory RVA unchanged after enrichment")
	}

	// Verify Import Directory Size increased (more descriptors).
	newImportSize := binary.LittleEndian.Uint32(enriched[optOff+124:])
	// Expected: (1 existing + 3 new + 1 null) * 20 = 100 bytes
	expectedSize := uint32((1 + len(benignImports) + 1) * 20)
	if newImportSize != expectedSize {
		t.Errorf("import dir size = %d, want %d", newImportSize, expectedSize)
	}

	// Read back import descriptors from the new location to verify content.
	secTableOff := optOff + 240
	newNumSec := int(newSections)
	descs, err := readImportDescriptors(enriched, newImportRVA, secTableOff, newNumSec)
	if err != nil {
		t.Fatalf("reading enriched imports: %v", err)
	}
	// Should have 1 original + 3 new = 4 descriptors.
	if len(descs) != 1+len(benignImports) {
		t.Errorf("got %d import descriptors, want %d", len(descs), 1+len(benignImports))
	}

	// Verify the original kernel32.dll descriptor is preserved.
	if len(descs) > 0 {
		origILTRVA := uint32(0x2028) // original ILT RVA
		if descs[0].OriginalFirstThunk != origILTRVA {
			t.Errorf("first descriptor ILT RVA = 0x%X, want 0x%X", descs[0].OriginalFirstThunk, origILTRVA)
		}
	}
}

func TestEnrichPEImports_PreservesExistingImports(t *testing.T) {
	pe := buildMinimalPE()
	enriched, ok, err := enrichPEImports(pe)
	if err != nil || !ok {
		t.Fatalf("enrichPEImports failed: err=%v, ok=%v", err, ok)
	}

	// The original .idata section data should be untouched.
	// Verify the original kernel32.dll name is still at its original file offset.
	dllNameOff := 0x400 + 0x46 // file offset of "kernel32.dll\0"
	origName := string(pe[dllNameOff : dllNameOff+12])
	newName := string(enriched[dllNameOff : dllNameOff+12])
	if origName != newName {
		t.Errorf("original DLL name corrupted: %q vs %q", origName, newName)
	}
}

func TestPostProcessPE_Integration(t *testing.T) {
	pe := buildMinimalPE()

	// Verify initial state.
	csOff := checksumFileOffset(pe)
	if binary.LittleEndian.Uint32(pe[csOff:]) != 0 {
		t.Fatal("initial checksum should be 0")
	}

	// Write to temp file.
	tmpFile := t.TempDir() + "/test.exe"
	if err := os.WriteFile(tmpFile, pe, 0o755); err != nil {
		t.Fatal(err)
	}

	// Run full post-processing.
	if err := postProcessPE(tmpFile, false); err != nil {
		t.Fatalf("postProcessPE: %v", err)
	}

	// Read back and verify.
	result, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatal(err)
	}

	// Checksum should be non-zero.
	cs := binary.LittleEndian.Uint32(result[csOff:])
	if cs == 0 {
		t.Error("checksum still 0 after postProcessPE")
	}

	// Should have more sections.
	coffOff := 0x84
	numSec := binary.LittleEndian.Uint16(result[coffOff+2:])
	if numSec != 3 { // original 2 + 1 new
		t.Errorf("sections = %d, want 3", numSec)
	}
}



