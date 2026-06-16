package hostmod

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"github.com/tetratelabs/wazero/api"
)

// mirrorDebugLog writes diagnostic messages to a platform-specific debug log.
// Only used for mirror operations (rare — COM setup only), not every SyscallN.
var mirrorDebugOnce sync.Once
var mirrorDebugFile *os.File

func mirrorDebugLog(format string, args ...interface{}) {
	mirrorDebugOnce.Do(func() {
		path := filepath.Join(os.TempDir(), "debug.log")
		var err error
		mirrorDebugFile, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			mirrorDebugFile = nil
		}
	})
	if mirrorDebugFile != nil {
		fmt.Fprintf(mirrorDebugFile, format+"\n", args...)
		mirrorDebugFile.Sync()
	}
}

// mirrorDiagMode gates additional diagnostics output to stderr.
// Set WFRT_DIAG=mirror to enable detailed mirror population diagnostics
// (raw host bytes, UTF-16 detection, VirtualQuery results).
var mirrorDiagMode = os.Getenv("WFRT_DIAG")

func mirrorDiag(format string, args ...interface{}) {
	if mirrorDiagMode == "" {
		return
	}
	fmt.Fprintf(os.Stderr, "[MDIAG] "+format+"\n", args...)
}

// mirrorEntry tracks a single host pointer that has been mirrored into WASM
// linear memory. The guest can read from the mirror address, and when it
// passes the mirror address back to SyscallN, it is reverse-translated to
// the original host address.
type mirrorEntry struct {
	wasmAddr uint32  // WASM mirror address (within the mirror arena).
	hostAddr uintptr // Original host address.
	size     uint32  // Bytes mirrored (x64 layout, 8-byte pointer slots).
	writable bool    // If true, WASM data is synced back to host before native calls.
}

// pendingMirror tracks a host pointer that has been assigned a WASM address
// but not yet copied into linear memory. The copy is deferred until the guest
// actually accesses the address, triggering the memory fault handler.
type pendingMirror struct {
	hostAddr uintptr
	size     uint32
}

// mirrorTable maintains the set of active host→WASM mirrors with a bump
// allocator for WASM mirror space. Thread-safe.
type mirrorTable struct {
	mu             sync.RWMutex
	byWasm         map[uint32]*mirrorEntry    // WASM addr → entry
	byHost         map[uintptr]*mirrorEntry   // Host addr → entry (dedup)
	pending        map[uint32]*pendingMirror   // WASM addr → pending (lazy)
	pendingByHost  map[uintptr]uint32          // Host addr → WASM addr (dedup)
	truncatedProcs map[uint32]uintptr          // low32(hostAddr) → full hostAddr (proc recovery)
	arena          uint32                      // Start of mirror region in WASM memory.
	offset         uint32                      // Next free offset from arena.
}

// maxMirrorDepth limits recursion in ScanAndMirrorPointers.
// COM vtable chains are typically 2-3 levels deep; 8 provides ample headroom.
const maxMirrorDepth = 8

// newMirrorTable creates a new empty mirror table.
func newMirrorTable() *mirrorTable {
	return &mirrorTable{
		byWasm:         make(map[uint32]*mirrorEntry),
		byHost:         make(map[uintptr]*mirrorEntry),
		pending:        make(map[uint32]*pendingMirror),
		pendingByHost:  make(map[uintptr]uint32),
		truncatedProcs: make(map[uint32]uintptr),
	}
}

// initArena sets the starting WASM address for the mirror arena.
// Called once when the first mirror is created, using Memory.Grow.
func (mt *mirrorTable) initArena(base uint32) {
	mt.arena = base
	mt.offset = 0
}

// allocate bumps the arena offset and returns the WASM address for a new mirror.
func (mt *mirrorTable) allocate(size uint32) uint32 {
	// Align to 8 bytes for safe pointer access.
	aligned := (size + 7) &^ 7
	addr := mt.arena + mt.offset
	mt.offset += aligned
	return addr
}

// Mirror copies data from a host address into WASM linear memory and
// tracks the mapping. Returns the WASM mirror address, or 0 on failure.
// If the host address was already mirrored, returns the existing mirror.
func (mt *mirrorTable) Mirror(mod api.Module, hostAddr uintptr, size uint32) uint32 {
	mt.mu.Lock()
	defer mt.mu.Unlock()

	// Dedup: check if this host address is already mirrored.
	if existing, ok := mt.byHost[hostAddr]; ok {
		return existing.wasmAddr
	}

	// Ensure arena is initialized. Grow WASM memory to make room.
	// We grow by a large amount (headroom + arena) because the guest's
	// Go runtime heap can expand into pages adjacent to the current
	// memory top. By adding headroom, the arena sits well above the
	// region the guest heap is likely to reach.
	if mt.arena == 0 {
		mem := mod.Memory()
		if mem == nil {
			return 0
		}
		headroomPages := uint32(1024) // 64MB headroom for guest heap growth
		arenaPages := uint32(64)      // 4MB mirror arena
		prevPages, ok := mem.Grow(headroomPages + arenaPages)
		if !ok {
			// Fallback: try smaller headroom if memory is constrained.
			headroomPages = 128 // 8MB headroom
			prevPages, ok = mem.Grow(headroomPages + arenaPages)
			if !ok {
				return 0
			}
		}
		mt.initArena((prevPages + headroomPages) * 65536)
	}

	wasmAddr := mt.allocate(size)

	// Ensure allocated address is within current memory. The arena may
	// extend past the current linear memory if many mirrors were allocated
	// since the last grow. Grow on demand.
	mem := mod.Memory()
	needed := uint64(wasmAddr) + uint64(size)
	if currentSize := uint64(mem.Size()); needed > currentSize {
		pagesNeeded := uint32((needed - currentSize + 65535) / 65536)
		if _, ok := mem.Grow(pagesNeeded); !ok {
			mirrorDebugLog("Mirror: grow failed for wasm=0x%x size=%d (need %d pages)", wasmAddr, size, pagesNeeded)
			return 0
		}
	}

	// Copy host data into WASM memory.
	hostData := mirrorReadHost(hostAddr, size)
	if hostData == nil {
		mirrorDebugLog("Mirror: mirrorReadHost FAILED host=0x%x size=%d", hostAddr, size)
		return 0
	}
	if uint32(len(hostData)) < size {
		mirrorDebugLog("Mirror: CLAMPED host=0x%x requested=%d actual=%d wasm=0x%x", hostAddr, size, len(hostData), wasmAddr)
	}
	mirrorDebugLog("Mirror: host=0x%x size=%d actual=%d wasm=0x%x", hostAddr, size, len(hostData), wasmAddr)
	if !writeBytes(mod, wasmAddr, hostData) {
		mirrorDebugLog("Mirror: writeBytes FAILED wasm=0x%x size=%d", wasmAddr, size)
		return 0
	}

	entry := &mirrorEntry{
		wasmAddr: wasmAddr,
		hostAddr: hostAddr,
		size:     size,
	}
	mt.byWasm[wasmAddr] = entry
	mt.byHost[hostAddr] = entry

	return wasmAddr
}

// MirrorWritable creates a writable mirror — the same as Mirror, but the
// entry is marked writable so that SyncWritableMirrors copies WASM data
// back to the host before native calls. Used for SafeArray pvData buffers
// where the guest writes data that the host must read (e.g., .NET assembly
// bytes loaded via AppDomain.Load_3).
//
// Unlike Mirror, this function reads host memory using unsafe.Slice instead
// of mirrorReadHost. mirrorReadHost uses VirtualQuery to determine region
// boundaries and clamps the read to a single region. Large heap allocations
// (>512KB, e.g., Seatbelt.exe at 597KB) span multiple VirtualQuery regions,
// causing mirrorReadHost to return only the first region's data. The writable
// mirror entry would store the full requested size but only have partial data
// in WASM, and SyncWritableMirrors would overwrite the host buffer with
// mostly-zero WASM data, corrupting the assembly bytes.
//
// The host memory for writable mirrors is always known-valid because it was
// allocated by a Win32 API (SafeArrayCreateVector) — direct unsafe.Slice
// is safe here.
func (mt *mirrorTable) MirrorWritable(mod api.Module, hostAddr uintptr, size uint32) uint32 {
	mt.mu.Lock()
	defer mt.mu.Unlock()

	// Dedup: check if this host address is already mirrored.
	if existing, ok := mt.byHost[hostAddr]; ok {
		existing.writable = true
		return existing.wasmAddr
	}

	// Ensure arena is initialized (same headroom logic as Mirror).
	if mt.arena == 0 {
		mem := mod.Memory()
		if mem == nil {
			return 0
		}
		headroomPages := uint32(1024) // 64MB headroom for guest heap growth
		arenaPages := uint32(64)      // 4MB mirror arena
		prevPages, ok := mem.Grow(headroomPages + arenaPages)
		if !ok {
			headroomPages = 128
			prevPages, ok = mem.Grow(headroomPages + arenaPages)
			if !ok {
				return 0
			}
		}
		mt.initArena((prevPages + headroomPages) * 65536)
	}

	wasmAddr := mt.allocate(size)

	// Ensure allocated address is within current memory.
	mem := mod.Memory()
	needed := uint64(wasmAddr) + uint64(size)
	if currentSize := uint64(mem.Size()); needed > currentSize {
		pagesNeeded := uint32((needed - currentSize + 65535) / 65536)
		if _, ok := mem.Grow(pagesNeeded); !ok {
			mirrorDebugLog("MirrorWritable: grow failed for wasm=0x%x size=%d", wasmAddr, size)
			return 0
		}
	}

	// Read host data directly via unsafe.Slice — bypass VirtualQuery clamping.
	// This is safe because the host memory was allocated by SafeArrayCreateVector.
	src := unsafe.Slice((*byte)(unsafe.Pointer(hostAddr)), size)
	hostData := make([]byte, size)
	copy(hostData, src)

	if !writeBytes(mod, wasmAddr, hostData) {
		return 0
	}

	entry := &mirrorEntry{
		wasmAddr: wasmAddr,
		hostAddr: hostAddr,
		size:     size,
		writable: true,
	}
	mt.byWasm[wasmAddr] = entry
	mt.byHost[hostAddr] = entry

	mirrorDebugLog("MirrorWritable: host=0x%x -> wasm=0x%x size=%d", hostAddr, wasmAddr, size)
	return wasmAddr
}

// SyncWritableMirrors copies all writable mirror data from WASM back to the
// host. Called before native SyscallN calls to ensure guest-written data
// (e.g., .NET assembly bytes in SafeArray pvData) is visible to the host.
//
// This is safe for data-only mirrors (no embedded pointer replacements).
// Do NOT mark COM struct mirrors as writable — ScanAndMirrorPointers
// replaces host pointers with WASM mirror addresses in those, and syncing
// them back would corrupt the host COM objects.
func (mt *mirrorTable) SyncWritableMirrors(mod api.Module) {
	mt.mu.RLock()
	var writable []*mirrorEntry
	for _, e := range mt.byWasm {
		if e.writable {
			writable = append(writable, e)
		}
	}
	mt.mu.RUnlock()

	for _, e := range writable {
		data, ok := readBytes(mod, e.wasmAddr, e.size)
		if !ok {
			continue
		}
		// Reverse-translate embedded WASM mirror addresses to host addresses.
		// Guest code (e.g., building VARIANT structs for Invoke_3) may write
		// WASM mirror addresses into writable mirror data. The host CLR expects
		// host pointers, not WASM addresses. Scan all 8-byte-aligned values
		// and replace known mirror addresses with their host counterparts.
		mt.mu.RLock()
		for off := 0; off+8 <= len(data); off += 8 {
			val := uint32(le64(data[off : off+8]))
			if val == 0 {
				continue
			}
			if me, ok := mt.byWasm[val]; ok {
				putLE64(data[off:off+8], uint64(me.hostAddr))
				mirrorDebugLog("SyncWritable: reverse-translate wasm=0x%x -> host=0x%x at offset %d in mirror 0x%x",
					val, me.hostAddr, off, e.wasmAddr)
			}
		}
		mt.mu.RUnlock()
		mirrorWriteHost(e.hostAddr, data)
		first := data[:min(len(data), 16)]
		mirrorDebugLog("SyncWritable: wasm=0x%x -> host=0x%x size=%d first16=%x", e.wasmAddr, e.hostAddr, e.size, first)
	}
}

// RefreshWritableMirrors copies host data back to WASM for all writable
// mirrors. Called after native SyscallN calls to capture modifications made
// by the host (e.g., RtlCopyMemory writing assembly bytes to host pvData
// via Step 0 mirror translation). This keeps the WASM mirror in sync with
// the host so that subsequent SyncWritableMirrors calls don't overwrite
// host data with stale WASM data.
//
// Uses direct unsafe.Slice instead of mirrorReadHost to avoid VirtualQuery
// region-boundary clamping. The host memory is known-valid because it was
// allocated by a Win32 API (SafeArrayCreateVector) and successfully written
// to. Large heap allocations (>512KB) may span multiple VirtualQuery regions,
// causing mirrorReadHost to return a truncated read.
func (mt *mirrorTable) RefreshWritableMirrors(mod api.Module) {
	mt.mu.RLock()
	var writable []*mirrorEntry
	for _, e := range mt.byWasm {
		if e.writable {
			writable = append(writable, e)
		}
	}
	mt.mu.RUnlock()

	for _, e := range writable {
		if e.hostAddr == 0 || e.size == 0 {
			continue
		}
		// Direct read — bypass VirtualQuery clamping for large buffers.
		src := unsafe.Slice((*byte)(unsafe.Pointer(e.hostAddr)), e.size)
		dst := make([]byte, e.size)
		copy(dst, src)
		writeBytes(mod, e.wasmAddr, dst)
		first := dst[:min(len(dst), 16)]
		mirrorDebugLog("RefreshWritable: host=0x%x -> wasm=0x%x size=%d first16=%x", e.hostAddr, e.wasmAddr, e.size, first)
	}
}

// LookupByWasm returns the mirror entry for a WASM address, searching
// for both exact matches and addresses within a mirrored range.
func (mt *mirrorTable) LookupByWasm(addr uint32) *mirrorEntry {
	mt.mu.RLock()
	defer mt.mu.RUnlock()

	// Exact match first.
	if e, ok := mt.byWasm[addr]; ok {
		return e
	}

	// Check if addr falls within any mirror entry's range.
	for _, e := range mt.byWasm {
		end := e.wasmAddr + e.size
		if addr >= e.wasmAddr && addr < end {
			return e
		}
	}
	return nil
}

// LookupPendingByWasm returns the pending mirror entry for a WASM address,
// searching for both exact matches and addresses within a pending range.
// Returns the host address and whether a match was found.
func (mt *mirrorTable) LookupPendingByWasm(addr uint32) (uintptr, bool) {
	mt.mu.RLock()
	defer mt.mu.RUnlock()

	// Exact match.
	if pm, ok := mt.pending[addr]; ok {
		return pm.hostAddr, true
	}

	// Check if addr falls within any pending entry's range.
	for wasmBase, pm := range mt.pending {
		end := wasmBase + pm.size
		if addr >= wasmBase && addr < end {
			offset := uintptr(addr - wasmBase)
			return pm.hostAddr + offset, true
		}
	}
	return 0, false
}

// LookupByHost returns the mirror entry for a host address, or nil.
func (mt *mirrorTable) LookupByHost(addr uintptr) *mirrorEntry {
	mt.mu.RLock()
	defer mt.mu.RUnlock()
	return mt.byHost[addr]
}

// StoreTruncatedProc records a full 64-bit host function address keyed by
// its low 32 bits. The wasmimport ABI truncates proc addresses to int32;
// this map allows the host to recover the original 48-bit address when the
// guest calls through an unmirrored COM vtable entry (CLR CCW thunks).
func (mt *mirrorTable) StoreTruncatedProc(low32 uint32, full uintptr) {
	// Log key=0 stores — these can pollute the truncation map and cause
	// proc resolution to return garbage for genuinely-zero vtable slots.
	if low32 == 0 {
		mirrorDebugLog("StoreTruncatedProc: KEY=0 full=0x%x (potential collision!)", full)
	}
	mt.mu.Lock()
	mt.truncatedProcs[low32] = full
	mt.mu.Unlock()
}

// LookupTruncatedProc recovers the full host address from its low 32 bits.
// Returns (0, false) if the low32 value was never seen during mirror scanning.
func (mt *mirrorTable) LookupTruncatedProc(low32 uint32) (uintptr, bool) {
	mt.mu.RLock()
	defer mt.mu.RUnlock()
	addr, ok := mt.truncatedProcs[low32]
	if ok && low32 == 0 {
		mirrorDebugLog("LookupTruncatedProc: KEY=0 returning 0x%x", addr)
	}
	return addr, ok
}

// SyncToHost copies the current WASM mirror data back to the original
// host address. Used before SyscallN calls to push guest modifications.
// The WASM data uses x64 layout (8-byte pointer slots) which matches the
// host layout, so the copy is a direct memcpy.
func (mt *mirrorTable) SyncToHost(mod api.Module, wasmAddr uint32) {
	mt.mu.RLock()
	e, ok := mt.byWasm[wasmAddr]
	mt.mu.RUnlock()
	if !ok {
		return
	}

	data, ok := readBytes(mod, e.wasmAddr, e.size)
	if !ok {
		return
	}
	mirrorWriteHost(e.hostAddr, data)
}

// ScanAndMirrorPointers scans a mirrored region for embedded host pointers
// and recursively mirrors them. This handles COM vtable chains and similar
// structures where one host pointer leads to another.
//
// The mirrored data keeps its native x64 layout (8-byte pointer slots)
// because Go's wasip1/wasm target uses 8-byte uintptr — struct field offsets
// match the x64 memory layout without any compaction.
//
// maxDepth limits recursion to prevent infinite loops.
// budget limits the total number of new mirrors across the entire recursion
// tree — COM chains need ~15-20 mirrors; more typically means false-positive
// address detection in DLL data sections.
func (mt *mirrorTable) ScanAndMirrorPointers(mod api.Module, wasmAddr uint32, data []byte, wasmMemSize uint32, depth int, budget *int, visited map[uintptr]bool) {
	if depth <= 0 || len(data) < 8 {
		return
	}
	startBudget := *budget
	mirrorDebugLog("scan: addr=0x%x depth=%d budget=%d bytes=%d", wasmAddr, depth, *budget, len(data))
	// Hex dump for COM object debugging: log each 8-byte slot value.
	if len(data) <= 128 {
		for dumpOff := 0; dumpOff+8 <= len(data); dumpOff += 8 {
			v := le64(data[dumpOff : dumpOff+8])
			mirrorDebugLog("scan-dump: addr=0x%x off=%d val=0x%x", wasmAddr, dumpOff, v)
		}
	}

	ptrSize := 8 // 64-bit host pointers
	for off := 0; off+ptrSize <= len(data); off += ptrSize {
		val := le64(data[off : off+ptrSize])
		if val == 0 {
			continue
		}

		hostPtr := uintptr(val)

		// Is this value a host pointer? It should be:
		// - Outside WASM memory range (> wasmMemSize)
		// - In a reasonable host address range (not a small integer/flag)
		// - Not a known WASM mirror address (which may be above wasmMemSize
		//   if the arena was initialized after wasmMemSize was captured)
		if val <= uint64(wasmMemSize) {
			continue
		}
		if val < 0x10000 {
			continue
		}
		// Skip values outside reasonable user-mode address range.
		if val > 0x7FFFFFFFFFFF {
			continue
		}
		// Skip known WASM mirror addresses. After mirror arena init, the
		// arena addresses are above wasmMemSize (as captured by the caller)
		// but are NOT host pointers. Without this check, the scan would
		// attempt Mirror() on them → VirtualQuery on Go heap → fail.
		if mt.LookupByWasm(uint32(val)) != nil {
			continue
		}
		// Also skip pending mirror addresses (registered but not yet resolved).
		mt.mu.RLock()
		_, isPending := mt.pending[uint32(val)]
		mt.mu.RUnlock()
		if isPending {
			continue
		}

		// Cycle detection: skip pointers already visited in this operation.
		// Without this, circular pointer chains (A→B→A) loop until budget
		// exhaustion. The visited map is allocated per top-level mirror
		// operation and garbage collected after.
		if visited[hostPtr] {
			if existing := mt.LookupByHost(hostPtr); existing != nil {
				putLE64(data[off:off+ptrSize], uint64(existing.wasmAddr))
			}
			mirrorDebugLog("scan: cycle detected host=0x%x, skipping", hostPtr)
			continue
		}
		visited[hostPtr] = true

		// Already mirrored — replace pointer in parent data with WASM mirror
		// address and do a shallow refresh of the mirror's WASM content.
		//
		// The shallow refresh re-reads host data and translates pointers that
		// are already in the mirror table (byHost lookup only, no new mirrors,
		// no recursion). This is critical for COM vtables where the initial
		// populateMirror + ScanAndMirrorPointers wrote translated data, but a
		// subsequent call path needs the mirror refreshed with current host
		// state. Without this, COM output parameters (e.g., Load_3's pAssembly)
		// may read stale or zeroed data from their mirror.
		//
		// We intentionally do NOT recurse: recursive re-scanning caused 661MB
		// scan loops on CLR COM object graphs (cascade overwrites + massive
		// cycling with zero new mirrors).
		mt.mu.RLock()
		_, exists := mt.byHost[hostPtr]
		mt.mu.RUnlock()
		if exists {
			existing := mt.LookupByHost(hostPtr)
			mirrorDebugLog("scan: dedup-hit host=0x%x existing=%v off=%d addr=0x%x", hostPtr, existing != nil, off, wasmAddr)
			if existing != nil {
				putLE64(data[off:off+ptrSize], uint64(existing.wasmAddr))

				// Shallow refresh: re-read host data, translate known pointers,
				// write back. No new mirrors, no recursion, no budget impact.
				if depth > 1 {
					hostData := mirrorReadHost(hostPtr, existing.size)
					if hostData != nil {
						// Validate: if the host data now looks like UTF-16 strings,
						// the CLR freed and reused this memory. Skip the refresh to
						// preserve the original (valid) mirror data.
						if mirrorDataIsUTF16(hostData, 64) {
							mirrorDebugLog("scan: dedup shallow-refresh SKIPPED (UTF-16 detected) wasm=0x%x host=0x%x", existing.wasmAddr, hostPtr)
						} else {
							for j := 0; j+ptrSize <= len(hostData); j += ptrSize {
								v := le64(hostData[j : j+ptrSize])
								if v > 0x10000 && v < 0x7FFFFFFFFFFF {
									if known := mt.LookupByHost(uintptr(v)); known != nil {
										putLE64(hostData[j:j+ptrSize], uint64(known.wasmAddr))
									} else if v > uint64(wasmMemSize) {
										// Store in truncation map: the shallow refresh
										// writes raw host addresses for entries not in
										// byHost (e.g., _AppDomain vtable entries that
										// weren't individually mirrored in the first scan).
										// The guest reads the full 8-byte value but the
										// i32 wasmimport ABI truncates to 32 bits. This
										// map recovers the full 64-bit address at proc
										// resolution time.
										mt.StoreTruncatedProc(uint32(v), uintptr(v))
									}
								}
							}
							writeBytes(mod, existing.wasmAddr, hostData)
							mirrorDebugLog("scan: dedup shallow-refresh wasm=0x%x host=0x%x size=%d", existing.wasmAddr, hostPtr, existing.size)
						}
					}
				}
			}
			continue
		}

		// Note: We intentionally do NOT filter on mirrorShouldMirror here.
		// The MEM_IMAGE filter belongs only in Step 6's top-level output
		// parameter loop (to prevent HMODULE corruption from direct API
		// return values). In recursive scanning, we're following pointer
		// chains from known-good mirrored objects (COM interfaces, etc.),
		// and COM vtables live in DLL memory (MEM_IMAGE). Filtering them
		// out here would break COM method dispatch.

		// Determine how much to mirror. Use platform-specific region query
		// or default to a reasonable size.
		regionSize := mirrorRegionSize(hostPtr)
		if regionSize == 0 {
			regionSize = 4096 // Default: one page
		}
		// Cap recursive mirrors. Large COM interfaces like _AppDomain
		// have 80+ vtable entries (640+ bytes). Cap at 1024 to cover
		// most COM vtables while avoiding scanning large heap regions
		// full of false-positive "host pointer" matches.
		if regionSize > 1024 {
			regionSize = 1024
		}

		isCode := mirrorIsCodeRegion(hostPtr)

		// Record ALL host pointers in the truncation map so the host
		// can recover the full 64-bit address when the guest passes the
		// low-32-bit-truncated value through the i32 wasmimport ABI.
		// CLR CCW thunks live at 48-bit addresses (e.g., 0x21b73a315c2)
		// that lose upper bits through the int32 proc parameter.
		// We store unconditionally (not gated on isCode) because:
		// 1. The map is only consulted as a last resort in proc resolution
		// 2. CCW thunks may not always be in PAGE_EXECUTE memory
		// 3. Extra entries are harmless (small memory overhead)
		mt.StoreTruncatedProc(uint32(hostPtr), hostPtr)

		// Budget exhausted: use lazy allocation instead of eager mirroring.
		// RegisterPending assigns a WASM address beyond current memory;
		// the fault handler copies data on first access and runs
		// ScanAndMirrorPointers to handle embedded pointers. This
		// eliminates stale host addresses that cause OOB crashes.
		if *budget <= 0 && !isCode {
			pendingAddr := mt.RegisterPending(mod, hostPtr, regionSize, wasmMemSize)
			if pendingAddr != 0 {
				putLE64(data[off:off+ptrSize], uint64(pendingAddr))
				mirrorDebugLog("scan: budget-exhausted lazy host=0x%x -> pending=0x%x", hostPtr, pendingAddr)
			}
			continue
		}

		mirrorAddr := mt.Mirror(mod, hostPtr, regionSize)
		if mirrorAddr == 0 {
			mirrorDebugLog("scan: Mirror FAILED host=0x%x regionSize=%d addr=0x%x off=%d", hostPtr, regionSize, wasmAddr, off)
			continue
		}

		// Only count non-code-region mirrors against the budget.
		// Code regions (x86 function bodies) are leaf nodes — they
		// don't spawn recursive scanning, so they have no budget
		// impact. Counting them was exhausting the budget before
		// large COM vtables (_AppDomain: 80+ entries) could be
		// fully mirrored.
		if !isCode {
			*budget--
		}

		// Replace the host pointer in the parent's WASM data with the mirror address.
		putLE64(data[off:off+ptrSize], uint64(mirrorAddr))

		// Recurse into the newly mirrored data to find embedded host
		// pointers. Skip recursion for code regions ONLY at the leaf
		// level (depth-1 == 0, i.e., depth == 1). At higher depths,
		// always recurse — COM vtable structures that happen to share
		// a page with executable code still contain function pointers
		// that need mirroring. The x86 false-positive concern only
		// applies at the leaf level where we'd be scanning actual
		// function body bytes.
		//
		// Example: IUnknown vtable at 0x...1dc8 in an execute-protected
		// page contains function pointers → must recurse to mirror them.
		// Individual function body at 0x...fba0 → no recursion needed
		// (code-region mirror gives reverse translation via LookupByWasm).
		shouldRecurse := !isCode || depth > 2
		if shouldRecurse {
			childData, ok := readBytes(mod, mirrorAddr, regionSize)
			if ok {
				mt.ScanAndMirrorPointers(mod, mirrorAddr, childData, wasmMemSize, depth-1, budget, visited)
				// Write back the updated child data (with replaced pointers).
				writeBytes(mod, mirrorAddr, childData)
			}
		}
	}

	// Write back the updated parent data (with replaced pointers).
	// No compaction needed: Go's wasip1/wasm uses 8-byte uintptr,
	// matching the x64 host pointer size.
	writeBytes(mod, wasmAddr, data)

	mirrorDebugLog("scan done: addr=0x%x depth=%d mirrored=%d budget_remaining=%d", wasmAddr, depth, startBudget-*budget, *budget)
}

// le64 reads a little-endian uint64 from a byte slice.
func le64(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

// putLE64 writes a little-endian uint64 to a byte slice.
func putLE64(b []byte, v uint64) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	b[4] = byte(v >> 32)
	b[5] = byte(v >> 40)
	b[6] = byte(v >> 48)
	b[7] = byte(v >> 56)
}

// RegisterPending allocates a WASM address for a host pointer without copying
// any data. The address will be beyond the current WASM memory size and will
// trigger an out-of-bounds fault when the guest accesses it. The fault handler
// (HandleFault) then grows memory and copies the data on demand.
//
// currentMemSize is the current WASM linear memory size in bytes — the arena
// is initialized at this boundary so all pending addresses are OOB.
func (mt *mirrorTable) RegisterPending(mod api.Module, hostAddr uintptr, size uint32, currentMemSize uint32) uint32 {
	mt.mu.Lock()
	defer mt.mu.Unlock()

	// Dedup: already mirrored eagerly?
	if existing, ok := mt.byHost[hostAddr]; ok {
		return existing.wasmAddr
	}
	// Dedup: already registered as pending?
	if wasmAddr, ok := mt.pendingByHost[hostAddr]; ok {
		return wasmAddr
	}

	// Initialize arena beyond a headroom gap so the guest Go heap
	// doesn't grow into mirror data.
	if mt.arena == 0 {
		mem := mod.Memory()
		if mem != nil {
			headroomPages := uint32(1024) // 64MB headroom for guest heap growth
			arenaPages := uint32(64)      // 4MB mirror arena
			prevPages, ok := mem.Grow(headroomPages + arenaPages)
			if ok {
				mt.initArena((prevPages + headroomPages) * 65536)
			} else {
				// Fallback: try smaller headroom.
				headroomPages = 128
				prevPages, ok = mem.Grow(headroomPages + arenaPages)
				if ok {
					mt.initArena((prevPages + headroomPages) * 65536)
				} else {
					mt.initArena(currentMemSize)
				}
			}
		} else {
			mt.initArena(currentMemSize)
		}
	}

	wasmAddr := mt.allocate(size)
	mt.pending[wasmAddr] = &pendingMirror{hostAddr: hostAddr, size: size}
	mt.pendingByHost[hostAddr] = wasmAddr
	return wasmAddr
}

// ResolvePendingEager is called when a pending mirror address is already
// within the current WASM memory bounds (because a previous HandleFault
// grew memory past the arena cursor). It removes the entry from pending
// and eagerly copies host data + scans for embedded pointers — just like
// HandleFault would, but without needing to grow memory.
func (mt *mirrorTable) ResolvePendingEager(mod api.Module, wasmAddr uint32, wasmMemSize uint32) {
	mt.mu.Lock()
	pm, ok := mt.pending[wasmAddr]
	if !ok {
		mt.mu.Unlock()
		return
	}
	delete(mt.pending, wasmAddr)
	delete(mt.pendingByHost, pm.hostAddr)
	mt.mu.Unlock()

	mirrorDebugLog("ResolvePendingEager: wasm=0x%x host=0x%x size=%d", wasmAddr, pm.hostAddr, pm.size)
	mt.populateMirror(mod, wasmAddr, pm.hostAddr, pm.size, wasmMemSize)
}

// HandleFault is called by the wazero memory fault handler when the guest
// accesses an address beyond linear memory. It checks whether the address
// corresponds to a pending mirror, and if so, grows memory, copies host data,
// and scans for embedded host pointers (registering them as new pending
// mirrors for lazy resolution).
//
// Returns true if the fault was handled (execution should resume), or false
// if the address is not a known pending mirror (triggers OOB panic).
func (mt *mirrorTable) HandleFault(mod api.Module, faultAddr, faultSize uint32) bool {
	mt.mu.Lock()

	// Find the pending mirror that contains the faulting address.
	var pm *pendingMirror
	var pmAddr uint32
	for addr, p := range mt.pending {
		if faultAddr >= addr && faultAddr < addr+p.size {
			pm = p
			pmAddr = addr
			break
		}
	}

	if pm == nil {
		mt.mu.Unlock()
		mirrorDebugLog("HandleFault: addr=0x%x size=%d NOT a pending mirror", faultAddr, faultSize)
		return false
	}

	// Remove from pending.
	delete(mt.pending, pmAddr)
	delete(mt.pendingByHost, pm.hostAddr)
	mt.mu.Unlock()

	mirrorDebugLog("HandleFault: addr=0x%x host=0x%x size=%d — growing memory", pmAddr, pm.hostAddr, pm.size)

	// Grow WASM memory to cover the pending mirror's address range.
	mem := mod.Memory()
	needed := uint64(pmAddr) + uint64(pm.size)
	currentSize := uint64(mem.Size())
	if needed > currentSize {
		pagesNeeded := uint32((needed - currentSize + 65535) / 65536)
		if _, ok := mem.Grow(pagesNeeded); !ok {
			mirrorDebugLog("HandleFault: memory grow failed (need %d pages)", pagesNeeded)
			return false
		}
		mirrorDebugLog("HandleFault: grew memory by %d pages (new size=%d)", pagesNeeded, mem.Size())
	}

	// Also populate any other pending mirrors that now fall within the grown
	// memory. After a grow, multiple pending addresses may become in-bounds.
	mt.mu.Lock()
	newSize := uint32(mem.Size())
	var extras []struct {
		addr uint32
		pm   *pendingMirror
	}
	for addr, p := range mt.pending {
		if addr+p.size <= newSize {
			extras = append(extras, struct {
				addr uint32
				pm   *pendingMirror
			}{addr, p})
		}
	}
	for _, e := range extras {
		delete(mt.pending, e.addr)
		delete(mt.pendingByHost, e.pm.hostAddr)
	}
	mt.mu.Unlock()

	// Copy host data for the faulted mirror.
	mt.populateMirror(mod, pmAddr, pm.hostAddr, pm.size, newSize)

	// Populate extras that became in-bounds from the grow.
	for _, e := range extras {
		mt.populateMirror(mod, e.addr, e.pm.hostAddr, e.pm.size, newSize)
	}

	return true
}

// populateMirror copies host data into WASM memory, tracks the entry, and
// scans for embedded host pointers (registering them as new pending mirrors).
func (mt *mirrorTable) populateMirror(mod api.Module, wasmAddr uint32, hostAddr uintptr, size uint32, wasmMemSize uint32) {
	hostData := mirrorReadHost(hostAddr, size)
	if hostData == nil {
		mirrorDebugLog("populateMirror: mirrorReadHost failed for host=0x%x size=%d", hostAddr, size)
		return
	}

	// DIAG: Log raw host bytes and detect UTF-16 string patterns.
	if mirrorDiagMode != "" {
		hexLimit := len(hostData)
		if hexLimit > 64 {
			hexLimit = 64
		}
		mirrorDiag("populateMirror: host=0x%x wasm=0x%x size=%d actual=%d first64=%x",
			hostAddr, wasmAddr, size, len(hostData), hostData[:hexLimit])

		if mirrorDataIsUTF16(hostData, 64) {
			mirrorDiag("populateMirror: WARNING UTF-16 string detected host=0x%x — likely NOT a COM object", hostAddr)
		}

		// Log VirtualQuery results via mirrorRegionSize for context.
		regionSz := mirrorRegionSize(hostAddr)
		mirrorDiag("populateMirror: VirtualQuery regionSize=%d for host=0x%x", regionSz, hostAddr)
	}

	if !writeBytes(mod, wasmAddr, hostData) {
		mirrorDebugLog("populateMirror: writeBytes failed for wasm=0x%x size=%d", wasmAddr, size)
		return
	}

	// Track as a real mirror entry.
	mt.mu.Lock()
	entry := &mirrorEntry{
		wasmAddr: wasmAddr,
		hostAddr: hostAddr,
		size:     size,
	}
	mt.byWasm[wasmAddr] = entry
	mt.byHost[hostAddr] = entry
	mt.mu.Unlock()

	// Scan for embedded host pointers and register them as new pending
	// mirrors (lazy resolution). Use the existing ScanAndMirrorPointers
	// which eagerly mirrors children — for now, this gives us correctness.
	// Future optimization: make ScanAndMirrorPointers register pending
	// mirrors instead of eager copying.
	data, ok := readBytes(mod, wasmAddr, size)
	if !ok {
		return
	}
	budget := 500
	mt.ScanAndMirrorPointers(mod, wasmAddr, data, wasmMemSize, maxMirrorDepth, &budget, make(map[uintptr]bool))
	mirrorDebugLog("populateMirror: wasm=0x%x host=0x%x size=%d budget_used=%d", wasmAddr, hostAddr, size, 500-budget)

	// Post-scan validation: detect two failure modes and retry.
	//
	// Pattern A: Offset 0 is a valid WASM mirror address, but the vtable
	//   data contains UTF-16 strings (CLR freed + reused the thunk heap for
	//   environment variable storage). Fix: invalidate the corrupt mirror,
	//   re-read the COM object, re-mirror with fresh data.
	//
	// Pattern B: Offset 0 is still a raw host address (48-bit, not mirrored).
	//   Mirror() failed during the scan — transient VirtualQuery issue.
	//   Fix: retry with delays until the CLR commits the page.
	if size >= 8 {
		for attempt := 0; attempt < 8; attempt++ {
			postData, postOk := readBytes(mod, wasmAddr, 8)
			if !postOk {
				break
			}
			val0 := le64(postData)
			if val0 == 0 {
				// NULL vtable pointer — COM object not yet initialized by
				// the CLR. Fall through to re-read from host after a delay.
				mirrorDebugLog("populateMirror: NULL vtable attempt=%d wasm=0x%x", attempt+1, wasmAddr)
			} else {
				// Non-pointer or small WASM address — nothing to validate.
				if val0 <= 0x10000 || val0 >= 0x7FFFFFFFFFFF {
					break
				}
				if val0 <= uint64(wasmMemSize) {
					break
				}

				// Check if offset 0 was mirrored to a WASM arena address.
				vtEntry := mt.LookupByWasm(uint32(val0))
				if vtEntry != nil {
					// Pattern A check: validate the mirrored vtable content.
					// If it contains UTF-16 strings, the CLR reused the memory.
					vtData, vtOk := readBytes(mod, vtEntry.wasmAddr, min(vtEntry.size, 64))
					if !vtOk {
						break // Read failed — transient issue, don't invalidate.
					}
					if !mirrorDataIsUTF16(vtData, 64) {
						break // Vtable content looks valid — done.
					}
					// Corrupt vtable data (UTF-16 env var strings). Invalidate the
					// mirror so re-mirror reads fresh host data instead of returning
					// the stale entry.
					mirrorDebugLog("populateMirror: vtable UTF-16 corrupt wasm=0x%x host=0x%x attempt=%d",
						vtEntry.wasmAddr, vtEntry.hostAddr, attempt+1)
					mt.mu.Lock()
					delete(mt.byWasm, vtEntry.wasmAddr)
					delete(mt.byHost, vtEntry.hostAddr)
					mt.mu.Unlock()
				}
				// else: Pattern B — raw host address, not mirrored.
			}
			mirrorDebugLog("populateMirror: post-scan stale offset0=0x%x attempt=%d", val0, attempt+1)

			delays := []int{10, 20, 40, 60, 80, 100, 150, 200} // total ~660ms
			delay := time.Duration(delays[attempt]) * time.Millisecond
			time.Sleep(delay)

			// Re-read the COM object from host. After CLR stabilization,
			// the vtable pointer may now point to valid committed memory.
			hostData2 := mirrorReadHost(hostAddr, size)
			if hostData2 == nil {
				mirrorDebugLog("populateMirror: retry mirrorReadHost failed host=0x%x attempt=%d", hostAddr, attempt+1)
				continue
			}
			writeBytes(mod, wasmAddr, hostData2)

			// Direct-mirror the vtable pointer, validating data quality.
			if len(hostData2) >= 8 {
				retryVtPtr := uintptr(le64(hostData2[:8]))
				mirrorDebugLog("populateMirror: retry vtPtr=0x%x attempt=%d", retryVtPtr, attempt+1)
				if retryVtPtr > 0x10000 && retryVtPtr < 0x7FFFFFFFFFFF && uint64(retryVtPtr) > uint64(wasmMemSize) {
					vtRegSize := mirrorRegionSize(retryVtPtr)
					if vtRegSize == 0 {
						vtRegSize = 1024
					}
					if vtRegSize > 1024 {
						vtRegSize = 1024
					}
					// Pre-validate: read the vtable data from host and
					// reject if it's UTF-16 strings (still corrupt).
					vtHostData := mirrorReadHost(retryVtPtr, vtRegSize)
					if vtHostData != nil && !mirrorDataIsUTF16(vtHostData, 64) {
						vtMirror := mt.Mirror(mod, retryVtPtr, vtRegSize)
						if vtMirror != 0 {
							putLE64(hostData2[:8], uint64(vtMirror))
							writeBytes(mod, wasmAddr, hostData2)
							mirrorDebugLog("populateMirror: vtable retry-mirror OK host=0x%x vtMirror=0x%x attempt=%d",
								retryVtPtr, vtMirror, attempt+1)
						}
					}
				}
			}

			// Re-scan with fresh data.
			data2, ok2 := readBytes(mod, wasmAddr, size)
			if ok2 {
				budget2 := 500
				mt.ScanAndMirrorPointers(mod, wasmAddr, data2, wasmMemSize, maxMirrorDepth, &budget2, make(map[uintptr]bool))
				mirrorDebugLog("populateMirror: retry scan wasm=0x%x host=0x%x budget_used=%d attempt=%d",
					wasmAddr, hostAddr, 500-budget2, attempt+1)
			}
		}
	}
}

// mirrorDataIsUTF16 checks if data contains UTF-16 string patterns (printable
// ASCII chars with alternating null bytes). The CLR's GC can free and reuse
// COM thunk heap memory for environment variable strings. When this happens,
// mirrorReadHost reads UTF-16 text instead of function pointers.
//
// Returns true if >4 ASCII+null pairs are found in the first checkLen bytes.
// Threshold rationale: COM vtables contain 8-byte function pointers (high
// addresses like 0x7FFE...) which never produce ASCII+null pairs. Environment
// variable strings like "ALLUSERSPROFILE=C:\..." produce 15+ pairs in 32
// bytes. The >4 threshold gives wide separation with zero false positives on
// valid COM data. The 64-byte check window covers the first 8 vtable slots.
func mirrorDataIsUTF16(data []byte, checkLen int) bool {
	if len(data) < 4 {
		return false
	}
	if checkLen > len(data) {
		checkLen = len(data)
	}
	utf16Pairs := 0
	for j := 0; j+1 < checkLen; j += 2 {
		if data[j] >= 0x20 && data[j] <= 0x7E && data[j+1] == 0 {
			utf16Pairs++
		}
	}
	return utf16Pairs > 4
}

// Context key for mirror table.
const ctxKeyMirrorTable contextKey = 11

// WithMirrorTable stores the mirror table in the context.
func WithMirrorTable(ctx context.Context, mt *mirrorTable) context.Context {
	return context.WithValue(ctx, ctxKeyMirrorTable, mt)
}

// getMirrorTable retrieves the mirror table from the context.
func getMirrorTable(ctx context.Context) *mirrorTable {
	mt, _ := ctx.Value(ctxKeyMirrorTable).(*mirrorTable)
	return mt
}

// GetMirrorTable retrieves the mirror table from the context (exported).
func GetMirrorTable(ctx context.Context) *mirrorTable {
	return getMirrorTable(ctx)
}

// NewMirrorTable creates a new mirror table for external use.
func NewMirrorTable() *mirrorTable {
	return newMirrorTable()
}
