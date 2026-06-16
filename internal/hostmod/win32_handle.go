package hostmod

import "sync"

// Handle kinds for the Win32/Darwin handle table.
const (
	handleDLL     = 0 // DLL handle (from LoadLibrary)
	handleProc    = 1 // Proc address (from GetProcAddress)
	handleWin32   = 2 // Generic Win32 HANDLE (registry keys, files, processes, tokens, etc.)
	handleHostMem = 3 // Host memory allocation (from VirtualAlloc)
	handleDylib   = 4 // macOS dylib/framework handle (from dlopen)
	handleSymbol  = 5 // macOS symbol address (from dlsym)
)

// win32HandleEntry holds a single entry in the Win32 handle table.
type win32HandleEntry struct {
	kind           int
	dllHandle      uintptr
	procAddr       uintptr
	winHandle      uintptr
	memSize        uintptr // size of host memory allocation (handleHostMem only)
	debugName      string  // optional: DLL or proc name for debug logging
	hasPointerMask bool    // true if pointerMask was set (distinguishes 0 mask from unset)
	pointerMask    uint32  // bitmask: bit N=1 means arg[N] is a WASM pointer to translate
}

// win32BaseHandle is the lowest guest handle ID for Win32 handles,
// kept well above the socket FD range (baseFD = 10000).
const win32BaseHandle = 20000

// win32HandleTable manages mappings from guest handle IDs to host resources.
type win32HandleTable struct {
	mu      sync.Mutex
	entries map[int32]*win32HandleEntry
	nextID  int32
}

// newWin32HandleTable creates a new Win32 handle table.
func newWin32HandleTable() *win32HandleTable {
	return &win32HandleTable{
		entries: make(map[int32]*win32HandleEntry),
		nextID:  win32BaseHandle,
	}
}

// register adds an entry to the handle table and returns the guest handle ID.
func (t *win32HandleTable) register(entry *win32HandleEntry) int32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	id := t.nextID
	t.nextID++
	t.entries[id] = entry
	return id
}

// get returns the entry for a guest handle ID, or nil if not found.
func (t *win32HandleTable) get(id int32) *win32HandleEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.entries[id]
}

// remove deletes an entry from the table and returns it, or nil if not found.
func (t *win32HandleTable) remove(id int32) *win32HandleEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	entry := t.entries[id]
	delete(t.entries, id)
	return entry
}

// procAddrs returns a map of handle ID → native proc address for all proc entries.
// Used by shadow entry point execution to translate handle IDs in GOT entries
// to real native addresses.
func (t *win32HandleTable) procAddrs() map[int32]uintptr {
	t.mu.Lock()
	defer t.mu.Unlock()
	result := make(map[int32]uintptr, len(t.entries))
	for id, entry := range t.entries {
		if entry.kind == handleProc {
			result[id] = entry.procAddr
		}
	}
	return result
}
