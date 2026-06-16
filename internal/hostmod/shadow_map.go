package hostmod

import (
	"sort"
	"sync"
)

// shadowEntry tracks a single shadow memory allocation — one region
// that exists in both WASM linear memory and real host memory.
type shadowEntry struct {
	wasmAddr uint32  // Address within WASM linear memory.
	hostAddr uintptr // Corresponding real host address (from VirtualAlloc).
	size     uint32  // Size of the allocation in bytes.
	protect  uint32  // Current memory protection flags.
}

// shadowMap maintains the set of active shadow allocations, kept sorted
// by wasmAddr for efficient binary search lookups.
type shadowMap struct {
	mu      sync.RWMutex
	entries []shadowEntry
}

// newShadowMap creates an empty shadow map.
func newShadowMap() *shadowMap {
	return &shadowMap{}
}

// Register adds a new shadow allocation to the map.
func (sm *shadowMap) Register(wasmAddr uint32, hostAddr uintptr, size, protect uint32) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	entry := shadowEntry{
		wasmAddr: wasmAddr,
		hostAddr: hostAddr,
		size:     size,
		protect:  protect,
	}

	// Insert in sorted order by wasmAddr.
	idx := sort.Search(len(sm.entries), func(i int) bool {
		return sm.entries[i].wasmAddr >= wasmAddr
	})
	sm.entries = append(sm.entries, shadowEntry{})
	copy(sm.entries[idx+1:], sm.entries[idx:])
	sm.entries[idx] = entry
}

// Lookup returns the shadow entry with an exact wasmAddr match, or nil.
func (sm *shadowMap) Lookup(wasmAddr uint32) *shadowEntry {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	idx := sort.Search(len(sm.entries), func(i int) bool {
		return sm.entries[i].wasmAddr >= wasmAddr
	})
	if idx < len(sm.entries) && sm.entries[idx].wasmAddr == wasmAddr {
		e := sm.entries[idx]
		return &e
	}
	return nil
}

// LookupContaining returns the shadow entry whose range [wasmAddr, wasmAddr+size)
// contains addr, or nil if no match. Uses binary search.
func (sm *shadowMap) LookupContaining(addr uint32) *shadowEntry {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// Find the last entry with wasmAddr <= addr.
	idx := sort.Search(len(sm.entries), func(i int) bool {
		return sm.entries[i].wasmAddr > addr
	}) - 1

	if idx >= 0 && addr >= sm.entries[idx].wasmAddr &&
		addr < sm.entries[idx].wasmAddr+sm.entries[idx].size {
		e := sm.entries[idx]
		return &e
	}
	return nil
}

// Remove atomically looks up and removes the shadow entry with the given
// wasmAddr. Returns the removed entry, or nil if not found. This avoids
// TOCTOU races between Lookup and Remove.
func (sm *shadowMap) Remove(wasmAddr uint32) *shadowEntry {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	idx := sort.Search(len(sm.entries), func(i int) bool {
		return sm.entries[i].wasmAddr >= wasmAddr
	})
	if idx >= len(sm.entries) || sm.entries[idx].wasmAddr != wasmAddr {
		return nil
	}

	e := sm.entries[idx]
	sm.entries = append(sm.entries[:idx], sm.entries[idx+1:]...)
	return &e
}

// GetAll returns a copy of all shadow entries. Used for full-sync operations
// (e.g., before/after calling native code entry points in shadow memory).
func (sm *shadowMap) GetAll() []shadowEntry {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	result := make([]shadowEntry, len(sm.entries))
	copy(result, sm.entries)
	return result
}

// UpdateProtect updates the protection flags for the entry at wasmAddr.
func (sm *shadowMap) UpdateProtect(wasmAddr, protect uint32) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	idx := sort.Search(len(sm.entries), func(i int) bool {
		return sm.entries[i].wasmAddr >= wasmAddr
	})
	if idx < len(sm.entries) && sm.entries[idx].wasmAddr == wasmAddr {
		sm.entries[idx].protect = protect
	}
}
