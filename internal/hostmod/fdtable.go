package hostmod

import (
	"net"
	"sync"
	"syscall"
)

const baseFD = 10000

// socketEntry holds metadata about a host-side socket.
//
// Thread safety: the immutable fields (osFD, family, sockType, protocol)
// are set at creation and never modified. The mutable fields (localAddr,
// remoteAddr) are written only from host function calls (sockBind,
// sockConnect, sockAccept) which are invoked from WASM guest code.
// wazero executes a single WASM module instance in one goroutine at a
// time, so host function calls are serialized and no concurrent writes
// to these fields occur.
type socketEntry struct {
	// Immutable after creation.
	osFD     osFDType
	family   int
	sockType int
	protocol int

	// Mutable — written only from serialized host function calls.
	// See type-level comment for thread safety rationale.
	localAddr  net.Addr
	remoteAddr net.Addr
}

// fdTable manages the mapping from guest socket FDs (>= 10000)
// to host OS file descriptors.
type fdTable struct {
	mu      sync.Mutex
	entries map[int32]*socketEntry
	nextFD  int32
}

// newFDTable creates a new socket FD table.
func newFDTable() *fdTable {
	return &fdTable{
		entries: make(map[int32]*socketEntry),
		nextFD:  baseFD,
	}
}

// register adds a new socket to the table and returns the guest FD.
func (t *fdTable) register(osFD osFDType, family, sockType, protocol int) int32 {
	t.mu.Lock()
	defer t.mu.Unlock()

	fd := t.nextFD
	t.nextFD++

	t.entries[fd] = &socketEntry{
		osFD:     osFD,
		family:   family,
		sockType: sockType,
		protocol: protocol,
	}
	return fd
}

// get returns the socket entry for a guest FD, or nil if not found.
func (t *fdTable) get(fd int32) *socketEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.entries[fd]
}

// remove closes and removes the socket entry for a guest FD.
func (t *fdTable) remove(fd int32) error {
	t.mu.Lock()
	entry, ok := t.entries[fd]
	if ok {
		delete(t.entries, fd)
	}
	t.mu.Unlock()

	if !ok {
		return syscall.EBADF
	}
	return socketClose(entry.osFD)
}

// closeAll closes all sockets in the table.
func (t *fdTable) closeAll() {
	t.mu.Lock()
	entries := t.entries
	t.entries = make(map[int32]*socketEntry)
	t.mu.Unlock()

	for _, e := range entries {
		socketClose(e.osFD)
	}
}
