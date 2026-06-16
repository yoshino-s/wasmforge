//go:build wasip1

package win32

import (
	"encoding/binary"
	"fmt"
)

// HostMem represents a host-side memory allocation created via VirtualAlloc.
// The memory exists in the host process address space (not WASM linear memory),
// so it cannot be accessed via unsafe.Pointer. All reads/writes go through
// the HMem* host function calls.
type HostMem struct {
	handle int32
	size   uint32
}

// Windows memory allocation type constants.
const (
	MEM_COMMIT  = uint32(0x1000)
	MEM_RESERVE = uint32(0x2000)
)

// Windows memory protection constants.
const (
	PAGE_NOACCESS          = uint32(0x01)
	PAGE_READONLY          = uint32(0x02)
	PAGE_READWRITE         = uint32(0x04)
	PAGE_WRITECOPY         = uint32(0x08)
	PAGE_EXECUTE           = uint32(0x10)
	PAGE_EXECUTE_READ      = uint32(0x20)
	PAGE_EXECUTE_READWRITE = uint32(0x40)
	PAGE_EXECUTE_WRITECOPY = uint32(0x80)
)

// VirtualAlloc allocates a region of memory in the host process using
// Windows VirtualAlloc. Returns a HostMem handle for subsequent operations.
func VirtualAlloc(size, allocType, protect uint32) (*HostMem, error) {
	if size == 0 {
		return nil, fmt.Errorf("win32: VirtualAlloc: size is zero")
	}
	var h int32
	errno := _win32_virtual_alloc(size, allocType, protect, &h)
	if err := errFromErrno(errno); err != nil {
		return nil, fmt.Errorf("win32: VirtualAlloc: %w", err)
	}
	return &HostMem{handle: h, size: size}, nil
}

// VirtualProtect changes the memory protection on the allocation.
// Returns the previous protection value.
func (m *HostMem) VirtualProtect(newProtect uint32) (oldProtect uint32, err error) {
	errno := _win32_virtual_protect(m.handle, newProtect, &oldProtect)
	if e := errFromErrno(errno); e != nil {
		return 0, fmt.Errorf("win32: VirtualProtect: %w", e)
	}
	return oldProtect, nil
}

// Free releases the host memory allocation using VirtualFree.
func (m *HostMem) Free() error {
	errno := _win32_virtual_free(m.handle)
	if err := errFromErrno(errno); err != nil {
		return fmt.Errorf("win32: VirtualFree: %w", err)
	}
	return nil
}

// Handle returns the raw guest handle ID for this allocation.
func (m *HostMem) Handle() int32 {
	return m.handle
}

// Size returns the allocation size in bytes.
func (m *HostMem) Size() uint32 {
	return m.size
}

// Write copies data from WASM memory into the host allocation at the given offset.
func (m *HostMem) Write(offset uint32, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	errno := _win32_hmem_write(m.handle, offset, &data[0], uint32(len(data)))
	if err := errFromErrno(errno); err != nil {
		return fmt.Errorf("win32: HMemWrite: %w", err)
	}
	return nil
}

// Read copies data from the host allocation into WASM memory.
func (m *HostMem) Read(offset, length uint32) ([]byte, error) {
	if length == 0 {
		return nil, nil
	}
	buf := make([]byte, length)
	errno := _win32_hmem_read(m.handle, offset, &buf[0], length)
	if err := errFromErrno(errno); err != nil {
		return nil, fmt.Errorf("win32: HMemRead: %w", err)
	}
	return buf, nil
}

// WriteUint32 writes a uint32 value at the given byte offset in the host allocation.
func (m *HostMem) WriteUint32(offset, value uint32) error {
	errno := _win32_hmem_write32(m.handle, offset, value)
	if err := errFromErrno(errno); err != nil {
		return fmt.Errorf("win32: HMemWrite32: %w", err)
	}
	return nil
}

// WriteUint64 writes a uint64 value (little-endian) at the given byte offset.
func (m *HostMem) WriteUint64(offset uint32, value uint64) error {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], value)
	errno := _win32_hmem_write64(m.handle, offset, &buf[0])
	if err := errFromErrno(errno); err != nil {
		return fmt.Errorf("win32: HMemWrite64: %w", err)
	}
	return nil
}

// ReadUint32 reads a uint32 from the given byte offset in the host allocation.
func (m *HostMem) ReadUint32(offset uint32) (uint32, error) {
	var val uint32
	errno := _win32_hmem_read32(m.handle, offset, &val)
	if err := errFromErrno(errno); err != nil {
		return 0, fmt.Errorf("win32: HMemRead32: %w", err)
	}
	return val, nil
}

// ReadUint64 reads a uint64 (little-endian) from the given byte offset.
func (m *HostMem) ReadUint64(offset uint32) (uint64, error) {
	var buf [8]byte
	errno := _win32_hmem_read64(m.handle, offset, &buf[0])
	if err := errFromErrno(errno); err != nil {
		return 0, fmt.Errorf("win32: HMemRead64: %w", err)
	}
	return binary.LittleEndian.Uint64(buf[:]), nil
}

// ProcFromOffset registers the host address at m+offset as a callable Proc handle.
// Use this to call code in host memory (shellcode, PE entry points) via SyscallN.
func (m *HostMem) ProcFromOffset(offset uint32) (Proc, error) {
	var p int32
	errno := _win32_proc_from_hmem(m.handle, offset, &p)
	if err := errFromErrno(errno); err != nil {
		return 0, fmt.Errorf("win32: ProcFromHMem: %w", err)
	}
	return Proc(p), nil
}

// Addr returns the real host-side address of the allocation as a uint64.
// This can be passed to SyscallN64 when a native pointer is needed.
func (m *HostMem) Addr() (uint64, error) {
	var buf [8]byte
	errno := _win32_hmem_addr(m.handle, &buf[0])
	if err := errFromErrno(errno); err != nil {
		return 0, fmt.Errorf("win32: HMemAddr: %w", err)
	}
	return binary.LittleEndian.Uint64(buf[:]), nil
}
