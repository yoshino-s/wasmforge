//go:build nativeaot

// NativeAOT-specific OS host functions.
// Directory listing and file existence checks that bypass WASI path mapping.

package hostmod

import (
	"context"
	"os"
	
	"github.com/tetratelabs/wazero/api"
)

// osListDir implements a host function that lists directory entries.
// This bypasses WASI filesystem path mapping issues by doing the
// directory read on the host side with native path resolution.
//
// Guest ABI:
//
//	path_ptr:   pointer to UTF-8 path string
//	path_len:   length of path string
//	buf_ptr:    pointer to output buffer (entries as null-separated UTF-8 strings)
//	buf_cap:    capacity of output buffer
//	count_ptr:  pointer to write the entry count
//
// Returns bytes written to buf, or 0 on error.
func osListDir(_ context.Context, mod api.Module, stack []uint64) {
	pathPtr := uint32(stack[0])
	pathLen := uint32(stack[1])
	bufPtr := uint32(stack[2])
	bufCap := uint32(stack[3])
	countPtr := uint32(stack[4])

	pathBytes, ok := readBytes(mod, pathPtr, pathLen)
	if !ok {
		stack[0] = 0
		return
	}
	dirPath := string(pathBytes)

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		stack[0] = 0
		return
	}

	var buf []byte
	count := uint32(0)
	for _, e := range entries {
		// Return just the basename. C# WfFs.List prepends the input
		// path to each entry, so writing full paths here was producing
		// doubled prefixes like "C:\foo\C:\foo\file" on the C# side.
		entry := []byte(e.Name())
		if uint32(len(buf)+len(entry)+1) > bufCap {
			break
		}
		buf = append(buf, entry...)
		buf = append(buf, 0) // null separator
		count++
	}

	if len(buf) > 0 {
		writeBytes(mod, bufPtr, buf)
	}
	writeUint32(mod, countPtr, count)
	stack[0] = uint64(len(buf))
}

// osFileExists checks if a file/directory exists on the host filesystem.
//
// Guest ABI:
//
//	path_ptr: pointer to UTF-8 path string
//	path_len: length of path string
//
// Returns 1 if exists, 0 if not.
func osFileExists(_ context.Context, mod api.Module, stack []uint64) {
	pathPtr := uint32(stack[0])
	pathLen := uint32(stack[1])

	pathBytes, ok := readBytes(mod, pathPtr, pathLen)
	if !ok {
		stack[0] = 0
		return
	}

	if _, err := os.Stat(string(pathBytes)); err == nil {
		stack[0] = 1
	} else {
		stack[0] = 0
	}
}

// osReadAll reads a file's full contents from the host filesystem,
// bypassing WASI's path remapping (which prepends '/' to absolute
// Windows paths like 'C:\Users\...').
//
// Wire format:
//
//	stack[0]: path_ptr (UTF-8 path)
//	stack[1]: path_len
//	stack[2]: buf_ptr (caller-allocated; 0 = sizing call)
//	stack[3]: buf_cap (bytes available in buf_ptr; 0 = sizing call)
//	stack[4]: out_len_ptr (host writes file size here)
//
// Returns int32:
//
//	>= 0: bytes written into buf (or 0 if sizing call)
//	-1:   path read failed
//	-2:   path open failed
//	-3:   path read failed mid-read
//
// On sizing call (buf_cap == 0), the function only writes the file size
// to *out_len_ptr and returns 0. On data call, the function copies up
// to buf_cap bytes into buf_ptr and writes the actual size to
// *out_len_ptr.
func osReadAll(_ context.Context, mod api.Module, stack []uint64) {
	pathPtr := uint32(stack[0])
	pathLen := uint32(stack[1])
	bufPtr := uint32(stack[2])
	bufCap := uint32(stack[3])
	outLenPtr := uint32(stack[4])

	pathBytes, ok := readBytes(mod, pathPtr, pathLen)
	if !ok {
		stack[0] = ^uint64(0)
		return
	}

	data, err := os.ReadFile(string(pathBytes))
	if err != nil {
		stack[0] = ^uint64(1)
		return
	}

	// Write the actual size to *out_len_ptr (caller uses this on both
	// sizing and data calls).
	mod.Memory().WriteUint32Le(outLenPtr, uint32(len(data)))

	if bufCap == 0 {
		// Sizing call — caller only wanted to know the file size.
		stack[0] = 0
		return
	}

	n := uint32(len(data))
	if n > bufCap {
		n = bufCap
	}
	if !mod.Memory().Write(bufPtr, data[:n]) {
		stack[0] = ^uint64(2)
		return
	}
	stack[0] = uint64(n)
}

// ────────────────────────────────────────────────────────────────────────
// Generic IO dispatcher (io_op)
//
// Sibling to xc_op (crypto dispatcher). One host export covering the
// file/directory operations that the WASM-side `fs_read_all` C bridge
// chain implements via 6-8 wf_calls per file (CreateFile + GetFileSize +
// CreateFile + ReadFile×N retries + CloseHandle). Empirically that chain
// costs ~45 ms per file, dominating SharpDPAPI machinemasterkeys wall-
// clock (207s with the crypto already optimized — the file IO of 13+
// master key files at ~46ms each was the next bottleneck).
//
// Running the whole CreateFile/Read/Close sequence as one Go syscall
// chain via `os.ReadFile` should bring per-file cost down to the
// wf_call boundary cost alone (~10-50 µs).
//
// Wire format: same as xc_op — opcode string + length-prefixed packed
// byte fields.
//
// Opcodes:
//   "read"  (utf8_path)              → file bytes
//   "stat"  (utf8_path)              → 8 bytes: 4-byte size_le + 4-byte exists(0/1)
//   "list"  (utf8_path)              → null-separated entry names
//
// Returns bytes written to outBuf (or 0 on error).
//
// Path access model: paths are passed verbatim to Go's os.* primitives with
// no prefix restriction. Callers already have equivalent arbitrary-read
// capability via wf_call CreateFile chains, so xi_op adds no new attack
// surface beyond what already exists in the bridge. If the threat model
// ever shifts to untrusted-WASM execution, a path-prefix allowlist would
// be added here.

func nativeaotIoOp(ctx context.Context, mod api.Module,
	opPtr, opLen, argsPtr, argsLen, outPtr, outCap uint32) uint32 {

	opBytes, ok := readBytes(mod, opPtr, opLen)
	if !ok {
		return 0
	}
	op := string(opBytes)

	args, ok := readBytes(mod, argsPtr, argsLen)
	if !ok {
		return 0
	}
	fields, ok := ioOpUnpackFields(args)
	if !ok || len(fields) < 1 {
		return 0
	}
	path := string(fields[0])

	switch op {
	case "read":
		data, err := os.ReadFile(path)
		if err != nil {
			return 0
		}
		if uint32(len(data)) > outCap {
			return 0
		}
		if !mod.Memory().Write(outPtr, data) {
			return 0
		}
		return uint32(len(data))
	case "stat":
		fi, err := os.Stat(path)
		if err != nil {
			return 0
		}
		buf := make([]byte, 8)
		sz := uint32(fi.Size())
		buf[0] = byte(sz)
		buf[1] = byte(sz >> 8)
		buf[2] = byte(sz >> 16)
		buf[3] = byte(sz >> 24)
		buf[4] = 1 // exists
		if !mod.Memory().Write(outPtr, buf) {
			return 0
		}
		return 8
	case "list":
		entries, err := os.ReadDir(path)
		if err != nil {
			return 0
		}
		var out []byte
		for _, e := range entries {
			out = append(out, []byte(e.Name())...)
			out = append(out, 0)
		}
		// Refuse the call rather than silently truncate — truncating at
		// outCap would split the final entry name mid-byte and leave it
		// un-null-terminated, producing a corrupted last name on the C#
		// side. Caller should retry with a larger buffer.
		if uint32(len(out)) > outCap {
			return 0
		}
		if len(out) == 0 {
			return 0
		}
		if !mod.Memory().Write(outPtr, out) {
			return 0
		}
		return uint32(len(out))
	}
	return 0
}

func ioOpUnpackFields(buf []byte) ([][]byte, bool) {
	var fields [][]byte
	i := 0
	for i < len(buf) {
		if i+4 > len(buf) {
			return nil, false
		}
		n := int(uint32(buf[i]) | uint32(buf[i+1])<<8 | uint32(buf[i+2])<<16 | uint32(buf[i+3])<<24)
		i += 4
		if i+n > len(buf) {
			return nil, false
		}
		fields = append(fields, buf[i:i+n])
		i += n
	}
	return fields, true
}
