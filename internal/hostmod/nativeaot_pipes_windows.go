//go:build nativeaot && windows

package hostmod

import (
	"context"
	"syscall"
	"unsafe"

	"github.com/tetratelabs/wazero/api"
)

// osListNamedPipes enumerates named pipes via FindFirstFileW / FindNextFileW
// on the host side, then writes the names NUL-separated into a WASM buffer.
//
// Guest ABI:
//
//	stack[0] in/out: buf_ptr in, bytes_written out (uint32)
//	stack[1] in:     buf_cap (uint32)
//	stack[2] in:     count_ptr — WASM ptr to uint32 receiving entry count
//
// Replaces NamedPipesCommand's FindFirstFile P/Invoke path that crashed
// the bridge due to WIN32_FIND_DATA struct marshaling.
func osListNamedPipes(_ context.Context, mod api.Module, stack []uint64) {
	bufPtr := uint32(stack[0])
	bufCap := uint32(stack[1])
	countPtr := uint32(stack[2])

	pattern, _ := syscall.UTF16PtrFromString(`\\.\pipe\*`)
	var data syscall.Win32finddata
	handle, err := syscall.FindFirstFile(pattern, &data)
	if err != nil || handle == syscall.InvalidHandle {
		writeUint32(mod, countPtr, 0)
		stack[0] = 0
		return
	}
	defer syscall.FindClose(handle)

	var buf []byte
	count := uint32(0)
	for {
		// Convert FileName (UTF-16 fixed array) to UTF-8 string.
		nameLen := 0
		for nameLen < len(data.FileName) && data.FileName[nameLen] != 0 {
			nameLen++
		}
		nameU16 := unsafe.Slice(&data.FileName[0], nameLen)
		name := string(utf16Decode(nameU16))
		if name != "" && name != "." && name != ".." {
			entry := []byte(name)
			if uint32(len(buf)+len(entry)+1) > bufCap {
				break
			}
			buf = append(buf, entry...)
			buf = append(buf, 0)
			count++
		}
		if err := syscall.FindNextFile(handle, &data); err != nil {
			break
		}
	}

	if len(buf) > 0 {
		writeBytes(mod, bufPtr, buf)
	}
	writeUint32(mod, countPtr, count)
	stack[0] = uint64(len(buf))
}

// utf16Decode converts a UTF-16 LE slice to UTF-8 runes.
func utf16Decode(u16 []uint16) []rune {
	out := make([]rune, 0, len(u16))
	for i := 0; i < len(u16); i++ {
		c := u16[i]
		if c >= 0xD800 && c <= 0xDBFF && i+1 < len(u16) {
			lo := u16[i+1]
			if lo >= 0xDC00 && lo <= 0xDFFF {
				out = append(out, rune((uint32(c-0xD800)<<10)|uint32(lo-0xDC00)+0x10000))
				i++
				continue
			}
		}
		out = append(out, rune(c))
	}
	return out
}
