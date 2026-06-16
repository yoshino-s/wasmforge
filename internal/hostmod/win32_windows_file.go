//go:build windows

package hostmod

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/tetratelabs/wazero/api"
	"golang.org/x/sys/windows"
)

// win32CreateFile opens or creates a file.
func win32CreateFile(ctx context.Context, mod api.Module, pathPtr, pathLen, access, share, creation, flags, handlePtr uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	if pathLen == 0 {
		return errnoEINVAL
	}
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoEINVAL
	}

	pathBytes, ok := readBytes(mod, pathPtr, pathLen)
	if !ok {
		return errnoEFAULT
	}
	pathUTF16, err := windows.UTF16PtrFromString(string(pathBytes))
	if err != nil {
		return errnoEINVAL
	}

	handle, err := windows.CreateFile(
		pathUTF16,
		access,
		share,
		nil,
		creation,
		flags,
		0,
	)
	if err != nil {
		return win32Errno(err)
	}

	id := ht.register(&win32HandleEntry{
		kind:      handleWin32,
		winHandle: uintptr(handle),
	})

	if !writeInt32(mod, handlePtr, id) {
		windows.CloseHandle(handle)
		return errnoEFAULT
	}
	return errnoSuccess
}

// win32ReadFile reads data from a file handle into WASM memory.
func win32ReadFile(ctx context.Context, mod api.Module, handle int32, bufPtr, bufLen, nreadPtr uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoEINVAL
	}

	entry := ht.get(handle)
	if entry == nil {
		return errnoEBADF
	}

	buf := make([]byte, bufLen)
	var nread uint32

	if err := windows.ReadFile(windows.Handle(entry.winHandle), buf, &nread, nil); err != nil {
		return win32Errno(err)
	}

	if !writeBytes(mod, bufPtr, buf[:nread]) {
		return errnoEFAULT
	}
	if !writeUint32(mod, nreadPtr, nread) {
		return errnoEFAULT
	}
	return errnoSuccess
}

// win32WriteFile writes data from WASM memory to a file handle.
func win32WriteFile(ctx context.Context, mod api.Module, handle int32, bufPtr, bufLen, nwrittenPtr uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoEINVAL
	}

	entry := ht.get(handle)
	if entry == nil {
		return errnoEBADF
	}

	buf, ok := readBytes(mod, bufPtr, bufLen)
	if !ok {
		return errnoEFAULT
	}

	var nwritten uint32
	if err := windows.WriteFile(windows.Handle(entry.winHandle), buf, &nwritten, nil); err != nil {
		return win32Errno(err)
	}

	if !writeUint32(mod, nwrittenPtr, nwritten) {
		return errnoEFAULT
	}
	return errnoSuccess
}

// win32GetFileAttrs retrieves file attributes for a path.
func win32GetFileAttrs(ctx context.Context, mod api.Module, pathPtr, pathLen, attrsPtr uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	if pathLen == 0 {
		return errnoEINVAL
	}

	pathBytes, ok := readBytes(mod, pathPtr, pathLen)
	if !ok {
		return errnoEFAULT
	}
	pathUTF16, err := windows.UTF16PtrFromString(string(pathBytes))
	if err != nil {
		return errnoEINVAL
	}

	attrs, err := windows.GetFileAttributes(pathUTF16)
	if err != nil {
		return win32Errno(err)
	}

	if !writeUint32(mod, attrsPtr, attrs) {
		return errnoEFAULT
	}
	return errnoSuccess
}

// win32SetFileAttrs sets file attributes for a path.
func win32SetFileAttrs(ctx context.Context, mod api.Module, pathPtr, pathLen, attrs uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	if pathLen == 0 {
		return errnoEINVAL
	}

	pathBytes, ok := readBytes(mod, pathPtr, pathLen)
	if !ok {
		return errnoEFAULT
	}
	pathUTF16, err := windows.UTF16PtrFromString(string(pathBytes))
	if err != nil {
		return errnoEINVAL
	}

	if err := windows.SetFileAttributes(pathUTF16, attrs); err != nil {
		return win32Errno(err)
	}
	return errnoSuccess
}

// errStopWalk is a sentinel used to break out of filepath.WalkDir early.
var errStopWalk = errors.New("stop walk")

func win32FindFiles(ctx context.Context, mod api.Module, rootPtr, rootLen, patternPtr, patternLen uint32, maxDepth, maxMatches int32, bufPtr, bufCap, countPtr uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	if rootLen == 0 {
		return errnoEINVAL
	}

	rootBytes, ok := readBytes(mod, rootPtr, rootLen)
	if !ok {
		return errnoEFAULT
	}
	root := string(rootBytes)

	var pattern string
	if patternLen > 0 {
		patternBytes, ok := readBytes(mod, patternPtr, patternLen)
		if !ok {
			return errnoEFAULT
		}
		pattern = strings.ToLower(string(patternBytes))
	}

	rootDepth := strings.Count(root, string(os.PathSeparator))

	var matches []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			if errors.Is(werr, fs.ErrPermission) {
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			return nil
		}

		if d.IsDir() {
			if maxDepth >= 0 {
				depth := strings.Count(path, string(os.PathSeparator)) - rootDepth
				if depth > int(maxDepth) {
					return filepath.SkipDir
				}
			}
			return nil
		}

		if pattern != "" {
			base := strings.ToLower(filepath.Base(path))
			// filepath.Match implements the standard FindFirstFileW glob
			// vocabulary: * matches 0+ chars, ? matches one. The previous
			// strings.Contains check only matched bare substrings — so a
			// SharpUp pattern of "*.xml" matched nothing (no filename
			// literally contains the asterisk). Fall back to the substring
			// behaviour if the pattern doesn't parse as a glob.
			matched, mErr := filepath.Match(pattern, base)
			if mErr != nil {
				if !strings.Contains(base, pattern) {
					return nil
				}
			} else if !matched {
				return nil
			}
		}

		matches = append(matches, path)
		if maxMatches > 0 && int32(len(matches)) >= maxMatches {
			return errStopWalk
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStopWalk) {
		// Non-fatal walk errors: proceed with whatever we collected.
	}

	// Write count.
	if !writeUint32(mod, countPtr, uint32(len(matches))) {
		return errnoEFAULT
	}

	if len(matches) == 0 {
		return 0
	}

	// Encode paths as NUL-terminated bytes. We append a trailing NUL on
	// EVERY entry (not just separators) because the WfFs.FindFiles C#
	// parser only adds an entry when it sees a NUL — without a terminator
	// on the last (or only) match, that final entry is silently dropped.
	var buf []byte
	for _, m := range matches {
		buf = append(buf, []byte(m)...)
		buf = append(buf, 0)
	}

	if uint32(len(buf)) > bufCap {
		// Truncate to capacity.
		buf = buf[:bufCap]
	}

	if !writeBytes(mod, bufPtr, buf) {
		return errnoEFAULT
	}
	return uint32(len(buf))
}
