//go:build nativeaot && windows

package hostmod

import (
	"context"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/tetratelabs/wazero/api"
	"golang.org/x/sys/windows"
)

// win32ProcModulesEnum enumerates all loaded modules across all accessible
// processes via CreateToolhelp32Snapshot. Wire format: one line per module
// formatted as "pid\tprocessName\tmodulePath\n". Empty lines are skipped by
// the C# consumer. Used by SharpUp's ProcessDLLHijack check to find writable
// DLL load paths outside C:\Windows.
//
// Module enumeration on x64 Windows uses TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32
// to capture both 32-bit and 64-bit modules. Process snapshot failures (typically
// "access denied" on protected processes) are silently skipped — we emit what
// we can. Matches Process.GetProcesses + p.Modules iteration in the BCL.
func win32ProcModulesEnum(ctx context.Context, mod api.Module, outBufPtr, outBufLen uint32) uint32 {
	const (
		th32csSnapProcess    = 0x00000002
		th32csSnapModule     = 0x00000008
		th32csSnapModule32   = 0x00000010
		maxPath              = 260
		invalidHandle uint32 = 0xFFFFFFFF
	)
	type processEntry32W struct {
		dwSize              uint32
		cntUsage            uint32
		th32ProcessID       uint32
		th32DefaultHeapID   uintptr
		th32ModuleID        uint32
		cntThreads          uint32
		th32ParentProcessID uint32
		pcPriClassBase      int32
		dwFlags             uint32
		szExeFile           [maxPath]uint16
	}
	type moduleEntry32W struct {
		dwSize        uint32
		th32ModuleID  uint32
		th32ProcessID uint32
		GlblcntUsage  uint32
		ProccntUsage  uint32
		modBaseAddr   uintptr
		modBaseSize   uint32
		hModule       uintptr
		szModule      [256]uint16
		szExePath     [maxPath]uint16
	}

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	pSnap := kernel32.NewProc("CreateToolhelp32Snapshot")
	pProc32First := kernel32.NewProc("Process32FirstW")
	pProc32Next := kernel32.NewProc("Process32NextW")
	pMod32First := kernel32.NewProc("Module32FirstW")
	pMod32Next := kernel32.NewProc("Module32NextW")
	pCloseHandle := kernel32.NewProc("CloseHandle")

	snap, _, _ := pSnap.Call(uintptr(th32csSnapProcess), 0)
	if snap == 0 || snap == ^uintptr(0) {
		fmt.Fprintf(os.Stderr, "[runtime] win32ProcModulesEnum: process snapshot failed\n")
		return 0
	}
	defer pCloseHandle.Call(snap)

	var sb strings.Builder
	var pe processEntry32W
	pe.dwSize = uint32(unsafe.Sizeof(pe))
	ret, _, _ := pProc32First.Call(snap, uintptr(unsafe.Pointer(&pe)))
	for ret != 0 {
		pid := pe.th32ProcessID
		procName := windows.UTF16ToString(pe.szExeFile[:])

		// PID 0 (System Idle) and 4 (System) have no enumerable modules.
		if pid > 4 {
			modSnap, _, _ := pSnap.Call(uintptr(th32csSnapModule|th32csSnapModule32), uintptr(pid))
			if modSnap != 0 && modSnap != ^uintptr(0) {
				var me moduleEntry32W
				me.dwSize = uint32(unsafe.Sizeof(me))
				mret, _, _ := pMod32First.Call(modSnap, uintptr(unsafe.Pointer(&me)))
				for mret != 0 {
					path := windows.UTF16ToString(me.szExePath[:])
					if path != "" {
						sb.WriteString(fmt.Sprintf("%d\t%s\t%s\n", pid, procName, path))
					}
					me.dwSize = uint32(unsafe.Sizeof(me))
					mret, _, _ = pMod32Next.Call(modSnap, uintptr(unsafe.Pointer(&me)))
				}
				pCloseHandle.Call(modSnap)
			}
			// Module snapshot failure (access denied) — silently skip this process.
		}

		pe.dwSize = uint32(unsafe.Sizeof(pe))
		ret, _, _ = pProc32Next.Call(snap, uintptr(unsafe.Pointer(&pe)))
	}

	data := sb.String()
	if uint32(len(data)) > outBufLen {
		// Truncate to last newline within buffer to keep parsing intact.
		cut := int(outBufLen)
		if cut > len(data) {
			cut = len(data)
		}
		for cut > 0 && data[cut-1] != '\n' {
			cut--
		}
		data = data[:cut]
	}
	if !writeBytes(mod, outBufPtr, []byte(data)) {
		return 0
	}
	return uint32(len(data))
}
