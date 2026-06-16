//go:build windows

package hostmod

import "testing"

// TestPointerMaskCoverage checks which commonly-used Win32 APIs have explicit
// pointer masks vs. falling through to the heuristic. This is informational:
// the test never fails, because some APIs legitimately have all-scalar params
// and will never appear in generatedPointerMasks.
//
// Run on Windows to get accurate results:
//
//	GOWORK=off go test -v -run TestPointerMaskCoverage ./internal/hostmod/
func TestPointerMaskCoverage(t *testing.T) {
	// Common Win32 APIs used by offensive tools and security research.
	commonAPIs := []string{
		// Virtual memory
		"VirtualAlloc", "VirtualAllocEx", "VirtualFree", "VirtualFreeEx",
		"VirtualProtect", "VirtualProtectEx", "VirtualQuery", "VirtualQueryEx",

		// Cross-process memory
		"WriteProcessMemory", "ReadProcessMemory",

		// Remote thread creation
		"CreateRemoteThread", "CreateRemoteThreadEx",

		// Process / token
		"OpenProcess", "OpenProcessToken", "GetTokenInformation",

		// File I/O
		"CreateFileW", "ReadFile", "WriteFile", "CloseHandle",

		// Library loading
		"LoadLibraryExW", "GetProcAddress", "FreeLibrary",
		"GetModuleHandleW", "GetModuleFileNameW",

		// Process management
		"CreateProcessW", "TerminateProcess",

		// Registry
		"RegOpenKeyExW", "RegQueryValueExW", "RegCloseKey",

		// Heap
		"HeapAlloc", "HeapFree", "HeapCreate",

		// Current process identity
		"GetCurrentProcess", "GetCurrentProcessId",

		// System info
		"GetComputerNameW", "GetUserNameW",

		// COM / CLR
		"CLRCreateInstance",

		// Nt* direct-syscall equivalents
		"NtAllocateVirtualMemory", "NtProtectVirtualMemory",
		"NtCreateThreadEx", "NtMapViewOfSection",
		"NtOpenProcess", "NtQueryInformationProcess",
		"NtQuerySystemInformation",
	}

	var withMask, missing []string
	for _, api := range commonAPIs {
		if _, ok := getPointerMask(api); ok {
			withMask = append(withMask, api)
		} else {
			missing = append(missing, api)
		}
	}

	if len(missing) > 0 {
		t.Logf("APIs without pointer masks (%d/%d) — heuristic fallback:", len(missing), len(commonAPIs))
		for _, api := range missing {
			t.Logf("  - %s", api)
		}
	}
	t.Logf("Coverage: %d/%d APIs have explicit pointer masks", len(withMask), len(commonAPIs))
}
