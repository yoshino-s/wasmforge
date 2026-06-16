// Package helpers tests are Go-level source-presence assertions over
// the C# WASI helpers in this directory. They lock in invariants that
// can't be expressed in C# alone (cross-file, cross-language, or
// behaviour-against-host-side-implementation properties).
package helpers

import (
	"os"
	"strings"
	"testing"
)

// TestWfWmiQuery_CallsCoSetProxyBlanket guards the guest-side WMI
// implementation against the exact runtime crash that hits Seatbelt
// AntiVirus and WMIEventConsumer: when WfWmi.Query connects to a
// restricted namespace (root\SecurityCenter2, ROOT\Subscription),
// the IWbemServices proxy keeps its default authn/imp posture and
// fires IUnknown auth callbacks during ExecQuery. Those callbacks
// re-enter the WASM via host function pointers, which corrupts the
// Go runtime's syscall accounting and crashes with
//
//	fatal error: exitsyscall: syscall frame is no longer valid
//
// Setting RPC_C_AUTHN_LEVEL_CALL + RPC_C_IMP_LEVEL_IMPERSONATE on the
// proxy via ole32!CoSetProxyBlanket suppresses the callbacks. The
// host-side implementation in internal/hostmod/nativeaot_wmi_windows.go
// already does this; the guest path must do the same.
func TestWfWmiQuery_CallsCoSetProxyBlanket(t *testing.T) {
	src, err := os.ReadFile("WfWmi.cs")
	if err != nil {
		t.Fatalf("read WfWmi.cs: %v", err)
	}
	body := string(src)

	// Find the Query method body. We require the call to happen INSIDE
	// Query (after ConnectServer), not just somewhere in the file.
	queryStart := strings.Index(body, "public static List<Dictionary<string, object>> Query(")
	if queryStart < 0 {
		t.Fatalf("WfWmi.cs no longer defines a Query method matching the expected signature; update this test if the API shape changed")
	}
	// End at the next public static (the next entry point in the file)
	// or end-of-file.
	tail := body[queryStart:]
	queryEnd := strings.Index(tail[1:], "\n        public static")
	if queryEnd < 0 {
		queryEnd = len(tail)
	} else {
		queryEnd += 1
	}
	queryBody := tail[:queryEnd]

	if !strings.Contains(queryBody, "CoSetProxyBlanket") {
		t.Errorf("WfWmi.Query does not call CoSetProxyBlanket. The host-side win32_wmi_query_restricted "+
			"implementation (internal/hostmod/nativeaot_wmi_windows.go) calls CoSetProxyBlanket(pSvc, "+
			"RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, NULL, RPC_C_AUTHN_LEVEL_CALL, "+
			"RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE) on the IWbemServices proxy after "+
			"ConnectServer returns. The guest WfWmi.Query must do the same; otherwise WMI queries against "+
			"restricted namespaces (root\\SecurityCenter2, ROOT\\Subscription) trigger IUnknown auth "+
			"callbacks that re-enter the WASM and crash the Go runtime with "+
			"'exitsyscall: syscall frame is no longer valid'.\n\nMethod body excerpt:\n%s",
			truncate(queryBody, 800))
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "... [truncated]"
}
