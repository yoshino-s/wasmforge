// Package dotnet is a placeholder for build-pipeline regression tests.
// The actual scripts live in this directory; this Go file only exists so
// `go test ./...` exercises the pipeline contract below.
package dotnet

import (
	"os"
	"strings"
	"testing"
)

// TestBuildScriptsRunCSharpPatcherBeforePublish asserts that every NativeAOT
// build script in this directory invokes `wasmforge dotnet-patch` BEFORE
// `dotnet publish`. Skipping the patch step silently produces binaries with
// unpatched identity calls (Environment.UserName, WindowsIdentity.GetCurrent
// ().Name, etc.) that all return WASI defaults like "Browser" instead of the
// real host user — which silently breaks Seatbelt OSInfo, LocalUsers,
// UserRightAssignments and Rubeus klist output.
//
// Real failure: in this codebase prior to commit (TBD), Seatbelt parity
// dropped from 28/28 to 18/28 because the build pipeline never ran the
// patcher; the user-visible bug was 'Username: Browser' across many verbs.
// This test prevents that exact regression.
func TestBuildScriptsRunCSharpPatcherBeforePublish(t *testing.T) {
	for _, script := range []string{"build.sh", "ludus_build.sh"} {
		t.Run(script, func(t *testing.T) {
			data, err := os.ReadFile(script)
			if err != nil {
				t.Fatalf("read %s: %v", script, err)
			}
			// Walk line by line so leading '#' comments don't count as
			// command invocations (build.sh's header mentions both verbs
			// long before the script actually runs anything).
			var patchLine, publishLine int
			for i, line := range strings.Split(string(data), "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "#") {
					continue
				}
				if patchLine == 0 && strings.Contains(line, "dotnet-patch") {
					patchLine = i + 1
				}
				if publishLine == 0 && strings.Contains(line, "dotnet publish") {
					publishLine = i + 1
				}
			}
			if patchLine == 0 {
				t.Errorf("%s does not invoke wasmforge dotnet-patch — NativeAOT identity calls "+
					"will not be redirected through WfOsInfo and will return WASI defaults (e.g., 'Browser'). "+
					"Add a 'dotnet-patch \"$PROJECT_DIR\"' step before 'dotnet publish'.", script)
				return
			}
			if publishLine == 0 {
				t.Skipf("%s does not run dotnet publish — ordering check N/A", script)
				return
			}
			if patchLine >= publishLine {
				t.Errorf("%s invokes dotnet-patch AFTER dotnet publish (lines: patch=%d, publish=%d). "+
					"The patcher must run BEFORE publish so the C# source is transformed before the compiler sees it.",
					script, patchLine, publishLine)
			}
		})
	}
}
