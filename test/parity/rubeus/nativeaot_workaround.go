// Package rubeus exposes per-tool helpers shared by rubeus_parity_test.go
// and capture-baseline.
//
// PrepareArgs applies a NativeAOT-WASI workaround to a case's Args slice
// before they reach the lab. This keeps cases.go aligned with what a real
// attacker would type at a Rubeus prompt, while the test framework owns
// the framework-level quirk required to make the binary actually run.
//
// Background
//
// wasmforge-built Rubeus.exe silently exits before Program.Main when argv
// contains specific Kerberos verb names (asktgt, asktgs, kerberoast,
// asreproast) immediately followed by a /-prefix argument. The trigger
// lives in NativeAOT-LLVM runtime initialization that runs after WASI
// args_get but before managed Main. It is invariant to:
//
//   - Host-side argv injection at the wasmforge runtime layer (proven via
//     debug-instrumented build: byte-identical cfg.Args reaching WASI
//     produces working-vs-broken WASM behavior depending on whether the
//     sentinel arrived via Windows CommandLine parsing or via Go literal
//     injection).
//   - Stripping System.Security.Cryptography.Pkcs from the Rubeus class
//     graph (rebuild + retest produced the same silent-exit pattern).
//   - Removing the failing-verb class files entirely (mini-rubeus repro
//     does not reproduce the bug).
//
// The only mitigation that empirically works is inserting any non-/-prefix
// token at argv index 2 via the Windows command line itself (i.e. the host
// command "rubeus.exe asktgt WF_RUN /user:..." reaches the WASM with a
// working argv layout that "rubeus.exe asktgt /user:..." does not).
//
// Process-respawn was attempted as a transparent fix (parent detects the
// pattern, re-execs itself with WF_RUN inserted so the child's argv arrives
// via Windows CommandLine parsing). It hits a second, independent silent-
// exit: wazero's CompileModule call silently terminates in any child
// process spawned from a Go binary, even though the same binary
// invoked directly from the shell compiles fine. Verified via marker
// files: child reaches runtime.Run, prints "about to compile WASM",
// then exits with code 0 producing no further output. Likely cause is
// PROCESS_MITIGATION_DYNAMIC_CODE_POLICY (or similar) inherited from the
// Go parent that blocks wazero's JIT executable-memory allocation. So
// respawn just trades the original bug for a different one — the test
// framework wrapper is the architecturally correct placement.
//
// PrepareArgs achieves that by appending "WF_RUN" between the verb and the
// first /-arg in the host invocation. The C# source patcher
// (internal/patch/csharp_patcher.go) strips the WF_RUN token from
// args[] inside Program.Main, so Rubeus's ArgumentParser sees the original
// args a real user would have typed.
//
// For other C# projects that hit this NativeAOT-WASI trigger, the same
// pattern applies: add a per-project sentinel both to the test runner's
// PrepareArgs (or equivalent) and to a one-line strip rule in the C#
// patcher. The wasmforge runtime layer cannot fix this transparently.
package rubeus

// failingVerbs are the Rubeus verbs that trigger the NativeAOT-WASI
// pre-Main silent-exit when immediately followed by a /-prefix arg.
var failingVerbs = map[string]bool{
	"asktgt":     true,
	"asktgs":     true,
	"kerberoast": true,
	"asreproast": true,
}

// PrepareArgs returns args with a "WF_RUN" sentinel inserted between a
// failing-verb token and an adjacent /-prefix argument. Returns args
// unchanged when the trigger pattern is not present.
//
// Both the parity test runner and capture-baseline call this helper before
// invoking the lab binary, so cases.go can describe what an attacker would
// actually type without having to encode framework-level quirks.
func PrepareArgs(args []string) []string {
	for i := 0; i < len(args)-1; i++ {
		if failingVerbs[args[i]] && len(args[i+1]) > 0 && args[i+1][0] == '/' {
			out := make([]string, 0, len(args)+1)
			out = append(out, args[:i+1]...)
			out = append(out, "WF_RUN")
			out = append(out, args[i+1:]...)
			return out
		}
	}
	return args
}
