// Command dotnet-runner executes a .NET WASM module (dotnet.wasm) inside
// WasmForge's wazero runtime with full Win32 API support. On Windows hosts
// the Win32 P/Invoke bridge connects to real DLLs; on macOS/Linux the host
// functions return graceful errors so managed .NET code still runs.
//
// Usage:
//
//	dotnet-runner [-managed <dir>] <dotnet.wasm> [assembly-name] [args...]
//
// Mono looks for "managed/Seatbelt.dll" relative to "/", so the directory
// containing managed/ is mounted at "/". All host drive letters are
// auto-mounted on Windows (C: → /c, etc.).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	wfruntime "github.com/praetorian-inc/wasmforge/internal/runtime"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "dotnet-runner: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("dotnet-runner", flag.ContinueOnError)
	managedFlag := fs.String("managed", "", "explicit path to the managed/ directory containing .NET assemblies")
	if err := fs.Parse(args); err != nil {
		return err
	}

	positional := fs.Args()
	if len(positional) == 0 {
		return fmt.Errorf("usage: dotnet-runner [-managed <dir>] <dotnet.wasm> [assembly-name] [args...]")
	}

	wasmPath := positional[0]
	restArgs := positional[1:]

	// Read the WASM file.
	wasmData, err := os.ReadFile(wasmPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", wasmPath, err)
	}

	fmt.Fprintf(os.Stderr, "dotnet-runner: loaded %s (%d bytes)\n", wasmPath, len(wasmData))

	// Discover the publish directory (directory containing dotnet.wasm).
	publishDir := filepath.Dir(wasmPath)

	// Build the argv for dotnet.wasm.
	// .NET WASI expects: ["dotnet.wasm", assembly-name, extra-args...]
	wasmArgs := make([]string, 0, 1+len(restArgs))
	wasmArgs = append(wasmArgs, "dotnet.wasm")
	wasmArgs = append(wasmArgs, restArgs...)

	// Discover the managed/ directory.
	// Mono looks for "managed/Seatbelt.dll" relative to "/", so the directory
	// that contains managed/ must be mounted at "/".
	managedDir, err := findManagedDir(*managedFlag, publishDir)
	if err != nil {
		return err
	}

	// Determine what to mount at "/".
	// If we found managed/, mount its parent so that "managed/" is visible at "/managed/".
	// If the WASM file is not under the mounted root, add a second mount for it.
	fsMounts := buildFSMounts(managedDir, publishDir)

	// Build environment: pass through host env, filtering Windows drive-dir
	// entries (e.g., "=C:=C:\Windows") which have an empty key and are
	// rejected by wazero's WithEnv.
	env := make([]string, 0, len(os.Environ()))
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "=") {
			continue
		}
		env = append(env, e)
	}

	// Enable platform-appropriate host APIs.
	win32APIs := runtime.GOOS == "windows"
	darwinAPIs := runtime.GOOS == "darwin"

	// Tell the .NET WASI guest that WasmForge Win32 bridge is available.
	// Commands guard P/Invoke code behind WASMFORGE_WIN32 to avoid Mono abort on macOS.
	if win32APIs {
		env = append(env, "WASMFORGE_WIN32=1")
	}

	fmt.Fprintf(os.Stderr, "dotnet-runner: win32=%v darwin=%v\n", win32APIs, darwinAPIs)

	cfg := &wfruntime.Config{
		WASMData:   wasmData,
		Args:       wasmArgs,
		Env:        env,
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
		Stdin:      os.Stdin,
		Win32APIs:  win32APIs,
		DarwinAPIs: darwinAPIs,
		FSMounts:   fsMounts,
	}

	ctx := context.Background()
	if err := wfruntime.Run(ctx, cfg); err != nil {
		return err
	}

	return nil
}

// findManagedDir returns the path to the managed/ directory of .NET assemblies.
// If managedFlag is non-empty it is used directly. Otherwise the function
// searches a set of candidate locations relative to publishDir.
func findManagedDir(managedFlag, publishDir string) (string, error) {
	if managedFlag != "" {
		info, err := os.Stat(managedFlag)
		if err != nil {
			return "", fmt.Errorf("managed directory %q: %w", managedFlag, err)
		}
		if !info.IsDir() {
			return "", fmt.Errorf("managed path %q is not a directory", managedFlag)
		}
		fmt.Fprintf(os.Stderr, "dotnet-runner: using managed/ at %s (from -managed flag)\n", managedFlag)
		return managedFlag, nil
	}

	// Auto-discovery: check common dotnet publish output layouts.
	candidates := []string{
		filepath.Join(publishDir, "managed"),
		filepath.Join(publishDir, "..", "AppBundle", "managed"),
		filepath.Join(publishDir, "..", "managed"),
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			abs, err := filepath.Abs(candidate)
			if err != nil {
				abs = candidate
			}
			fmt.Fprintf(os.Stderr, "dotnet-runner: found managed/ at %s\n", abs)
			return abs, nil
		}
	}

	fmt.Fprintf(os.Stderr, "dotnet-runner: managed/ not found, falling back to publishDir mount\n")
	return "", nil
}

// buildFSMounts constructs the list of filesystem mounts for the wazero runtime.
// WasmForge's runtime.Run() auto-mounts "/" on macOS/Linux and drive letters on
// Windows, so we only need to mount managed/ at "/managed" explicitly. Mono's
// MONO_PATH includes "/managed" and the entrypoint references "managed/Seatbelt.dll".
func buildFSMounts(managedDir, publishDir string) []string {
	var fsMounts []string

	if managedDir != "" {
		// Mount the managed directory at /managed so Mono can find assemblies.
		// WasmForge's auto-mount of "/" handles everything else (the host root
		// is visible to the guest, but /managed on the host doesn't exist).
		fsMounts = append(fsMounts, managedDir+":/managed")
		fmt.Fprintf(os.Stderr, "dotnet-runner: mounting %s at /managed\n", managedDir)
	}

	return fsMounts
}
