package compile

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/praetorian-inc/wasmforge/internal/patch"
	"github.com/praetorian-inc/wasmforge/internal/patch/rules"
)

// Config controls the C# → WASM compilation pipeline.
type Config struct {
	SourceDir  string // Project directory containing .csproj
	OutputDir  string // Temp directory for intermediate files
	BridgeDir  string // Path to dotnet/bridge/ (auto-detected if empty)
	HelpersDir string // Path to dotnet/helpers/ (auto-detected if empty)
	StubsDir   string // Path to dotnet/stubs/ (auto-detected if empty)
	Verbose    bool
}

// Result holds the output of a successful C# compilation.
type Result struct {
	WASMPath string // Path to the final linked .wasm file
}

// CompileCSharpToWASM runs the full C# → WASM pipeline.
func CompileCSharpToWASM(cfg Config) (*Result, error) {
	absSource, err := filepath.Abs(cfg.SourceDir)
	if err != nil {
		return nil, fmt.Errorf("resolving source dir: %w", err)
	}

	// Auto-detect dotnet asset directories
	if cfg.BridgeDir == "" || cfg.HelpersDir == "" || cfg.StubsDir == "" {
		root, err := findModuleRoot()
		if err != nil {
			return nil, fmt.Errorf("cannot find wasmforge source tree (needed for dotnet/ assets): %w", err)
		}
		if cfg.BridgeDir == "" {
			cfg.BridgeDir = filepath.Join(root, "dotnet", "bridge")
		}
		if cfg.HelpersDir == "" {
			cfg.HelpersDir = filepath.Join(root, "dotnet", "helpers")
		}
		if cfg.StubsDir == "" {
			cfg.StubsDir = filepath.Join(root, "dotnet", "stubs")
		}
	}

	logf(cfg.Verbose, "C# → WASM compilation: %s", absSource)

	// Step 1: Copy helpers into project (idempotent)
	if err := injectHelpers(absSource, cfg.HelpersDir, cfg.Verbose); err != nil {
		return nil, fmt.Errorf("injecting helpers: %w", err)
	}

	// Step 1.5: Copy stub projects (idempotent)
	if err := injectStubs(absSource, cfg.StubsDir, cfg.Verbose); err != nil {
		return nil, fmt.Errorf("injecting stubs: %w", err)
	}

	// Step 2: Apply C# source patches
	n, _, err := patch.ApplyCSharpASTPatches(absSource, rules.AllNativeAOTASTRules(), cfg.Verbose)
	if err != nil {
		return nil, fmt.Errorf("applying C# patches: %w", err)
	}
	logf(cfg.Verbose, "applied %d C# patches", n)

	// Step 3: Compile C bridge objects
	bridgeObj, pinvokeObj, err := compileBridge(cfg.BridgeDir, cfg.OutputDir, cfg.Verbose)
	if err != nil {
		return nil, fmt.Errorf("compiling C bridge: %w", err)
	}

	// Step 4: dotnet publish
	wasmFile, err := dotnetPublish(absSource, cfg.Verbose)
	if err != nil {
		return nil, fmt.Errorf("dotnet publish: %w", err)
	}
	logf(cfg.Verbose, "WASM output: %s", wasmFile)

	// Step 5: Re-link with bridge objects
	outputWasm := filepath.Join(cfg.OutputDir, "linked.wasm")
	if err := relinkWithBridge(wasmFile, bridgeObj, pinvokeObj, outputWasm, cfg.Verbose); err != nil {
		// Non-fatal fallback: use unlinked WASM directly
		logf(cfg.Verbose, "wasm-ld re-link failed (%v), using dotnet output directly", err)
		outputWasm = wasmFile
	}

	return &Result{WASMPath: outputWasm}, nil
}

// findModuleRoot walks up from the current working directory looking for a
// go.mod that declares the wasmforge module. Returns the directory containing
// go.mod, or an error if not found.
func findModuleRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getting working directory: %w", err)
	}
	current := wd
	for {
		gomod := filepath.Join(current, "go.mod")
		data, err := os.ReadFile(gomod)
		if err == nil && strings.Contains(string(data), "github.com/praetorian-inc/wasmforge") {
			return current, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return "", fmt.Errorf("WasmForge module root not found (no go.mod with github.com/praetorian-inc/wasmforge above %s)", wd)
}

// injectHelpers creates a WasmForge/ subdirectory in projectDir and copies the
// four helper .cs files from helpersDir into it. Existing files are skipped
// (idempotent).
func injectHelpers(projectDir, helpersDir string, verbose bool) error {
	wfDir := filepath.Join(projectDir, "WasmForge")
	if err := os.MkdirAll(wfDir, 0755); err != nil {
		return fmt.Errorf("creating WasmForge/ directory: %w", err)
	}

	names := []string{
		"WfHostBridge.cs",
		"LsaHostHelper.cs",
		"CryptoHostHelper.cs",
		"NetworkHostHelper.cs",
	}

	for _, name := range names {
		dst := filepath.Join(wfDir, name)
		if _, err := os.Stat(dst); err == nil {
			logf(verbose, "helper already present: %s", name)
			continue
		}
		src := filepath.Join(helpersDir, name)
		if err := copyFile(src, dst); err != nil {
			return fmt.Errorf("copying helper %s: %w", name, err)
		}
		logf(verbose, "injected helper: %s", name)
	}
	return nil
}

// injectStubs creates a stubs/ subdirectory in projectDir and recursively
// copies stub project directories from stubsDir. Existing directories are
// skipped (idempotent).
func injectStubs(projectDir, stubsDir string, verbose bool) error {
	targetStubsDir := filepath.Join(projectDir, "stubs")

	entries, err := os.ReadDir(stubsDir)
	if err != nil {
		return fmt.Errorf("reading stubs directory %s: %w", stubsDir, err)
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dst := filepath.Join(targetStubsDir, e.Name())
		if _, err := os.Stat(dst); err == nil {
			logf(verbose, "stub already present: %s", e.Name())
			continue
		}
		src := filepath.Join(stubsDir, e.Name())
		if err := copyDir(src, dst); err != nil {
			return fmt.Errorf("copying stub %s: %w", e.Name(), err)
		}
		logf(verbose, "copied stub: %s", e.Name())
	}
	return nil
}

// compileBridge compiles the two C bridge source files (wf_bridge.c and
// pinvoke_nativeaot.c) using the WASI clang toolchain. Returns paths to the
// two resulting object files.
func compileBridge(bridgeDir, outputDir string, verbose bool) (bridgeObj, pinvokeObj string, err error) {
	clang, err := findWASIClang()
	if err != nil {
		return "", "", fmt.Errorf("finding WASI clang: %w", err)
	}

	bridgeObj = filepath.Join(outputDir, "wf_bridge.o")
	pinvokeObj = filepath.Join(outputDir, "pinvoke_nativeaot.o")

	bridgeSrc := filepath.Join(bridgeDir, "wf_bridge.c")
	if err := runCmd(verbose, clang,
		"--target=wasm32-wasi", "-O2", "-c", bridgeSrc,
		"-o", bridgeObj,
		"-I", bridgeDir,
	); err != nil {
		return "", "", fmt.Errorf("compiling wf_bridge.c: %w", err)
	}
	logf(verbose, "compiled bridge object: %s", bridgeObj)

	pinvokeSrc := filepath.Join(bridgeDir, "pinvoke_nativeaot.c")
	if err := runCmd(verbose, clang,
		"--target=wasm32-wasi", "-O2", "-c", pinvokeSrc,
		"-o", pinvokeObj,
		"-I", bridgeDir,
	); err != nil {
		return "", "", fmt.Errorf("compiling pinvoke_nativeaot.c: %w", err)
	}
	logf(verbose, "compiled pinvoke object: %s", pinvokeObj)

	return bridgeObj, pinvokeObj, nil
}

// dotnetPublish runs `dotnet publish` on the project directory targeting
// wasi-wasm. It returns the path to the resulting .wasm file.
func dotnetPublish(sourceDir string, verbose bool) (string, error) {
	args := []string{"publish", sourceDir, "-c", "Release", "-r", "wasi-wasm"}

	cmd := exec.Command("dotnet", args...)
	if verbose {
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
	}

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("dotnet publish: %w", err)
	}

	// Find the .wasm file under <sourceDir>/bin/Release/*/wasi-wasm/native/
	pattern := filepath.Join(sourceDir, "bin", "Release", "*", "wasi-wasm", "native", "*.wasm")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return "", fmt.Errorf("globbing for wasm output: %w", err)
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("no .wasm file found under %s/bin/Release/*/wasi-wasm/native/", sourceDir)
	}
	return matches[0], nil
}

// relinkWithBridge uses wasm-ld to combine the dotnet publish output WASM
// with the compiled C bridge objects.
func relinkWithBridge(wasmFile, bridgeObj, pinvokeObj, output string, verbose bool) error {
	wasmld, err := findWASMLD()
	if err != nil {
		return fmt.Errorf("finding wasm-ld: %w", err)
	}

	return runCmd(verbose, wasmld,
		wasmFile, bridgeObj, pinvokeObj,
		"-o", output,
		"--export-all",
		"--allow-undefined",
	)
}

// findWASIClang locates the WASI clang compiler. It checks in order:
//  1. $WASI_SDK_PATH/bin/clang
//  2. $WASI_CLANG environment variable
//  3. clang on PATH
func findWASIClang() (string, error) {
	if sdkPath := os.Getenv("WASI_SDK_PATH"); sdkPath != "" {
		candidate := filepath.Join(sdkPath, "bin", "clang")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	if wc := os.Getenv("WASI_CLANG"); wc != "" {
		return wc, nil
	}
	path, err := exec.LookPath("clang")
	if err != nil {
		return "", fmt.Errorf("clang not found (set WASI_SDK_PATH or WASI_CLANG): %w", err)
	}
	return path, nil
}

// findWASMLD locates the wasm-ld linker. It checks in order:
//  1. $WASI_SDK_PATH/bin/wasm-ld
//  2. wasm-ld on PATH
func findWASMLD() (string, error) {
	if sdkPath := os.Getenv("WASI_SDK_PATH"); sdkPath != "" {
		candidate := filepath.Join(sdkPath, "bin", "wasm-ld")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	path, err := exec.LookPath("wasm-ld")
	if err != nil {
		return "", fmt.Errorf("wasm-ld not found (set WASI_SDK_PATH): %w", err)
	}
	return path, nil
}

// runCmd executes a command, optionally streaming output to stderr.
func runCmd(verbose bool, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if verbose {
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
	}
	return cmd.Run()
}

// logf prints a progress message to stderr when verbose is true.
func logf(verbose bool, format string, args ...interface{}) {
	if verbose {
		fmt.Fprintf(os.Stderr, "[compile] "+format+"\n", args...)
	}
}

// copyFile copies src to dst, creating dst's parent directories as needed.
// If dst already exists it is overwritten.
func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

// copyDir recursively copies all files from srcDir into dstDir, preserving
// relative paths. dstDir is created if it does not exist.
func copyDir(srcDir, dstDir string) error {
	return filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		dst := filepath.Join(dstDir, rel)
		if d.IsDir() {
			return os.MkdirAll(dst, 0755)
		}
		return copyFile(path, dst)
	})
}

