// Package migrate automates the migration of .NET Framework C# projects
// (e.g. GhostPack/Seatbelt, GhostPack/Rubeus) to .NET 10 NativeAOT-WASI for
// use with the WasmForge pipeline.
//
// Run() performs the following idempotent steps:
//  1. Discover the .csproj and auto-detect the project name.
//  2. Auto-detect WasmForge helper/stub/bridge directories from the module root,
//     or use the paths provided in Config.
//  3. Backup the original .csproj as .csproj.framework-backup.
//  4. Generate a new .NET 10 NativeAOT .csproj using GenerateCsproj().
//  5. Inject the four WasmForge helper .cs files into WasmForge/.
//  6. Copy the four stub projects into stubs/.
//  7. Copy the bridge/ directory (wf_bridge.c, wf_bridge.h, pinvoke_nativeaot.c).
//  8. Write nuget.config referencing the dotnet-experimental NuGet feed.
//  9. Apply C# source patches via patch.ApplyCSharpASTPatches().
package migrate

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/praetorian-inc/wasmforge/internal/patch"
	"github.com/praetorian-inc/wasmforge/internal/patch/rules"
)

// Config controls the migration of a .NET Framework project.
type Config struct {
	// SourceDir is the root directory of the .NET Framework project.
	SourceDir string

	// ProjectName overrides the name auto-detected from the .csproj.
	// If empty, Run() parses <AssemblyName> or <RootNamespace> from the .csproj.
	ProjectName string

	// BridgeDir is the path to dotnet/bridge/. When empty, Run() walks up from
	// the working directory looking for the WasmForge module root.
	BridgeDir string

	// HelpersDir is the path to dotnet/helpers/. Same auto-detection as BridgeDir.
	HelpersDir string

	// StubsDir is the path to dotnet/stubs/. Same auto-detection as BridgeDir.
	StubsDir string

	// ExtraPackages are additional NuGet packages to include beyond the defaults
	// returned by DefaultNuGetPackages().
	ExtraPackages []NuGetRef

	// Verbose enables progress messages written to stderr.
	Verbose bool
}

// Result reports what Run() did.
type Result struct {
	// CsprojPath is the path to the newly-generated .csproj file.
	CsprojPath string

	// OriginalCsproj is the path to the .csproj.framework-backup file.
	OriginalCsproj string

	// InjectedHelpers lists the helper .cs files that were copied into WasmForge/.
	InjectedHelpers []string

	// PatchesApplied is the count returned by patch.ApplyCSharpASTPatches.
	PatchesApplied int
}

var (
	assemblyNameRe  = regexp.MustCompile(`<AssemblyName>([^<]+)</AssemblyName>`)
	rootNamespaceRe = regexp.MustCompile(`<RootNamespace>([^<]+)</RootNamespace>`)
)

// detectProjectName parses the raw .csproj XML content for AssemblyName or
// RootNamespace, preferring AssemblyName when both are present.
func detectProjectName(content string) string {
	if m := assemblyNameRe.FindStringSubmatch(content); len(m) == 2 {
		return strings.TrimSpace(m[1])
	}
	if m := rootNamespaceRe.FindStringSubmatch(content); len(m) == 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// findModuleRoot walks up from dir searching for a go.mod that declares the
// wasmforge module. Returns the directory containing go.mod, or an error if
// not found.
func findModuleRoot(dir string) (string, error) {
	current := dir
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
	return "", fmt.Errorf("WasmForge module root not found (no go.mod with github.com/praetorian-inc/wasmforge above %s)", dir)
}

// logf prints a progress message to stderr when verbose is true.
func logf(verbose bool, format string, args ...interface{}) {
	if verbose {
		fmt.Fprintf(os.Stderr, "[migrate] "+format+"\n", args...)
	}
}

// copyFile copies src to dst, creating dst's parent directories as needed.
// If dst already exists it is overwritten.
func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
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

// helperNames are the WasmForge C# helper files to inject.
var helperNames = []string{
	"WfHostBridge.cs",
	"LsaHostHelper.cs",
	"CryptoHostHelper.cs",
	"NetworkHostHelper.cs",
	"WfRegistry.cs",
	"WfFs.cs",
	"WfSidShim.cs",
	"WfReg.cs",
	"WfForge.cs",
	"WfCom.cs",
	"WfWmi.cs",
	"WfEventLog.cs",
}

// stubDirNames are the stub project directories to copy.
var stubDirNames = []string{
	"System.DirectoryServices",
	"System.DirectoryServices.AccountManagement",
	"System.DirectoryServices.ActiveDirectory",
	"System.DirectoryServices.Protocols",
	"System.IdentityModel.Tokens",
	"System.Management",
	"System.Net.NetworkInformation",
	"CERTENROLLLib",
	"CERTCLILib",
}

// Run performs the full .NET Framework → .NET 10 NativeAOT-WASI migration for
// the project at cfg.SourceDir.
func Run(cfg Config) (*Result, error) {
	// ── Step 1: Discover .csproj and detect project name ──────────────
	entries, err := os.ReadDir(cfg.SourceDir)
	if err != nil {
		return nil, fmt.Errorf("reading source directory %s: %w", cfg.SourceDir, err)
	}

	var csprojFile string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".csproj") &&
			!strings.HasSuffix(e.Name(), ".framework-backup") {
			csprojFile = filepath.Join(cfg.SourceDir, e.Name())
			break
		}
	}
	if csprojFile == "" {
		return nil, fmt.Errorf("no .csproj found in %s", cfg.SourceDir)
	}

	csprojData, err := os.ReadFile(csprojFile)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", csprojFile, err)
	}

	projectName := cfg.ProjectName
	if projectName == "" {
		projectName = detectProjectName(string(csprojData))
	}
	if projectName == "" {
		// Fall back to the .csproj filename stem.
		base := filepath.Base(csprojFile)
		projectName = strings.TrimSuffix(base, ".csproj")
	}
	logf(cfg.Verbose, "project name: %s", projectName)

	// ── Step 2: Auto-detect helper/stub/bridge paths ──────────────────
	helpersDir := cfg.HelpersDir
	stubsDir := cfg.StubsDir
	bridgeDir := cfg.BridgeDir

	if helpersDir == "" || stubsDir == "" || bridgeDir == "" {
		wd, wdErr := os.Getwd()
		if wdErr != nil {
			wd = cfg.SourceDir
		}
		root, rootErr := findModuleRoot(wd)
		if rootErr != nil {
			return nil, fmt.Errorf(
				"auto-detection failed (%v); provide HelpersDir, StubsDir, and BridgeDir explicitly", rootErr)
		}
		if helpersDir == "" {
			helpersDir = filepath.Join(root, "dotnet", "helpers")
		}
		if stubsDir == "" {
			stubsDir = filepath.Join(root, "dotnet", "stubs")
		}
		if bridgeDir == "" {
			bridgeDir = filepath.Join(root, "dotnet", "bridge")
		}
	}
	logf(cfg.Verbose, "helpers: %s", helpersDir)
	logf(cfg.Verbose, "stubs:   %s", stubsDir)
	logf(cfg.Verbose, "bridge:  %s", bridgeDir)

	// ── Step 3: Backup original .csproj (idempotent) ──────────────────
	backupPath := csprojFile + ".framework-backup"
	result := &Result{
		CsprojPath:     csprojFile,
		OriginalCsproj: backupPath,
	}

	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		if err := os.Rename(csprojFile, backupPath); err != nil {
			return nil, fmt.Errorf("backing up .csproj: %w", err)
		}
		logf(cfg.Verbose, "backed up original .csproj → %s", filepath.Base(backupPath))
	} else {
		logf(cfg.Verbose, "backup already exists, skipping")
	}

	// ── Step 3.5: Delete AssemblyInfo.cs files (conflict with SDK auto-generation) ──
	filepath.Walk(cfg.SourceDir, func(path string, info os.FileInfo, err error) error { //nolint:errcheck
		if err != nil {
			return nil
		}
		if !info.IsDir() && info.Name() == "AssemblyInfo.cs" {
			os.Remove(path) //nolint:errcheck
			if cfg.Verbose {
				rel, _ := filepath.Rel(cfg.SourceDir, path)
				fmt.Fprintf(os.Stderr, "[migrate] deleted %s (conflicts with SDK-style project)\n", rel)
			}
		}
		return nil
	})

	// ── Step 4: Generate new .csproj ──────────────────────────────────
	packages := DefaultNuGetPackages()
	packages = append(packages, cfg.ExtraPackages...)

	// Build relative paths to stub .csproj files.
	var stubRefs []string
	for _, name := range stubDirNames {
		stubRefs = append(stubRefs, filepath.Join("stubs", name, name+".csproj"))
	}

	csprojGenData := CsprojData{
		ProjectName:     projectName,
		TargetFramework: "net10.0",
		NuGetPackages:   packages,
		StubProjects:    stubRefs,
		AllowUnsafe:     true,
	}
	if err := GenerateCsproj(csprojFile, csprojGenData); err != nil {
		return nil, fmt.Errorf("generating .csproj: %w", err)
	}
	logf(cfg.Verbose, "generated new .csproj at %s", filepath.Base(csprojFile))

	// ── Step 5: Inject helper .cs files into WasmForge/ (idempotent) ──
	wasmforgeDir := filepath.Join(cfg.SourceDir, "WasmForge")
	if err := os.MkdirAll(wasmforgeDir, 0755); err != nil {
		return nil, fmt.Errorf("creating WasmForge/ directory: %w", err)
	}

	for _, name := range helperNames {
		dst := filepath.Join(wasmforgeDir, name)
		if _, err := os.Stat(dst); err == nil {
			logf(cfg.Verbose, "helper already present: %s", name)
			result.InjectedHelpers = append(result.InjectedHelpers, dst)
			continue
		}
		src := filepath.Join(helpersDir, name)
		if err := copyFile(src, dst); err != nil {
			return nil, fmt.Errorf("copying helper %s: %w", name, err)
		}
		logf(cfg.Verbose, "injected helper: %s", name)
		result.InjectedHelpers = append(result.InjectedHelpers, dst)
	}

	// ── Step 6: Copy stub project directories into stubs/ ─────────────
	targetStubsDir := filepath.Join(cfg.SourceDir, "stubs")
	for _, name := range stubDirNames {
		dst := filepath.Join(targetStubsDir, name)
		if _, err := os.Stat(dst); err == nil {
			logf(cfg.Verbose, "stub already present: %s", name)
			continue
		}
		src := filepath.Join(stubsDir, name)
		if err := copyDir(src, dst); err != nil {
			return nil, fmt.Errorf("copying stub %s: %w", name, err)
		}
		logf(cfg.Verbose, "copied stub: %s", name)
	}

	// ── Step 7: Copy bridge/ directory (idempotent) ───────────────────
	targetBridgeDir := filepath.Join(cfg.SourceDir, "bridge")
	if _, err := os.Stat(targetBridgeDir); os.IsNotExist(err) {
		if err := copyDir(bridgeDir, targetBridgeDir); err != nil {
			return nil, fmt.Errorf("copying bridge directory: %w", err)
		}
		logf(cfg.Verbose, "copied bridge directory")
	} else {
		logf(cfg.Verbose, "bridge/ already present, skipping")
	}

	// ── Step 8: Write nuget.config for NativeAOT-LLVM experimental feed ─
	nugetConfigPath := filepath.Join(cfg.SourceDir, "nuget.config")
	if _, err := os.Stat(nugetConfigPath); os.IsNotExist(err) {
		nugetConfig := `<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <add key="dotnet-experimental" value="https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet-experimental/nuget/v3/index.json" />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
</configuration>
`
		if err := os.WriteFile(nugetConfigPath, []byte(nugetConfig), 0644); err != nil {
			return nil, fmt.Errorf("writing nuget.config: %w", err)
		}
		logf(cfg.Verbose, "wrote nuget.config (dotnet-experimental feed)")
	} else {
		logf(cfg.Verbose, "nuget.config already present, skipping")
	}

	// ── Step 9: Apply C# source patches ───────────────────────────────
	n, _, err := patch.ApplyCSharpASTPatches(cfg.SourceDir, rules.AllNativeAOTASTRules(), cfg.Verbose)
	if err != nil {
		return nil, fmt.Errorf("applying C# patches: %w", err)
	}
	result.PatchesApplied = n
	logf(cfg.Verbose, "applied %d C# patches", n)

	// ── Step 10: Emit trim-preservation directives ────────────────────
	// Without this rd.xml NativeAOT trim deletes type/property metadata
	// that the tool relies on for Assembly.GetTypes()/Type.GetProperties()
	// reflection. See internal/patch/rdxml.go for the full rationale.
	if rdPath, rdErr := patch.EmitWfPreserveRdXml(cfg.SourceDir, cfg.Verbose); rdErr != nil {
		return nil, fmt.Errorf("emitting trim directives: %w", rdErr)
	} else {
		logf(cfg.Verbose, "emitted trim directives at %s", rdPath)
	}

	// ── Step 11: Emit DirectPInvoke props from discovered [DllImport]s ─
	// NativeAOT-LLVM rejects lazy P/Invoke resolution at runtime; every
	// DllImport target must be listed as <DirectPInvoke> in the csproj.
	// The scanner walks all .cs files for [DllImport(...)] declarations
	// and writes Properties/WfDirectPInvoke.props with the full set. The
	// csproj template <Import>s the props file conditionally.
	if ppath, dlls, perr := patch.EmitDirectPInvokeProps(cfg.SourceDir, cfg.Verbose); perr != nil {
		return nil, fmt.Errorf("emitting DirectPInvoke props: %w", perr)
	} else {
		logf(cfg.Verbose, "emitted DirectPInvoke props at %s (%d DLLs)", ppath, len(dlls))
	}

	return result, nil
}
