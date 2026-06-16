package compile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindModuleRoot(t *testing.T) {
	// Should find wasmforge module root from CWD
	root, err := findModuleRoot()
	if err != nil {
		t.Skipf("not running from wasmforge source tree: %v", err)
	}
	// Verify the root has go.mod
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Errorf("module root %s has no go.mod", root)
	}
	// Verify dotnet/ exists
	if _, err := os.Stat(filepath.Join(root, "dotnet", "bridge")); err != nil {
		t.Errorf("module root %s missing dotnet/bridge/", root)
	}
}

func TestInjectHelpers(t *testing.T) {
	tmpDir := t.TempDir()
	helpersDir := t.TempDir()

	// Create fake helper files
	for _, name := range []string{"WfHostBridge.cs", "LsaHostHelper.cs", "CryptoHostHelper.cs", "NetworkHostHelper.cs"} {
		os.WriteFile(filepath.Join(helpersDir, name), []byte("// "+name), 0644)
	}

	err := injectHelpers(tmpDir, helpersDir, false)
	if err != nil {
		t.Fatalf("injectHelpers: %v", err)
	}

	// Verify WasmForge/ subdir created with 4 files
	wfDir := filepath.Join(tmpDir, "WasmForge")
	entries, err := os.ReadDir(wfDir)
	if err != nil {
		t.Fatalf("reading WasmForge dir: %v", err)
	}
	if len(entries) != 4 {
		t.Errorf("expected 4 helpers, got %d", len(entries))
	}

	// Verify idempotency (run again, no error)
	err = injectHelpers(tmpDir, helpersDir, false)
	if err != nil {
		t.Fatalf("second injectHelpers: %v", err)
	}
}

func TestInjectStubs(t *testing.T) {
	tmpDir := t.TempDir()
	stubsDir := t.TempDir()

	// Create fake stub dirs
	for _, name := range []string{"System.DirectoryServices", "System.IdentityModel.Tokens"} {
		dir := filepath.Join(stubsDir, name)
		os.MkdirAll(dir, 0755)
		os.WriteFile(filepath.Join(dir, name+".csproj"), []byte("<Project/>"), 0644)
		os.WriteFile(filepath.Join(dir, "Stubs.cs"), []byte("// stub"), 0644)
	}

	err := injectStubs(tmpDir, stubsDir, false)
	if err != nil {
		t.Fatalf("injectStubs: %v", err)
	}

	// Verify stubs/ subdir
	stubsOut := filepath.Join(tmpDir, "stubs")
	entries, err := os.ReadDir(stubsOut)
	if err != nil {
		t.Fatalf("reading stubs dir: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 stub dirs, got %d", len(entries))
	}
}
