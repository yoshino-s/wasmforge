package build

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- Fix 1: //+build (no space) variant ---

func TestRewriteWindowsBuildTags_NoSpaceVariant(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		changed bool
	}{
		{
			name:    "old-style with space",
			input:   "// +build windows\n\npackage foo\n",
			want:    "//go:build (windows || wasip1)\n// +build windows\n\npackage foo\n",
			changed: true,
		},
		{
			name:    "old-style no space",
			input:   "//+build windows\n\npackage foo\n",
			want:    "//go:build (windows || wasip1)\n//+build windows\n\npackage foo\n",
			changed: true,
		},
		{
			name:    "old-style no space negated",
			input:   "//+build !windows\n\npackage foo\n",
			want:    "//go:build !(windows || wasip1)\n//+build !windows\n\npackage foo\n",
			changed: true,
		},
		{
			name:    "go:build already present — old-style ignored",
			input:   "//go:build windows\n//+build windows\n\npackage foo\n",
			want:    "//go:build (windows || wasip1)\n//+build windows\n\npackage foo\n",
			changed: true,
		},
		{
			name:    "no build tags",
			input:   "package foo\n",
			want:    "package foo\n",
			changed: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, changed := rewriteWindowsBuildTags([]byte(tt.input))
			if changed != tt.changed {
				t.Errorf("changed = %v, want %v", changed, tt.changed)
			}
			if string(got) != tt.want {
				t.Errorf("output mismatch:\ngot:  %q\nwant: %q", string(got), tt.want)
			}
		})
	}
}

func TestFileExcludesWasip1_NoSpaceVariant(t *testing.T) {
	tests := []struct {
		name string
		data string
		want bool
	}{
		{
			name: "old-style with space excludes",
			data: "// +build !windows\n\npackage foo\n",
			want: true,
		},
		{
			name: "old-style no space excludes",
			data: "//+build !windows\n\npackage foo\n",
			want: true,
		},
		{
			name: "old-style no space positive — does not exclude",
			data: "//+build windows\n\npackage foo\n",
			want: false,
		},
		{
			name: "go:build excludes",
			data: "//go:build !wasip1\n\npackage foo\n",
			want: true,
		},
		{
			name: "no tags",
			data: "package foo\n",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// fileExcludesWasip1 reads from disk; use fileExcludesWasip1FromData
			// which operates on in-memory data and now also checks old-style tags.
			got := fileExcludesWasip1FromData([]byte(tt.data))
			if got != tt.want {
				t.Errorf("fileExcludesWasip1FromData() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFileExcludesWasip1FromData_OldStyleTags(t *testing.T) {
	tests := []struct {
		name string
		data string
		want bool
	}{
		{
			name: "go:build negated wasip1",
			data: "//go:build !wasip1\n\npackage foo\n",
			want: true,
		},
		{
			name: "go:build negated windows||wasip1",
			data: "//go:build !(windows || wasip1)\n\npackage foo\n",
			want: true,
		},
		{
			name: "old-style with space !windows",
			data: "// +build !windows\n\npackage foo\n",
			want: true,
		},
		{
			name: "old-style no space !windows",
			data: "//+build !windows\n\npackage foo\n",
			want: true,
		},
		{
			name: "old-style no space positive windows",
			data: "//+build windows\n\npackage foo\n",
			want: false,
		},
		{
			name: "no tags at all",
			data: "package foo\n",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fileExcludesWasip1FromData([]byte(tt.data))
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// --- Fix 2: Broader syscall type mismatch rewriting ---

func TestRewriteSyscallTypeMismatches(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "Close(Handle)",
			input: `syscall.Close(h)`,
			want:  `syscall.CloseW(h)`,
		},
		{
			name:  "Write(Handle(x),...)",
			input: `syscall.Write(syscall.Handle(fd), buf)`,
			want:  `syscall.Write(int(fd), buf)`,
		},
		{
			name:  "Read(Handle(x),...)",
			input: `syscall.Read(syscall.Handle(fd), buf)`,
			want:  `syscall.Read(int(fd), buf)`,
		},
		{
			name:  "Seek(Handle(x),...)",
			input: `syscall.Seek(syscall.Handle(fd), 0, 0)`,
			want:  `syscall.Seek(int(fd), 0, 0)`,
		},
		{
			name:  "no match",
			input: `fmt.Println("hello")`,
			want:  `fmt.Println("hello")`,
		},
		{
			name:  "multiple in one file",
			input: "syscall.Write(syscall.Handle(a), b)\nsyscall.Read(syscall.Handle(c), d)\nsyscall.Close(h)",
			want:  "syscall.Write(int(a), b)\nsyscall.Read(int(c), d)\nsyscall.CloseW(h)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(rewriteSyscallTypeMismatches([]byte(tt.input)))
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// --- Fix 3: Panic fallback rewriting ---

func TestRewritePanicFallbacks(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantRet bool   // whether rewriting happened
		check   string // substring that must appear in output
	}{
		{
			name: "single panic with return values",
			input: `package foo

func readPassword() ([]byte, error) {
	panic("Not implemented")
}
`,
			wantRet: true,
			check:   "return",
		},
		{
			name: "single panic no return values",
			input: `package foo

func doNothing() {
	panic("not supported")
}
`,
			wantRet: true,
			check:   "return",
		},
		{
			name: "multi-statement body — not rewritten",
			input: `package foo

func something() error {
	x := 1
	panic(x)
}
`,
			wantRet: false,
		},
		{
			name: "no panic at all",
			input: `package foo

func normal() int {
	return 42
}
`,
			wantRet: false,
		},
		{
			name: "panic with string return",
			input: `package foo

func getName() string {
	panic("not implemented")
}
`,
			wantRet: true,
			check:   `""`,
		},
		{
			name: "panic with int return",
			input: `package foo

func getCount() int {
	panic("not implemented")
}
`,
			wantRet: true,
			check:   "return 0",
		},
		{
			name: "panic with bool return",
			input: `package foo

func isReady() bool {
	panic("not implemented")
}
`,
			wantRet: true,
			check:   "return false",
		},
		{
			name: "multiple functions — mix of panic and normal",
			input: `package foo

func a() int {
	panic("nope")
}

func b() int {
	return 1
}

func c() error {
	panic("nope")
}
`,
			wantRet: true,
			check:   "return 0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, changed := rewritePanicFallbacks([]byte(tt.input))
			if changed != tt.wantRet {
				t.Errorf("changed = %v, want %v", changed, tt.wantRet)
			}
			if tt.wantRet && tt.check != "" {
				if !strings.Contains(string(got), tt.check) {
					t.Errorf("output missing %q:\n%s", tt.check, string(got))
				}
			}
			if tt.wantRet {
				// Ensure no panic remains in rewritten functions.
				if strings.Contains(string(got), "panic(") && !strings.Contains(tt.input, "return") {
					t.Errorf("panic still present in output:\n%s", string(got))
				}
			}
		})
	}
}

func TestHasRemainingHandleMismatches(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "syscall.Handle in call",
			input: `x := syscall.Handle(fd)`,
			want:  true,
		},
		{
			name:  "syscall.MustLoadDLL",
			input: `var dll = syscall.MustLoadDLL("msvcrt.dll")`,
			want:  true,
		},
		{
			name:  "clean file",
			input: `x := syscall.CloseW(h)`,
			want:  false,
		},
		{
			name:  "Handle in type declaration — no call parens so no match",
			input: `type Foo struct { h syscall.Handle }`,
			want:  false, // "syscall.Handle" without "(" doesn't match
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasRemainingHandleMismatches([]byte(tt.input))
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// --- Fix 4: Module cache stub generation ---

func TestIsModuleCachePkg(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "module cache path",
			path: "/Users/foo/go/pkg/mod/github.com/sirupsen/logrus@v1.9.3",
			want: true,
		},
		{
			name: "project vendored path",
			path: "/tmp/build/vendor/github.com/sirupsen/logrus",
			want: false,
		},
		{
			name: "project source",
			path: "/tmp/build/cmd/agent",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isModuleCachePkg(tt.path)
			if got != tt.want {
				t.Errorf("isModuleCachePkg(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestParseModCachePath(t *testing.T) {
	tests := []struct {
		name    string
		pkgDir  string
		wantMod string
		wantVer string
		wantOK  bool
	}{
		{
			name:    "simple module root",
			pkgDir:  "/Users/foo/go/pkg/mod/github.com/sirupsen/logrus@v1.9.3",
			wantMod: "github.com/sirupsen/logrus",
			wantVer: "v1.9.3",
			wantOK:  true,
		},
		{
			name:    "sub-package",
			pkgDir:  "/Users/foo/go/pkg/mod/github.com/foo/bar@v2.0.0/sub/pkg",
			wantMod: "github.com/foo/bar",
			wantVer: "v2.0.0",
			wantOK:  true,
		},
		{
			name:    "not module cache",
			pkgDir:  "/tmp/build/vendor/github.com/foo/bar",
			wantMod: "",
			wantVer: "",
			wantOK:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, modPath, version, ok := parseModCachePath(tt.pkgDir)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if modPath != tt.wantMod {
				t.Errorf("modPath = %q, want %q", modPath, tt.wantMod)
			}
			if version != tt.wantVer {
				t.Errorf("version = %q, want %q", version, tt.wantVer)
			}
		})
	}
}

func TestDecodeModCachePath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"github.com/sirupsen/logrus", "github.com/sirupsen/logrus"},
		{"github.com/!microsoft/go-winio", "github.com/Microsoft/go-winio"},
		{"github.com/!azure/azure-sdk-for-go", "github.com/Azure/azure-sdk-for-go"},
	}
	for _, tt := range tests {
		got := decodeModCachePath(tt.input)
		if got != tt.want {
			t.Errorf("decodeModCachePath(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestGenerateModCacheStub(t *testing.T) {
	// Create a fake module cache structure.
	tmpDir := t.TempDir()
	fakeModCache := filepath.Join(tmpDir, "go", "pkg", "mod", "github.com", "example", "lib@v1.0.0")
	if err := os.MkdirAll(fakeModCache, 0o755); err != nil {
		t.Fatal(err)
	}

	// Write a Go file that defines isTerminal in a platform-specific way.
	os.WriteFile(filepath.Join(fakeModCache, "terminal_unix.go"), []byte(`// +build linux
package lib

func isTerminal(fd int) bool {
	return true
}
`), 0o444) // read-only like real module cache

	// Write a Go file that references isTerminal (compiles on wasip1).
	os.WriteFile(filepath.Join(fakeModCache, "terminal.go"), []byte(`package lib

func CheckTerminal() bool {
	return isTerminal(0)
}
`), 0o444)

	// Write a go.mod.
	os.WriteFile(filepath.Join(fakeModCache, "go.mod"), []byte("module github.com/example/lib\n\ngo 1.21\n"), 0o444)

	// Create a fake project go.mod.
	projectDir := filepath.Join(tmpDir, "project")
	os.MkdirAll(projectDir, 0o755)
	gomodPath := filepath.Join(projectDir, "go.mod")
	os.WriteFile(gomodPath, []byte("module myproject\n\ngo 1.21\n\nrequire github.com/example/lib v1.0.0\n"), 0o644)

	// Call generateModCacheStub.
	symbols := map[string]bool{"isTerminal": true}
	buildTmpDir := filepath.Join(tmpDir, "buildtmp")
	os.MkdirAll(buildTmpDir, 0o755)

	n, err := generateModCacheStub(fakeModCache, symbols, buildTmpDir, gomodPath, true)
	if err != nil {
		t.Fatalf("generateModCacheStub failed: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 stub generated, got %d", n)
	}

	// Verify the stub was written in the copy.
	modCopyStub := filepath.Join(buildTmpDir, "modreplace", "github.com", "example", "lib", "wfstub_wasip1.go")
	data, err := os.ReadFile(modCopyStub)
	if err != nil {
		t.Fatalf("stub not found at %s: %v", modCopyStub, err)
	}
	if !strings.Contains(string(data), "isTerminal") {
		t.Errorf("stub missing isTerminal definition:\n%s", data)
	}
	if !strings.Contains(string(data), "//go:build wasip1") {
		t.Errorf("stub missing wasip1 build tag:\n%s", data)
	}

	// Verify the replace directive was injected.
	gomod, err := os.ReadFile(gomodPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(gomod), "replace github.com/example/lib v1.0.0 =>") {
		t.Errorf("go.mod missing replace directive:\n%s", gomod)
	}
}
