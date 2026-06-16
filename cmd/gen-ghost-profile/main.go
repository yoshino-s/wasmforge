// gen-ghost-profile extracts gopclntab function symbols from a compiled Go
// binary and produces a JSON ghost profile describing the binary's packages,
// functions, types, and methods.
//
// Usage:
//
//	go run ./cmd/gen-ghost-profile -binary /path/to/traefik.exe -name traefik
//	go run ./cmd/gen-ghost-profile -binary /path/to/caddy.exe -name caddy -out ./profiles/
//
// Extraction runs "go tool objdump <binary>" and parses TEXT symbol lines.
// Only project and dependency paths are captured; Go stdlib is excluded.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// GhostProfile is the JSON output format.
type GhostProfile struct {
	Name           string                `json:"name"`
	Source         string                `json:"source"`
	ModulePath     string                `json:"module_path"`
	Packages       []string              `json:"packages"`
	Functions      map[string][]string   `json:"functions"`
	Types          map[string][]string   `json:"types"`
	Methods        map[string][]string   `json:"methods"`
	TotalFunctions int                   `json:"total_functions"`
	TotalPackages  int                   `json:"total_packages"`
}

// textLineRE matches objdump TEXT lines:
//
//	TEXT github.com/traefik/traefik/v3/pkg/provider.(*Docker).Provide(SB) /path/to/file.go
var textLineRE = regexp.MustCompile(`^TEXT\s+(\S+)\(SB\)`)

// stdlibPrefixes lists Go standard library import-path prefixes to exclude.
// We match these against the full import path of each symbol.
var stdlibPrefixes = []string{
	"runtime",
	"runtime/",
	"net",
	"net/",
	"os",
	"os/",
	"crypto",
	"crypto/",
	"encoding",
	"encoding/",
	"sync",
	"sync/",
	"io",
	"io/",
	"fmt",
	"math",
	"math/",
	"strings",
	"bytes",
	"context",
	"reflect",
	"time",
	"sort",
	"strconv",
	"errors",
	"unicode",
	"unicode/",
	"path",
	"path/",
	"regexp",
	"bufio",
	"log",
	"flag",
	"testing",
	"testing/",
	"internal/",
	"syscall",
	"unsafe",
	"text/",
	"html/",
	"database/",
	"debug/",
	"expvar",
	"hash",
	"hash/",
	"image",
	"image/",
	"index/",
	"maps",
	"slices",
	"cmp",
	"iter",
}

// compilerGeneratedPrefixes lists symbol name patterns that are
// compiler-generated and should be excluded from the profile.
var compilerGeneratedPrefixes = []string{
	"type..",
	"type:",
	"go.buildid",
	"go.itab",
	"go:info",
	"go:string",
	"go:func",
	"gclocals",
	"runtime.gcbits",
}

// compilerGeneratedSuffixes excludes closure and defer wrappers by name suffix.
var compilerGeneratedSuffixes = []string{
	"·dwrap",
	"-fm",
}

// isCompilerGenerated returns true if the symbol name looks like a
// compiler-generated artifact (closures, type hashes, init funcs, etc.).
func isCompilerGenerated(name string) bool {
	for _, p := range compilerGeneratedPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	for _, s := range compilerGeneratedSuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	// Skip vendor directory symbols.
	if strings.Contains(name, "/vendor/") {
		return true
	}
	// type..hash, type..eq
	if strings.Contains(name, "type..") {
		return true
	}
	return false
}

// isStdlib returns true when the import path belongs to the Go standard library
// or is a compiler-generated symbol we always want to exclude.
func isStdlib(importPath string) bool {
	// Standard library packages have no dots in the first path segment.
	// e.g. "fmt", "net/http", "encoding/json" — all begin with a non-dotted
	// segment, whereas third-party paths begin with e.g. "github.com/...".
	firstSeg := importPath
	if idx := strings.IndexByte(importPath, '/'); idx >= 0 {
		firstSeg = importPath[:idx]
	}
	if !strings.Contains(firstSeg, ".") {
		return true
	}
	// Fallback: check explicit prefix list for paths that start with a plain
	// word (covers "runtime", "net", "os", etc. when the first segment has no
	// slash at all).
	for _, p := range stdlibPrefixes {
		if importPath == strings.TrimSuffix(p, "/") || strings.HasPrefix(importPath, p) {
			return true
		}
	}
	return false
}

// parsedSymbol holds the parts we care about from a single TEXT entry.
type parsedSymbol struct {
	importPath string // full import path (e.g. "github.com/traefik/traefik/v3/pkg/provider")
	typeName   string // type name without pointer (e.g. "Docker") or ""
	funcName   string // function or method name (e.g. "Provide")
}

// parseSymbol splits a raw gopclntab symbol string into its constituent parts.
// Returns (symbol, ok). ok is false when the symbol should be skipped.
//
// Examples:
//
//	github.com/foo/bar/pkg.(*MyType).Method   → {pkg: "github.com/foo/bar/pkg", type: "MyType",  func: "Method"}
//	github.com/foo/bar/pkg.FuncName            → {pkg: "github.com/foo/bar/pkg", type: "",        func: "FuncName"}
//	github.com/foo/bar/pkg.MyType.Method       → {pkg: "github.com/foo/bar/pkg", type: "MyType",  func: "Method"}
func parseSymbol(raw string) (parsedSymbol, bool) {
	if isCompilerGenerated(raw) {
		return parsedSymbol{}, false
	}

	// Find the last dot that separates the package from the identifier.
	// We must be careful: import paths can contain dots (e.g. "github.com").
	// The heuristic: the package path is everything up to the last '/' followed
	// by the portion before the first '.' after that last '/'.
	//
	// Examples:
	//   "github.com/foo/bar/pkg.Func"            last slash at 20, dot after = "pkg.Func"
	//   "github.com/foo/bar/pkg.(*T).Method"      similar
	//   "github.com/foo.(*T).Method"              last slash might be early

	lastSlash := strings.LastIndex(raw, "/")
	afterSlash := raw
	if lastSlash >= 0 {
		afterSlash = raw[lastSlash+1:]
	}

	// afterSlash is something like "pkg.(*Type).Method" or "pkg.Func"
	dotInAfter := strings.IndexByte(afterSlash, '.')
	if dotInAfter < 0 {
		// No dot after last slash — not a valid symbol.
		return parsedSymbol{}, false
	}

	var importPath string
	if lastSlash >= 0 {
		importPath = raw[:lastSlash+1] + afterSlash[:dotInAfter]
	} else {
		importPath = afterSlash[:dotInAfter]
	}

	if isStdlib(importPath) {
		return parsedSymbol{}, false
	}

	// Everything after the import path dot.
	rest := afterSlash[dotInAfter+1:]
	if rest == "" {
		return parsedSymbol{}, false
	}

	// Skip compiler-generated function names.
	// func1, func2, init.0, init.1, deferwrap
	funcPart := rest
	if idx := strings.LastIndex(rest, "."); idx >= 0 {
		// e.g. "(*Type).Method" → method is "Method"
		funcPart = rest[idx+1:]
	}
	if isClosureName(funcPart) {
		return parsedSymbol{}, false
	}

	sym := parsedSymbol{importPath: importPath}

	// Detect pointer receiver: "(*Type).Method"
	if strings.HasPrefix(rest, "(*") {
		end := strings.Index(rest, ")")
		if end < 0 {
			return parsedSymbol{}, false
		}
		sym.typeName = rest[2:end]
		if len(rest) > end+2 {
			sym.funcName = rest[end+2:] // skip ")."
		}
	} else if dot := strings.Index(rest, "."); dot >= 0 {
		// Value receiver: "Type.Method"
		sym.typeName = rest[:dot]
		sym.funcName = rest[dot+1:]
	} else {
		// Plain function: "FuncName"
		sym.funcName = rest
	}

	// Clean up any trailing generic type parameter brackets from funcName.
	if idx := strings.IndexByte(sym.funcName, '['); idx >= 0 {
		sym.funcName = sym.funcName[:idx]
	}
	if sym.funcName == "" {
		return parsedSymbol{}, false
	}
	if isClosureName(sym.funcName) {
		return parsedSymbol{}, false
	}

	return sym, true
}

// isClosureName returns true for compiler-synthesised sub-function names:
// funcN (where N is a digit), init.N, deferwrap, etc.
func isClosureName(name string) bool {
	if name == "" {
		return false
	}
	// "func1", "func12", ...
	if strings.HasPrefix(name, "func") {
		rest := name[4:]
		if rest != "" && isAllDigits(rest) {
			return true
		}
	}
	// "init.0", "init.1", ...
	if strings.HasPrefix(name, "init.") {
		return true
	}
	// "deferwrap"
	if strings.Contains(name, "deferwrap") {
		return true
	}
	return false
}

func isAllDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// hasPathSegment returns true if any /-separated segment of path equals name
// (case-insensitive).
func hasPathSegment(path, name string) bool {
	lower := strings.ToLower(name)
	for _, seg := range strings.Split(strings.ToLower(path), "/") {
		if seg == lower {
			return true
		}
	}
	return false
}

// moduleCandidates returns the candidate module prefixes for an import path.
// It generates a 3-segment prefix and, when the 4th segment is a version tag
// (v2, v3, …), also a 4-segment prefix.
func moduleCandidates(importPath string) []string {
	parts := strings.Split(importPath, "/")
	var candidates []string
	if len(parts) >= 3 {
		candidates = append(candidates, strings.Join(parts[:3], "/"))
	}
	if len(parts) >= 4 {
		v := parts[3]
		if len(v) >= 2 && v[0] == 'v' && isAllDigits(v[1:]) {
			candidates = append(candidates, strings.Join(parts[:4], "/"))
		}
	}
	return candidates
}

// detectModulePath returns the most-likely module path from the set of import
// paths.  A module with many sub-packages gets a high score; ties are broken
// by total symbol count.
//
// For each distinct import path we generate a 3-segment prefix
// (e.g. "github.com/traefik/traefik") and, when the 4th segment is a version
// tag (v2, v3, …), also a 4-segment prefix.  The prefix whose sub-package
// count (distinct child paths) is highest wins.
func detectModulePath(counts map[string]int) string {
	// prefixChildren[prefix] = distinct import paths with that prefix (children).
	prefixChildren := make(map[string]int)
	prefixSyms := make(map[string]int)

	for p, syms := range counts {
		for _, prefix := range moduleCandidates(p) {
			if p != prefix {
				prefixChildren[prefix]++
			}
			prefixSyms[prefix] += syms
		}
	}

	best := ""
	bestChildren := -1
	bestSyms := 0

	for prefix, children := range prefixChildren {
		syms := prefixSyms[prefix]
		if children > bestChildren ||
			(children == bestChildren && syms > bestSyms) {
			bestChildren = children
			bestSyms = syms
			best = prefix
		}
	}

	if best == "" {
		for prefix, syms := range prefixSyms {
			if syms > bestSyms {
				bestSyms = syms
				best = prefix
			}
		}
	}

	return best
}

// relPath strips the module prefix from an import path, returning the
// relative package path (e.g. "pkg/provider").
func relPath(importPath, modulePath string) string {
	if importPath == modulePath {
		return "."
	}
	prefix := modulePath + "/"
	if strings.HasPrefix(importPath, prefix) {
		return importPath[len(prefix):]
	}
	return importPath
}

// runObjdump runs "go tool objdump" on the binary and accumulates symbol data.
func runObjdump(binary string) (pkgFuncs, pkgTypes map[string]map[string]bool, typeMethods map[string]map[string]bool, importPathCounts map[string]int, totalSymbols int, err error) {
	fmt.Fprintf(os.Stderr, "[gen-ghost-profile] running go tool objdump on %s\n", binary)

	cmd := exec.Command("go", "tool", "objdump", binary)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, nil, nil, 0, fmt.Errorf("objdump pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, nil, nil, 0, fmt.Errorf("objdump start: %w", err)
	}

	// Use a large scanner buffer — objdump output can be millions of lines.
	const maxScannerBuf = 16 * 1024 * 1024 // 16 MB
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, maxScannerBuf), maxScannerBuf)

	pkgFuncs = make(map[string]map[string]bool)
	pkgTypes = make(map[string]map[string]bool)
	typeMethods = make(map[string]map[string]bool)
	importPathCounts = make(map[string]int)

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "TEXT ") {
			continue
		}
		m := textLineRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		sym, ok := parseSymbol(m[1])
		if !ok {
			continue
		}

		totalSymbols++
		importPathCounts[sym.importPath]++

		if pkgFuncs[sym.importPath] == nil {
			pkgFuncs[sym.importPath] = make(map[string]bool)
		}

		if sym.typeName == "" {
			pkgFuncs[sym.importPath][sym.funcName] = true
		} else {
			if pkgTypes[sym.importPath] == nil {
				pkgTypes[sym.importPath] = make(map[string]bool)
			}
			pkgTypes[sym.importPath][sym.typeName] = true
			if typeMethods[sym.typeName] == nil {
				typeMethods[sym.typeName] = make(map[string]bool)
			}
			typeMethods[sym.typeName][sym.funcName] = true
		}
	}
	if scanErr := scanner.Err(); scanErr != nil {
		cmd.Wait() //nolint:errcheck
		return nil, nil, nil, nil, 0, fmt.Errorf("scanner error: %w", scanErr)
	}
	if waitErr := cmd.Wait(); waitErr != nil {
		log.Printf("WARNING: objdump exited with error: %v", waitErr)
	}

	fmt.Fprintf(os.Stderr, "[gen-ghost-profile] parsed %d symbols from %d packages\n",
		totalSymbols, len(importPathCounts))

	return pkgFuncs, pkgTypes, typeMethods, importPathCounts, totalSymbols, nil
}

// buildProfile assembles a GhostProfile from the accumulated symbol data.
func buildProfile(name string, pkgFuncs, pkgTypes map[string]map[string]bool, typeMethods map[string]map[string]bool, importPathCounts map[string]int, totalSymbols int) GhostProfile {
	modulePath := detectModulePath(importPathCounts)

	// If the auto-detected module path doesn't contain the profile name
	// as an exact path segment, search for a better match.
	if !hasPathSegment(modulePath, name) {
		for p := range importPathCounts {
			for _, c := range moduleCandidates(p) {
				if hasPathSegment(c, name) {
					modulePath = c
					break
				}
			}
			if hasPathSegment(modulePath, name) {
				break
			}
		}
	}

	fmt.Fprintf(os.Stderr, "[gen-ghost-profile] detected module path: %s\n", modulePath)

	profile := GhostProfile{
		Name:       name,
		Source:     modulePath,
		ModulePath: modulePath,
		Functions:  make(map[string][]string),
		Types:      make(map[string][]string),
		Methods:    make(map[string][]string),
	}

	pkgSet := make(map[string]bool)

	for importPath, funcs := range pkgFuncs {
		rel := relPath(importPath, modulePath)
		pkgSet[rel] = true

		if len(funcs) > 0 {
			fs := sortedKeys(funcs)
			if existing, ok := profile.Functions[rel]; ok {
				profile.Functions[rel] = mergeSorted(existing, fs)
			} else {
				profile.Functions[rel] = fs
			}
		}
	}

	for importPath, types := range pkgTypes {
		rel := relPath(importPath, modulePath)
		pkgSet[rel] = true

		if len(types) > 0 {
			ts := sortedKeys(types)
			if existing, ok := profile.Types[rel]; ok {
				profile.Types[rel] = mergeSorted(existing, ts)
			} else {
				profile.Types[rel] = ts
			}
		}
	}

	for typeName, methods := range typeMethods {
		if len(methods) > 0 {
			ms := sortedKeys(methods)
			if existing, ok := profile.Methods[typeName]; ok {
				profile.Methods[typeName] = mergeSorted(existing, ms)
			} else {
				profile.Methods[typeName] = ms
			}
		}
	}

	profile.Packages = sortedKeys(pkgSet)
	profile.TotalFunctions = totalSymbols
	profile.TotalPackages = len(profile.Packages)

	return profile
}

// writeProfile serialises profile as indented JSON to <outDir>/<name>.json.
func writeProfile(profile GhostProfile, outDir, name string) error {
	outPath := filepath.Join(outDir, name+".json")
	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(profile); err != nil {
		f.Close()
		return fmt.Errorf("encode JSON: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close output: %w", err)
	}
	fmt.Fprintf(os.Stderr, "[gen-ghost-profile] wrote profile to %s\n", outPath)
	fmt.Fprintf(os.Stderr, "  packages:  %d\n", profile.TotalPackages)
	fmt.Fprintf(os.Stderr, "  functions: %d\n", profile.TotalFunctions)
	return nil
}

func main() {
	binary := flag.String("binary", "", "Path to compiled Go binary (required)")
	name := flag.String("name", "", "Profile name (required)")
	outDir := flag.String("out", ".", "Output directory for the JSON profile")
	flag.Parse()

	if *binary == "" || *name == "" {
		flag.Usage()
		os.Exit(1)
	}

	pkgFuncs, pkgTypes, typeMethods, importPathCounts, totalSymbols, err := runObjdump(*binary)
	if err != nil {
		log.Fatal(err)
	}

	if len(importPathCounts) == 0 {
		log.Fatal("no symbols found — is this a Go binary? try running with a different binary")
	}

	profile := buildProfile(*name, pkgFuncs, pkgTypes, typeMethods, importPathCounts, totalSymbols)

	if err := writeProfile(profile, *outDir, *name); err != nil {
		log.Fatal(err)
	}
}

// sortedKeys returns the keys of a map[string]bool sorted ascending.
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// mergeSorted merges two sorted slices, deduplicating.
func mergeSorted(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	for _, s := range a {
		seen[s] = true
	}
	for _, s := range b {
		seen[s] = true
	}
	return sortedKeys(seen)
}
