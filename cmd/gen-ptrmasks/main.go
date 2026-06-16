// gen-ptrmasks generates pointer bitmasks for Win32 API parameters from
// the win32json metadata (https://github.com/marlersoft/win32json).
//
// For each Win32 function, it produces a uint32 bitmask where bit N=1
// means parameter N is a WASM linear memory pointer that needs host-address
// translation. This replaces manual curation for the vast majority of the
// ~17,000 Win32 APIs.
//
// Usage:
//
//	go run ./cmd/gen-ptrmasks -json /path/to/win32json/api -o internal/hostmod/generated_ptrmasks.go
//
// Or via go generate (see internal/hostmod/generate.go).
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"
)

// JSON schema types matching win32json format.

// APIFile represents one api/*.json file.
type APIFile struct {
	Constants json.RawMessage `json:"Constants"`
	Types     []TypeDef       `json:"Types"`
	Functions []Function      `json:"Functions"`
}

// Function represents a Win32 API function.
type Function struct {
	Name       string   `json:"Name"`
	DllImport  string   `json:"DllImport"`
	Params     []Param  `json:"Params"`
	ReturnType TypeDesc `json:"ReturnType"`
}

// Param represents a function parameter.
type Param struct {
	Name  string            `json:"Name"`
	Type  TypeDesc          `json:"Type"`
	Attrs []json.RawMessage `json:"Attrs"`
}

// TypeDesc describes a type in the metadata.
type TypeDesc struct {
	Kind  string    `json:"Kind"`
	Name  string    `json:"Name,omitempty"`
	Child *TypeDesc `json:"Child,omitempty"`
	// ApiRef fields
	TargetKind string `json:"TargetKind,omitempty"`
	Api        string `json:"Api,omitempty"`
}

// TypeDef represents a type definition in the Types array.
type TypeDef struct {
	Name string    `json:"Name"`
	Kind string    `json:"Kind"`
	Def  *TypeDesc `json:"Def,omitempty"`
}

// maskEntry holds a computed mask for output.
type maskEntry struct {
	Name    string
	Mask    uint32
	Comment string // parameter annotations
}

func main() {
	jsonDir := flag.String("json", "", "Path to win32json/api directory")
	output := flag.String("o", "", "Output Go file path")
	pkgName := flag.String("pkg", "hostmod", "Go package name for generated file")
	remoteCtx := flag.String("remote-ctx", "", "Optional path to remote-context overrides config file")
	flag.Parse()

	if *jsonDir == "" || *output == "" {
		flag.Usage()
		os.Exit(1)
	}

	log.Printf("Loading API files from %s...", *jsonDir)

	// Phase 1: Load all API files and build global type registry.
	typeRegistry := make(map[string]*TypeDef) // key: type name
	var allFunctions []Function

	err := filepath.WalkDir(*jsonDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}

		var apiFile APIFile
		if err := json.Unmarshal(data, &apiFile); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}

		for i := range apiFile.Types {
			t := &apiFile.Types[i]
			typeRegistry[t.Name] = t
		}

		allFunctions = append(allFunctions, apiFile.Functions...)
		return nil
	})
	if err != nil {
		log.Fatalf("Failed to load API files: %v", err)
	}

	log.Printf("Loaded %d types, %d functions", len(typeRegistry), len(allFunctions))

	// Load remote-context overrides (optional).
	remoteOverrides := loadRemoteContextOverrides(*remoteCtx)
	if remoteOverrides != nil {
		log.Printf("Loaded remote-context overrides for %d APIs", len(remoteOverrides))
	}

	// Phase 2: Compute pointer masks for all functions.
	var entries []maskEntry
	stats := struct {
		total            int
		withPtrs         int
		allZero          int
		skippedDups      int
		remoteOverridden int
	}{}

	seen := make(map[string]bool)

	for _, fn := range allFunctions {
		if seen[fn.Name] {
			stats.skippedDups++
			continue
		}
		seen[fn.Name] = true
		stats.total++

		if len(fn.Params) > 32 {
			// uint32 bitmask can only represent 32 params
			log.Printf("WARNING: %s has %d params (>32), truncating mask", fn.Name, len(fn.Params))
		}

		var mask uint32
		var comments []string
		for i, param := range fn.Params {
			if i >= 32 {
				break
			}
			if isWasmPointer(param.Type, typeRegistry, 0) {
				mask |= 1 << uint(i)
				comments = append(comments, param.Name)
			}
		}

		// Apply remote-context overrides: clear bits for args that are remote
		// process addresses (not WASM pointers), even if typed as PointerTo(Void).
		if overrides, ok := remoteOverrides[fn.Name]; ok {
			for idx := range overrides {
				if idx < 32 {
					mask &^= 1 << uint(idx)
				}
			}
			stats.remoteOverridden++
		}

		if mask != 0 {
			stats.withPtrs++
		} else {
			stats.allZero++
		}

		entries = append(entries, maskEntry{
			Name:    fn.Name,
			Mask:    mask,
			Comment: strings.Join(comments, ", "),
		})
	}

	// Sort entries by name for deterministic output.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name < entries[j].Name
	})

	log.Printf("Computed masks: %d total, %d with pointers, %d all-zero, %d duplicate names skipped, %d remote-context overrides applied",
		stats.total, stats.withPtrs, stats.allZero, stats.skippedDups, stats.remoteOverridden)

	// Phase 3: Generate Go source file.
	tmpl := template.Must(template.New("output").Parse(outputTemplate))

	f, err := os.Create(*output)
	if err != nil {
		log.Fatalf("Failed to create output file: %v", err)
	}
	defer f.Close()

	err = tmpl.Execute(f, struct {
		Package   string
		Timestamp string
		Entries   []maskEntry
		Stats     struct {
			Total    int
			WithPtrs int
			AllZero  int
		}
	}{
		Package:   *pkgName,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Entries:   entries,
		Stats: struct {
			Total    int
			WithPtrs int
			AllZero  int
		}{
			Total:    stats.total,
			WithPtrs: stats.withPtrs,
			AllZero:  stats.allZero,
		},
	})
	if err != nil {
		log.Fatalf("Failed to generate output: %v", err)
	}

	log.Printf("Generated %s (%d entries)", *output, len(entries))
}

// isWasmPointer returns true if the given type represents a WASM linear memory
// pointer that needs host-address translation. The depth parameter prevents
// infinite recursion on circular type references.
func isWasmPointer(td TypeDesc, types map[string]*TypeDef, depth int) bool {
	if depth > 10 {
		return false // prevent infinite recursion
	}

	switch td.Kind {
	case "PointerTo":
		return true // LPVOID, LPCWSTR, LPBYTE, etc.

	case "LPArray":
		return true // Array buffers passed by pointer

	case "Native":
		// IntPtr, UIntPtr, UInt32, Int32, etc. are scalars/handles, not WASM pointers.
		// IntPtr is used for HANDLE, HWND, LPARAM -- all opaque values, not dereferenceable.
		return false

	case "ApiRef":
		// Resolve the referenced type definition.
		resolved, ok := types[td.Name]
		if !ok {
			return false // unknown type, assume not pointer
		}
		return isTypeDefPointer(resolved, types, depth+1)

	case "FunctionPointer":
		return false // Native callback address, not WASM memory

	case "Enum":
		return false // Scalar value

	case "Struct":
		return false // Struct passed by value

	case "Union":
		return false // Union passed by value

	case "Com":
		return true // COM interface pointer

	case "ComClassID":
		return false // GUID value

	default:
		return false
	}
}

// isTypeDefPointer determines if a TypeDef resolves to a WASM pointer.
func isTypeDefPointer(td *TypeDef, types map[string]*TypeDef, depth int) bool {
	switch td.Kind {
	case "NativeTypedef":
		if td.Def == nil {
			return false
		}
		return isWasmPointer(*td.Def, types, depth)

	case "Enum":
		return false // Enumeration is a scalar

	case "Struct":
		return false // Struct value passed by value

	case "Union":
		return false // Union value passed by value

	case "FunctionPointer":
		return false // Callback address, not WASM memory

	case "Com":
		return true // COM interface pointer

	case "ComClassID":
		return false // GUID value

	default:
		return false
	}
}

// loadRemoteContextOverrides reads a config file listing APIs whose
// pointer-typed params are remote process addresses (not WASM pointers).
// Returns map[apiName]map[argIndex]bool, or nil if path is empty.
//
// File format: lines of the form "ApiName idx1 [idx2...]" where indices are
// 0-based parameter positions. Lines starting with '#' and blank lines are
// ignored.
func loadRemoteContextOverrides(path string) map[string]map[int]bool {
	if path == "" {
		return nil
	}

	f, err := os.Open(path)
	if err != nil {
		log.Fatalf("Failed to open remote-context overrides file %s: %v", path, err)
	}
	defer f.Close()

	result := make(map[string]map[int]bool)
	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and blank lines.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			log.Printf("WARNING: remote-ctx line %d: expected 'ApiName idx...', got %q (skipping)", lineNum, line)
			continue
		}

		apiName := fields[0]
		indices := make(map[int]bool)
		for _, s := range fields[1:] {
			idx, err := strconv.Atoi(s)
			if err != nil {
				log.Printf("WARNING: remote-ctx line %d: invalid index %q for %s: %v (skipping)", lineNum, s, apiName, err)
				continue
			}
			if idx < 0 || idx >= 32 {
				log.Printf("WARNING: remote-ctx line %d: index %d out of range [0,31] for %s (skipping)", lineNum, idx, apiName)
				continue
			}
			indices[idx] = true
		}

		if len(indices) > 0 {
			result[apiName] = indices
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Failed to read remote-context overrides file %s: %v", path, err)
	}

	return result
}

const outputTemplate = `// Code generated by gen-ptrmasks from win32json metadata. DO NOT EDIT.
// Generated: {{.Timestamp}}
// Stats: {{.Stats.Total}} APIs total, {{.Stats.WithPtrs}} with pointer params, {{.Stats.AllZero}} with no pointer params

//go:build windows

package {{.Package}}

// generatedPointerMasks maps Win32 API names to bitmasks indicating which
// arguments are WASM linear memory pointers that need host-address translation.
// Bit N=1 means arg[N] IS a WASM pointer; bit N=0 means it is NOT.
//
// This map is auto-generated from the win32json project's metadata
// (https://github.com/marlersoft/win32json). Semantic overrides in
// semanticOverrides take priority over these entries for APIs where the
// type-level classification is insufficient (e.g., remote process memory
// addresses that are typed as PointerTo(Void) but are not WASM pointers).
var generatedPointerMasks = map[string]uint32{
{{- range .Entries}}
{{- if ne .Mask 0}}
	"{{.Name}}": 0x{{printf "%02x" .Mask}}, // {{.Comment}}
{{- end}}
{{- end}}
}
`
