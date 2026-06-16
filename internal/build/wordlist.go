package build

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
)

// wordList provides natural-sounding developer identifiers for polymorphic
// code generation. Identifiers are formed by concatenating a prefix (verb)
// with a suffix (noun), producing names like "parseBuffer", "loadConfig",
// "syncRegistry".
//
// A custom dictionary file can override the defaults via the
// WASMFORGE_WORDLIST environment variable (one word per line, prefixes and
// suffixes separated by a blank line).
type wordList struct {
	prefixes []string
	suffixes []string
}

// Go keywords and predeclared identifiers that must never be generated.
var goReserved = map[string]bool{
	// Keywords (lowercase and Title-case). Title-case is blocked because the
	// wazeroOnly method rename uses strings.ToLower(wo[:1])+wo[1:] — if the
	// ghost assigns wo="Import", the method becomes "import" (a keyword).
	// Blocking "Import", "Func", etc. prevents this class of errors.
	"break": true, "case": true, "chan": true, "const": true,
	"continue": true, "default": true, "defer": true, "else": true,
	"fallthrough": true, "for": true, "func": true, "go": true,
	"goto": true, "if": true, "import": true, "interface": true,
	"map": true, "package": true, "range": true, "return": true,
	"select": true, "struct": true, "switch": true, "type": true,
	"var": true,
	// Title-case equivalents of keywords (e.g., "Import" → "import"):
	"Break": true, "Case": true, "Chan": true, "Const": true,
	"Continue": true, "Default": true, "Defer": true, "Else": true,
	"Fallthrough": true, "For": true, "Func": true, "Go": true,
	"Goto": true, "If": true, "Import": true, "Interface": true,
	"Map": true, "Package": true, "Range": true, "Return": true,
	"Select": true, "Struct": true, "Switch": true, "Type": true,
	"Var": true,
	// Predeclared types
	"bool": true, "byte": true, "complex64": true, "complex128": true,
	"error": true, "float32": true, "float64": true, "int": true,
	"int8": true, "int16": true, "int32": true, "int64": true,
	"rune": true, "string": true, "uint": true, "uint8": true,
	"uint16": true, "uint32": true, "uint64": true, "uintptr": true,
	// Predeclared constants/zero value
	"true": true, "false": true, "iota": true, "nil": true,
	// Predeclared functions
	"append": true, "cap": true, "close": true, "complex": true,
	"copy": true, "delete": true, "imag": true, "len": true,
	"make": true, "new": true, "panic": true, "print": true,
	"println": true, "real": true, "recover": true, "clear": true,
	"min": true, "max": true,
	// Common standard library identifiers that could collide
	"init": true, "main": true,
	// Go pseudo-packages: naming a package "unsafe" or "builtin" causes import
	// conflicts because every file importing stdlib "unsafe" would collide with
	// a module-local package of the same name.
	"unsafe": true, "builtin": true,
	// Standard library package names frequently imported by wazero. If a
	// wazero sub-package is renamed to one of these, it collides with the
	// stdlib import of the same name (e.g., "errors redeclared in this block"
	// when both "errors" stdlib and "mod/core/internal/errors" are imported).
	// Package name = last segment of import path (e.g., "encoding/binary" → "binary").
	"errors": true, "context": true, "binary": true, "json": true,
	"reflect": true, "cmp": true, "sync": true, "io": true,
	"fmt": true, "os": true, "log": true, "math": true,
	"bytes": true, "strings": true, "strconv": true, "unicode": true,
	"runtime": true, "syscall": true, "time": true, "hash": true,
	"path": true, "sort": true, "regexp": true, "atomic": true,
	"bits": true, "rand": true, "utf8": true, "utf16": true,
	"net": true,
	// Wazero-specific collision guards:
	// "magic": wazero engine_cache.go has `var magic = []byte{...}`; if the ghost
	//   assigns "magic" as a package rename target and the renamed package is
	//   imported as "magic", the local var and the import alias conflict.
	// "Grow": MemoryInstance.Grow() method; if WazeroOnlyType is renamed to "Grow"
	//   and embedded in MemoryInstance, the promoted field Grow conflicts with the method.
	"magic": true, "Grow": true,
	// wazero MemoryInstance method names — WazeroOnlyType is embedded in MemoryInstance;
	// if wot (WazeroOnlyType rename target) matches any MemoryInstance method name,
	// the promoted field collides with the method ("field and method with same name X").
	"Definition": true, "Size": true, "ReadByte": true, "ReadUint16Le": true,
	"ReadUint32Le": true, "ReadFloat32Le": true, "ReadUint64Le": true, "ReadFloat64Le": true,
	"Read": true, "WriteByte": true, "WriteUint16Le": true, "WriteUint32Le": true,
	"WriteFloat32Le": true, "WriteUint64Le": true, "WriteFloat64Le": true,
	"Write": true, "WriteString": true,
	// "zlib": main.go template imports "compress/zlib"; if a wazero sub-package
	//   is renamed to "zlib", both the stdlib and the internal import share the alias.
	// "shared": wazero internal/wasm/binary/memory.go and table.go declare
	//   `var shared bool`; if pkgWasm="shared", the local var shadows the import alias.
	"zlib": true, "shared": true,
	// Stdlib package names commonly used as import aliases in host/runtime/wazero source.
	// If the ghost pool assigns these to package renames or dead code functions,
	// they collide with the stdlib import alias of the same name in the same package.
	"html": true, "http": true, "url": true, "tls": true, "x509": true,
	"gzip": true, "hex": true, "base64": true,
	"xml": true, "pem": true, "tar": true, "big": true, "template": true,
	"pe": true, "bufio": true, "flag": true, "rpc": true,
	// Go "internal" package visibility: naming a sub-package "internal" creates
	// paths like "mod/internal/internal" which Go's internal-package rules block.
	"internal": true,
	// Hardcoded wazero rename targets (fsapi→ioutil, sysfs→osutil, regalloc→allocator).
	// If the ghost pool also assigns these names, the wazero rename silently
	// collides with another directory rename — producing duplicate package names.
	"ioutil": true, "osutil": true, "allocator": true,
	// Wazero source package names (the OLD names in WazeroTypeRenames).
	// If the ghost pool assigns these names as rename TARGETS for other packages,
	// chain substitutions occur: e.g., ieee754→wasip1 in source strings, then
	// wasip1→mem, resulting in both packages mapping to the same directory.
	"wasm": true, "ssa": true, "wasip1": true, "leb128": true, "ieee754": true,
	"wazevo": true, "wazevoapi": true, "assemblyscript": true, "wasmruntime": true,
	"internalapi": true, "interpreter": true, "emscripten": true, "filecache": true,
	"wasmdebug": true, "regalloc": true, "fsapi": true, "sysfs": true,
	// Wazero engine sub-package targets (codegen, compiler, emitter, lowering, etc.)
	// from realisticEnginePkgs — these are fixed rename targets that must not be
	// picked by the ghost pool for other packages.
	"codegen": true, "compiler": true, "emitter": true, "lowering": true,
	"engineapi": true, "backendapi": true, "targetapi": true, "machineapi": true,
	// Wazero sub-directory names that appear in the traefik ghost pool.
	// Assigning these as rename targets would collide with existing wazero dirs.
	"arm64": true, "backend": true, "frontend": true, "wazero": true,
	"imports": true, "proxy": true, "static": true,
	// Wazero package names that are NOT in the explicit rename list but exist
	// as directories in the wazero fork (internal/sys, internal/sock, etc.).
	// If the ghost pool assigns these names for other renames, the os.Rename
	// fails silently and two directories end up with the same package declaration.
	"sys": true, "sock": true, "api": true, "platform": true,
	"testing": true, "version": true, "u32": true, "u64": true,
	"diff": true, "multi": true, "logging": true, "moremath": true,
	// Wazero type names used as local struct names in core package. If a
	// wazero sub-package is renamed to one of these, the imported package
	// alias shadows the local type declaration ("already declared through
	// import of package X").
	"cache": true, "engine": true,
	// Wazero interpreter package defines local type "function struct". If the
	// ghost pool assigns the name "function" to any renamed sub-package (e.g.,
	// wasm→function), then the interpreter's import alias "function" collides
	// with the local type, causing "function (package name) is not a type".
	"function": true,
	// Local function and variable names that appear in wazero source and in the
	// host module stub files. If a wazero package or ghost stub function is
	// assigned one of these names, it collides with local declarations.
	// "format" collides with interpreter/format.go func format(...).
	// "base"   collides with wazevo/call_engine.go var base := uintptr(...).
	// "exec"   collides with os/exec package alias in host module files.
	// "user"   is handled above (see os/user section).
	"format": true, "base": true, "exec": true,
	// Wazero core package exported identifiers (functions and types). The
	// ghost profile's ExportedName() picks rename targets for CompilationCache
	// (cc), WazeroOnlyType (wot), etc. If ExportedName() returns a name that
	// already exists in the wazero core package (runtime.go, cache.go, etc.),
	// the rename creates duplicate declarations in the same package.
	// Block ALL exported identifiers from the wazero core package.
	"NewRuntime": true, "NewRuntimeWithConfig": true, "NewRuntimeConfig": true,
	"NewRuntimeConfigCompiler": true, "NewRuntimeConfigInterpreter": true,
	"NewCompilationCache": true, "NewCompilationCacheWithDir": true,
	"NewFSConfig": true, "NewModuleConfig": true,
	"CompilationCache": true, "CompiledModule": true, "FSConfig": true,
	"HostFunctionBuilder": true, "HostModuleBuilder": true, "ModuleConfig": true,
	"RuntimeConfig": true, "Runtime": true,
	// Block unexported identifiers from the wazero core package that are used
	// as %%WAZERO_RUNTIME_TYPE%% rename target (rt). If rt equals a type name
	// already in the core package (e.g., hostModuleBuilder, runtimeConfig, etc.),
	// the "runtime" struct rename creates a duplicate type declaration.
	"hostModuleBuilder": true, "runtimeConfig": true, "hostFunctionBuilder": true,
	"compiledModule": true, "moduleConfig": true, "fsConfig": true,
	"hostModuleInstance": true,
	// Also block stdlib identifier "user" — "os/user" imports as alias "user",
	// which collides with any generated function named "user" in the same package.
	"user": true,
	// Wazero SSA package ("ssa") is frequently renamed by ghost profiles.
	// The SSA package is imported as "ssa" in wazevo source files, but those
	// same files use local variables named "store", "pass", "builder", "instr",
	// "block", "phi", etc. Renaming "ssa" to any of these causes the imported
	// package alias to be shadowed by a local variable.
	"store": true, "pass": true, "builder": true, "instr": true, "phi": true,
	"reg": true, "mem": true, "abi": true, "isa": true,
	// Common Go local variable names that frequently appear as parameter/loop
	// variable names in Go source files. If a wazero sub-package is renamed to
	// one of these, it collides with local variables in the same function scope
	// (e.g., "label already declared through import of package label").
	"label": true, "module": true, "debug": true, "table": true, "types": true,
	"code": true, "block": true, "index": true, "value": true,
	"token": true, "state": true, "stack": true, "frame": true,
	"input": true, "output": true, "result": true, "target": true,
	"source": true, "buffer": true, "offset": true, "length": true,
	"config": true, "signal": true, "status": true, "params": true,
	"header": true, "body": true, "field": true, "entry": true,
	"count": true, "limit": true, "start": true, "size": true,
	"data": true, "info": true, "node": true, "root": true,
	"left": true, "right": true, "next": true, "prev": true,
	"args": true, "opts": true, "spec": true, "desc": true,
	"file": true, "line": true, "col": true, "row": true,
	"name": true, "key": true, "val": true, "typ": true,
	"expr": true, "stmt": true, "decl": true, "def": true,
	"msg": true, "req": true, "resp": true, "err": true,
	"ctx": true, "obj": true, "ref": true, "ptr": true,
	"op": true, "fn": true, "cb": true, "id": true,
	"v": true, "r": true, "w": true, "s": true, "b": true,
	"n": true, "m": true, "e": true, "f": true, "p": true,
	"t": true, "c": true, "k": true, "u": true, "x": true,
	"a": true, "d": true, "g": true, "h": true, "i": true,
	"j": true, "l": true, "q": true, "y": true, "z": true,
}

// Default prefix pool — generic developer verbs.
var defaultPrefixes = []string{
	"parse", "load", "read", "write", "get", "set", "put",
	"check", "validate", "process", "handle", "create", "build",
	"format", "encode", "decode", "transform", "resolve", "compute",
	"apply", "merge", "flush", "sync", "reset", "open",
	"fetch", "store", "marshal", "render", "dispatch",
	"acquire", "release", "lookup", "register", "notify",
	"prepare", "compile", "bind", "attach", "detach",
	"scan", "collect", "aggregate", "filter", "sort",
	"wrap", "unwrap", "pack", "unpack", "inflate",
	"schedule", "execute", "invoke", "emit", "drain",
}

// Default suffix pool — generic developer nouns.
var defaultSuffixes = []string{
	"Config", "Buffer", "Cache", "Entry", "Table",
	"Index", "State", "Queue", "Pool", "Worker",
	"Handler", "Manager", "Provider", "Service", "Context",
	"Result", "Params", "Options", "Metadata", "Registry",
	"Factory", "Builder", "Parser", "Encoder", "Decoder",
	"Filter", "Router", "Mapper", "Tracker", "Counter",
	"Batch", "Chunk", "Frame", "Header", "Payload",
	"Token", "Session", "Channel", "Stream", "Pipeline",
	"Bucket", "Segment", "Record", "Schema", "Layout",
	"Metric", "Event", "Signal", "Task", "Job",
}

// newWordList creates a word list, loading a custom dictionary from
// WASMFORGE_WORDLIST if set, otherwise using the built-in defaults.
func newWordList() *wordList {
	wl := &wordList{
		prefixes: defaultPrefixes,
		suffixes: defaultSuffixes,
	}

	// Allow custom dictionary override.
	if path := os.Getenv("WASMFORGE_WORDLIST"); path != "" {
		if custom, err := loadCustomWordList(path); err == nil {
			wl = custom
		}
	}

	return wl
}

// loadCustomWordList reads a word list file. Format: prefixes (one per line),
// blank line separator, suffixes (one per line).
func loadCustomWordList(path string) (*wordList, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}

	parts := strings.SplitN(string(data), "\n\n", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("wordlist must have prefixes and suffixes separated by blank line")
	}

	prefixes := filterEmpty(strings.Split(strings.TrimSpace(parts[0]), "\n"))
	suffixes := filterEmpty(strings.Split(strings.TrimSpace(parts[1]), "\n"))

	if len(prefixes) == 0 || len(suffixes) == 0 {
		return nil, fmt.Errorf("wordlist must have at least one prefix and one suffix")
	}

	return &wordList{prefixes: prefixes, suffixes: suffixes}, nil
}

// generate produces a unique identifier by combining a random prefix and
// suffix. The used set prevents collisions within a build. Returns
// identifiers like "parseBuffer", "loadConfig", "syncRegistry".
func (wl *wordList) generate(used map[string]bool) string {
	for attempts := 0; attempts < 1000; attempts++ {
		prefix := wl.prefixes[cryptoRandN(len(wl.prefixes))]
		suffix := wl.suffixes[cryptoRandN(len(wl.suffixes))]
		name := prefix + suffix

		if !goReserved[name] && !goReserved[strings.ToLower(name)] && !used[name] {
			used[name] = true
			return name
		}
	}
	// Fallback: add random suffix digits.
	name := fmt.Sprintf("%s%s%d",
		wl.prefixes[cryptoRandN(len(wl.prefixes))],
		wl.suffixes[cryptoRandN(len(wl.suffixes))],
		cryptoRandN(9999))
	used[name] = true
	return name
}

// generateExported produces an exported (capitalized) identifier.
func (wl *wordList) generateExported(used map[string]bool) string {
	for attempts := 0; attempts < 1000; attempts++ {
		prefix := wl.prefixes[cryptoRandN(len(wl.prefixes))]
		suffix := wl.suffixes[cryptoRandN(len(wl.suffixes))]
		// Capitalize prefix for export.
		name := strings.ToUpper(prefix[:1]) + prefix[1:] + suffix
		if !goReserved[name] && !used[name] {
			used[name] = true
			return name
		}
	}
	name := fmt.Sprintf("%s%s%d",
		strings.Title(wl.prefixes[cryptoRandN(len(wl.prefixes))]),
		wl.suffixes[cryptoRandN(len(wl.suffixes))],
		cryptoRandN(9999))
	used[name] = true
	return name
}

// generateN produces n unique identifiers.
func (wl *wordList) generateN(n int, used map[string]bool) []string {
	names := make([]string, n)
	for i := range names {
		names[i] = wl.generate(used)
	}
	return names
}

func filterEmpty(ss []string) []string {
	var out []string
	for _, s := range ss {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// cryptoRandN returns a cryptographically random int in [0, n).
func cryptoRandN(n int) int {
	if n <= 0 {
		return 0
	}
	v, _ := rand.Int(rand.Reader, big.NewInt(int64(n)))
	return int(v.Int64())
}
