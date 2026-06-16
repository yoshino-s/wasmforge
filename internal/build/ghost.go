package build

import (
	"embed"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

// Embeds all *.json files in ghost_profiles. Files prefixed with `_` are
// retained for historical reference but filtered out by ListGhostProfiles
// (e.g., _caddy.json was disabled in v0.5.5 after VT correlation showed 59%
// detection vs traefik's 17%).
//go:embed ghost_profiles/*.json
var ghostProfilesFS embed.FS

// GhostProfile holds harvested gopclntab names from a real Go binary.
type GhostProfile struct {
	Name           string              `json:"name"`
	Source         string              `json:"source"`
	ModulePath     string              `json:"module_path"`
	Packages       []string            `json:"packages"`
	Functions      map[string][]string `json:"functions"`
	Types          map[string][]string `json:"types"`
	Methods        map[string][]string `json:"methods"`
	TotalFunctions int                 `json:"total_functions"`
	TotalPackages  int                 `json:"total_packages"`

	// flatFunctions is lazily built from Functions + Methods across all packages.
	flatFunctions []string
	// flatExported is lazily built: only names with an uppercase first letter.
	flatExported []string
	// flatPkgSegments is lazily built from last path components of Packages.
	flatPkgSegments []string
}

// LoadGhostProfile loads a named profile from the embedded ghost_profiles directory.
func LoadGhostProfile(name string) (*GhostProfile, error) {
	data, err := ghostProfilesFS.ReadFile("ghost_profiles/" + name + ".json")
	if err != nil {
		return nil, fmt.Errorf("ghost profile %q not found: %w", name, err)
	}
	var gp GhostProfile
	if err := json.Unmarshal(data, &gp); err != nil {
		return nil, fmt.Errorf("parsing ghost profile %q: %w", name, err)
	}
	return &gp, nil
}

// ListGhostProfiles returns the names of all embedded ghost profiles (excluding
// the placeholder).
func ListGhostProfiles() []string {
	entries, err := ghostProfilesFS.ReadDir("ghost_profiles")
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if !strings.HasSuffix(n, ".json") {
			continue
		}
		base := strings.TrimSuffix(n, ".json")
		if strings.HasPrefix(base, "_") {
			continue
		}
		names = append(names, base)
	}
	return names
}

// LoadRandomGhostProfile picks a random embedded profile using cryptoRandN.
// Returns an error only if no non-placeholder profiles are available; in that
// case callers should fall back to wordList.
func LoadRandomGhostProfile() (*GhostProfile, error) {
	names := ListGhostProfiles()
	if len(names) == 0 {
		return nil, fmt.Errorf("no ghost profiles available")
	}
	name := names[cryptoRandN(len(names))]
	return LoadGhostProfile(name)
}

// ModuleName returns a short, filesystem-safe identifier derived from the
// profile's module path. Version suffixes (/v2, /v3, …) are stripped.
// Examples:
//
//	"github.com/traefik/traefik/v3" → "traefik"
//	"github.com/hashicorp/vault"    → "vault"
//	"placeholder"                   → "placeholder"
func (g *GhostProfile) ModuleName() string {
	mp := g.ModulePath
	// Strip trailing version component (/vN).
	if idx := strings.LastIndex(mp, "/v"); idx >= 0 {
		tail := mp[idx+2:]
		allDigit := len(tail) > 0
		for _, c := range tail {
			if c < '0' || c > '9' {
				allDigit = false
				break
			}
		}
		if allDigit {
			mp = mp[:idx]
		}
	}
	// Take the last path segment.
	if idx := strings.LastIndex(mp, "/"); idx >= 0 {
		mp = mp[idx+1:]
	}
	if mp == "" {
		return "app"
	}
	return mp
}

// buildFlat populates the lazy flat name slices on first call.
func (g *GhostProfile) buildFlat() {
	if g.flatFunctions != nil {
		return
	}
	seen := make(map[string]bool)
	add := func(name string) {
		if name == "" || goReserved[name] || seen[name] || !isValidPkgName(name) {
			return
		}
		seen[name] = true
		g.flatFunctions = append(g.flatFunctions, name)
		if len(name) > 0 && name[0] >= 'A' && name[0] <= 'Z' {
			g.flatExported = append(g.flatExported, name)
		}
	}

	// Harvest functions across all packages.
	for _, fns := range g.Functions {
		for _, fn := range fns {
			add(fn)
		}
	}
	// Harvest method names across all types in all packages.
	for _, methods := range g.Methods {
		for _, m := range methods {
			add(m)
		}
	}

	// Build package segment list.
	// VT testing (n=38, 2026-03-23/24) showed strong correlation between
	// RuntimePkg name characteristics and Microsoft Wacatac detection:
	//   Clean avg: 4.4 chars (jwt, apis, bpf, fake, dns01, ecdsa, qr, ops)
	//   Detected avg: 5.8+ chars (fsnotify, sockets, redirect, httpguts)
	// Names ≤5 chars and generic/crypto-sounding pass; network/system names flag.
	pkgSeen := make(map[string]bool)
	for _, pkg := range g.Packages {
		seg := filepath.Base(pkg)
		if seg == "" || seg == "." || !isValidPkgName(seg) || len(seg) < 3 || len(seg) > 5 || pkgSeen[seg] || goReserved[seg] {
			continue
		}
		if pkgSegmentBlocklisted[seg] {
			continue
		}
		pkgSeen[seg] = true
		g.flatPkgSegments = append(g.flatPkgSegments, seg)
	}
}

// FunctionName returns a random real function name from the ghost profile,
// avoiding collisions tracked in used. Falls back to the default wordList
// generate() when the ghost pool is exhausted or empty.
func (g *GhostProfile) FunctionName(used map[string]bool) string {
	g.buildFlat()
	if len(g.flatFunctions) > 0 {
		if name := pickUnused(g.flatFunctions, used); name != "" {
			return name
		}
	}
	// Fall back to the default wordList.
	return newWordList().generate(used)
}

// ExportedName returns a random exported (capitalized) name from the ghost
// profile. Falls back to wordList generateExported() when exhausted.
func (g *GhostProfile) ExportedName(used map[string]bool) string {
	g.buildFlat()
	if len(g.flatExported) > 0 {
		if name := pickUnused(g.flatExported, used); name != "" {
			return name
		}
	}
	return newWordList().generateExported(used)
}

// PackageSegment returns a real package-path last-segment from the ghost.
// The category hint is accepted for API compatibility but not used — names are
// picked randomly from the available pool to avoid category-based guessing.
func (g *GhostProfile) PackageSegment(category string, used map[string]bool) string {
	g.buildFlat()
	if len(g.flatPkgSegments) > 0 {
		if seg := pickUnused(g.flatPkgSegments, used); seg != "" {
			return seg
		}
	}
	// Fall back to a generated lowercase name.
	return strings.ToLower(newWordList().generate(used))
}

// PackagePool returns count unique package-path last-segments from the ghost.
// It uses an internal fresh used-map, so results may collide with names
// returned by other PackagePool/PackageSegment calls that used different maps.
// Prefer PackagePoolWithUsed when coordination across calls is required.
func (g *GhostProfile) PackagePool(count int) []string {
	return g.PackagePoolWithUsed(count, make(map[string]bool))
}

// PackagePoolWithUsed returns count unique package-path last-segments,
// recording each into pkgUsed to prevent collisions with previously-selected
// names (and with names selected by subsequent calls using the same map).
func (g *GhostProfile) PackagePoolWithUsed(count int, pkgUsed map[string]bool) []string {
	g.buildFlat()
	result := make([]string, 0, count)
	for len(result) < count {
		// PackageSegment records the chosen name into pkgUsed, so each call
		// returns a different segment.
		seg := g.PackageSegment("", pkgUsed)
		result = append(result, seg)
	}
	return result
}

// DeadCodePackages generates dead-code package source strings using real ghost
// names. Each entry in the returned map is "internal/<pkgname>" → Go source
// string. Each source file has:
//   - package declaration
//   - imports (sync, time)
//   - a struct with ghost type names as fields
//   - functions with ghost function names
//   - an init() that references them to prevent DCE
//
// pkgNameUsed is a shared map of already-used package names. Passing a
// pre-populated map prevents the generated package names from colliding with
// names chosen for wazero sub-package renames or hostmod/runtime/names
// packages. If nil, a fresh map is used (legacy behavior, may collide).
func (g *GhostProfile) DeadCodePackages(count, funcsPerPkg int, pkgNameUsed map[string]bool) map[string]string {
	g.buildFlat()
	if pkgNameUsed == nil {
		pkgNameUsed = make(map[string]bool)
	}
	fnUsed := make(map[string]bool)

	result := make(map[string]string, count)
	for i := 0; i < count; i++ {
		pkgSeg := g.PackageSegment("", pkgNameUsed)

		importPath := "internal/" + pkgSeg
		src := g.buildDeadCodeSource(pkgSeg, funcsPerPkg, fnUsed)
		result[importPath] = src
	}
	return result
}

// buildDeadCodeSource produces a single Go source file for a dead-code package.
func (g *GhostProfile) buildDeadCodeSource(pkgName string, funcsPerPkg int, fnUsed map[string]bool) string {
	var sb strings.Builder

	// Package declaration and imports.
	fmt.Fprintf(&sb, "package %s\n\nimport (\n\t\"sync\"\n\t\"time\"\n)\n\n", pkgName)

	// Pick a struct name from exported ghost names. Use fnUsed (the shared
	// function-name map) so the struct name and all function names are tracked
	// in the same map — preventing the struct and a function in the same
	// package from receiving the same name ("redeclared in this block").
	structName := g.ExportedName(fnUsed)

	// Struct with time.Time and sync.Mutex fields to reference both imports.
	fmt.Fprintf(&sb, "type %s struct {\n\tmu    sync.Mutex\n\tstamp time.Time\n}\n\n", structName)

	// Pick function names first so init() and stubs reference the same names.
	names := make([]string, funcsPerPkg)
	for j := range names {
		names[j] = g.FunctionName(fnUsed)
	}

	// init() references struct and all stub functions to prevent DCE.
	fmt.Fprintf(&sb, "func init() {\n\tvar _ %s\n", structName)
	for _, fn := range names {
		fmt.Fprintf(&sb, "\t_ = %s\n", fn)
	}
	fmt.Fprintf(&sb, "}\n\n")

	// Emit stub function declarations.
	for _, fn := range names {
		fmt.Fprintf(&sb, "func %s() {}\n", fn)
	}

	return sb.String()
}

// pkgSegmentBlocklisted contains names that trigger ML classifiers when used
// as the wazero fork RuntimePkg (appears in ~1,700+ gopclntab entries).
// Names relating to networking, system internals, credentials, or common
// Go package names score higher on Microsoft Wacatac.B!ml.
var pkgSegmentBlocklisted = map[string]bool{
	// Self-referential / collides with wazero internals
	"core": true, "wasm": true, "wasi": true, "api": true,
	// Contains "github" or VCS terms
	"git": true, "repo": true,
	// Network/system terms (flag ML classifiers, VT tested 2026-03-24)
	"net": true, "http": true, "tcp": true, "udp": true, "dns": true,
	"sock": true, "unix": true, "exec": true, "proc": true, "ssh": true,
	"tls": true, "ssl": true, "grpc": true, "ping": true, "cidr": true,
	// Additional network/protocol terms (CS-hit in R33/R34, 2026-06-11):
	"ipv6": true, "ipv4": true, "netip": true, "icmp": true,
	"vlan": true, "wol": true, "arp": true, "nat": true, "rip": true,
	// MS Wacatac wave detection terms (R48, 2026-06-12):
	"http2": true, "yamux": true, "mux": true, "ndr": true,
	"xsync": true, "watch": true, "rest": true, "fake": true,
	"job": true, "cty": true,
	// Crypto cipher/primitive names — CrowdStrike Falcon flags strongly
	// (R33: zstd; R34: pkix, salsa, rc2 → all CS hits)
	"zstd": true, "salsa": true, "rc2": true, "rc4": true, "rc5": true, "rc6": true,
	"pkix": true, "des": true, "aes": true, "rsa": true, "dsa": true,
	"ecdh": true, "ecc": true, "gcm": true, "ctr": true, "cbc": true,
	"ecb": true, "ofb": true, "cfb": true, "xts": true, "ccm": true,
	"hmac": true, "sha": true, "md5": true, "blake": true, "kdf": true,
	// Well-known Go libraries (R33: logr; R34: viper → CS hits)
	"logr": true, "viper": true, "cobra": true, "gorm": true, "gin": true,
	// Credential/auth/security terms
	"auth": true, "cred": true, "token": true, "login": true,
	"cert": true, "oauth": true, "xray": true,
	// System/debug terms that flag as suspicious
	"trace": true, "idle": true, "term": true, "model": true,
	"util": true, "codes": true, "typed": true,
	// Go stdlib collision
	"io": true, "os": true, "fmt": true, "log": true, "sys": true,
	"sync": true, "time": true, "math": true, "sort": true,
}

// isValidPkgName reports whether name is a valid Go identifier (letters,
// digits, underscore only; must start with letter or underscore). Package path
// segments like "yaml.v3" or "wasi-go" contain dots/hyphens that would produce
// invalid import paths if used directly.
func isValidPkgName(name string) bool {
	if len(name) == 0 {
		return false
	}
	for i, c := range name {
		if i == 0 {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_') {
				return false
			}
		} else {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
				return false
			}
		}
	}
	return true
}

// pickUnused picks a random element from pool that is not in used. On success
// it records the name in used and returns it. Returns "" if all pool entries
// are exhausted.
func pickUnused(pool []string, used map[string]bool) string {
	if len(pool) == 0 {
		return ""
	}
	// Up to len(pool) random tries before giving up.
	for attempts := 0; attempts < len(pool); attempts++ {
		name := pool[cryptoRandN(len(pool))]
		if !used[name] {
			used[name] = true
			return name
		}
	}
	// Linear scan as final fallback.
	for _, name := range pool {
		if !used[name] {
			used[name] = true
			return name
		}
	}
	return ""
}
