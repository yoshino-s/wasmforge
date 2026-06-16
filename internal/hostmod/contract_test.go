package hostmod

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestEnvExportsMatchContract enumerates every Export(export("<name>")) call
// across internal/hostmod/*.go and cross-references it against the contract
// document at docs/internals/HOST-API-CONTRACT.md. The contract is the source
// of truth; adding a new export without a matching contract row fails CI.
// Removing an export that's still documented in the contract also fails
// (the documentation row should be removed at the same time).
func TestEnvExportsMatchContract(t *testing.T) {
	codeExports, err := exportsFromCode(".")
	if err != nil {
		t.Fatalf("scanning hostmod source: %v", err)
	}
	docExports, err := exportsFromContract("../../docs/internals/HOST-API-CONTRACT.md")
	if err != nil {
		t.Fatalf("parsing contract: %v", err)
	}

	// Anything in code but not documented => fail.
	for _, name := range codeExports {
		if _, ok := docExports[name]; !ok {
			t.Errorf("undocumented env export: %s (add a row in docs/internals/HOST-API-CONTRACT.md or remove the Export call)", name)
		}
	}
	// Anything documented but not in code => fail.
	for name := range docExports {
		found := false
		for _, c := range codeExports {
			if c == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("stale contract row: %s (no matching Export(export(\"%s\")) found — remove the row)", name, name)
		}
	}
}

var exportRe = regexp.MustCompile(`Export\(export\("([a-z][a-z0-9_]*)"\)\)`)

func exportsFromCode(hostmodDir string) ([]string, error) {
	out := map[string]bool{}
	err := filepath.WalkDir(hostmodDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		scan := bufio.NewScanner(f)
		scan.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scan.Scan() {
			m := exportRe.FindStringSubmatch(scan.Text())
			if m != nil {
				out[m[1]] = true
			}
		}
		return scan.Err()
	})
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(out))
	for n := range out {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

// contractRowRe matches the canonical (Go-side) name in a table row.
// Contract tables use the format:
//
//	| canonical_name | anonymized_name | Category | Rationale |
//
// The canonical name is always a lowercase identifier in the first column.
var contractRowRe = regexp.MustCompile(`^\|\s*([a-z][a-z0-9_]*)\s*\|`)

// retiredSectionRe matches any heading that indicates a "retired" or
// "out-of-scope" section. Rows in such sections are excluded from
// enforcement — they document what was removed, not what is present.
var retiredSectionRe = regexp.MustCompile(`(?i)^#{1,6}\s+(retired|out-of-scope)`)

func exportsFromContract(path string) (map[string]bool, error) {
	out := map[string]bool{}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	inRetiredSection := false
	for scan.Scan() {
		line := scan.Text()
		// Track section headings.
		if strings.HasPrefix(line, "#") {
			inRetiredSection = retiredSectionRe.MatchString(line)
		}
		if inRetiredSection {
			continue
		}
		m := contractRowRe.FindStringSubmatch(line)
		if m != nil {
			out[m[1]] = true
		}
	}
	return out, scan.Err()
}
