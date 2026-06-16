package patch

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBruteParseUsersPatchRulePresent verifies the rule exists in the patch table.
func TestBruteParseUsersPatchRulePresent(t *testing.T) {
	patches := NativeAOTCSharpPatches()

	var rule *CSharpPatch
	for i := range patches {
		if strings.Contains(patches[i].Description, "Brute.ParseUsers") &&
			strings.Contains(patches[i].Description, "inline-list") {
			rule = &patches[i]
			break
		}
	}
	require.NotNil(t, rule, "expected a CSharpPatch rule with description containing 'Brute.ParseUsers' and 'inline-list'")
	assert.Equal(t, "**/Commands/Brute.cs", rule.FileGlob, "rule must target Commands/Brute.cs")

	// Old must match the exact upstream try/catch block verbatim.
	assert.Contains(t, rule.Old, "File.ReadAllLines(arguments[\"/users\"])",
		"rule.Old must contain the upstream ReadAllLines call")
	assert.Contains(t, rule.Old, "catch (FileNotFoundException)",
		"rule.Old must include the upstream FileNotFoundException catch")

	// New must implement inline-list-first heuristic.
	assert.Contains(t, rule.New, "IndexOf(',') < 0",
		"rule.New must check for comma absence (if no comma → treat as file path or single user)")
	assert.Contains(t, rule.New, "Split(',', StringSplitOptions.RemoveEmptyEntries)",
		"rule.New must split on comma for inline lists")
	assert.Contains(t, rule.New, "File.ReadAllLines",
		"rule.New must still support file-path mode for Windows-style paths")
}

// TestBruteParseUsersPatchApplied verifies the rule transforms upstream source correctly.
func TestBruteParseUsersPatchApplied(t *testing.T) {
	// Verbatim excerpt from Commands/Brute.cs (lines 169-176).
	original := `            if (arguments.ContainsKey("/users"))
            {
                try {
                    this.usernames = File.ReadAllLines(arguments["/users"]);
                }catch (FileNotFoundException)
                {
                    throw new BruteArgumentException("[X] Unable to open users file \"" + arguments["/users"] + "\": Not found file");
                }
            }`

	patches := NativeAOTCSharpPatches()

	var applied string
	for _, p := range patches {
		if strings.Contains(p.Description, "Brute.ParseUsers") &&
			strings.Contains(p.Description, "inline-list") {
			applied = strings.ReplaceAll(original, p.Old, p.New)
			break
		}
	}

	require.NotEmpty(t, applied, "no Brute.ParseUsers rule found in NativeAOTCSharpPatches")
	assert.NotEqual(t, original, applied, "patch must modify the source")

	// The patched source must handle a bare username (no path separator, no comma)
	// as an inline single-element list — not attempt File.ReadAllLines.
	assert.Contains(t, applied, "IndexOf(',') < 0",
		"patched source must contain comma-absence check")
	assert.Contains(t, applied, "Split(',', StringSplitOptions.RemoveEmptyEntries)",
		"patched source must split comma-separated users")
}
