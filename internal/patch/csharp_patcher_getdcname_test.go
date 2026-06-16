package patch

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetDCNamePatchRulePresent verifies the GetDCName redirect rule exists in
// NativeAOTCSharpPatches and applies correctly to a representative Networking.cs
// snippet. Root cause: DsGetDcNameW writes DOMAIN_CONTROLLER_INFO with 64-bit
// host LPWSTR pointers; Marshal.PtrToStructure copies them into wasm32 memory
// but the char* fields still point to host addresses — walking off linear memory
// with IndexOfNullCharacter causes OOB traps in tgtdeleg/diamond.
func TestGetDCNamePatchRulePresent(t *testing.T) {
	patches := NativeAOTCSharpPatches()

	// Find the GetDCName rule.
	var rule *CSharpPatch
	for i := range patches {
		if strings.Contains(patches[i].Description, "GetDCName") &&
			strings.Contains(patches[i].Description, "host bridge") {
			rule = &patches[i]
			break
		}
	}
	require.NotNil(t, rule, "expected a CSharpPatch rule with description containing 'GetDCName' and 'host bridge'")
	assert.Equal(t, "**/Networking.cs", rule.FileGlob, "rule must target Networking.cs")

	// The Old pattern must match the actual Rubeus method signature verbatim.
	assert.Contains(t, rule.Old, `public static string GetDCName(string domainName = "")`,
		"rule.Old must start with the canonical GetDCName signature from Networking.cs")

	// The New replacement must contain the WasmForge bridge redirect.
	assert.Contains(t, rule.New, "WasmForge.Bridge.NetworkHostHelper.GetDCIP",
		"rule.New must redirect to NetworkHostHelper.GetDCIP")

	// DS_RETURN_DNS_NAME flag ensures we get the FQDN.
	assert.Contains(t, rule.New, "0x00000010",
		"rule.New must set DS_RETURN_DNS_NAME flag (0x00000010)")
}

// TestGetDCNamePatchApplied simulates the string-replacement applied by
// applyPatchToFile on a representative Networking.cs snippet and confirms
// (a) the OOB-prone DsGetDcName + Marshal.PtrToStructure path is replaced,
// (b) the host bridge call is present.
func TestGetDCNamePatchApplied(t *testing.T) {
	// Minimal representative Networking.cs snippet from Rubeus.
	original := `        public static string GetDCName(string domainName = "")
        {
            // retrieves the current domain controller name
            Interop.DOMAIN_CONTROLLER_INFO domainInfo;
            const int ERROR_SUCCESS = 0;
            IntPtr pDCI = IntPtr.Zero;

            int val = Interop.DsGetDcName("", domainName, 0, "",
                Interop.DSGETDCNAME_FLAGS.DS_DIRECTORY_SERVICE_REQUIRED |
                Interop.DSGETDCNAME_FLAGS.DS_RETURN_DNS_NAME |
                Interop.DSGETDCNAME_FLAGS.DS_IP_REQUIRED, out pDCI);

            if (ERROR_SUCCESS == val) {
                domainInfo = (Interop.DOMAIN_CONTROLLER_INFO)Marshal.PtrToStructure(pDCI, typeof(Interop.DOMAIN_CONTROLLER_INFO));
                string dcName = domainInfo.DomainControllerName;
                Interop.NetApiBufferFree(pDCI);
                return dcName.Trim('\\');
            }
            else {
                return "";
            }
        }`

	patches := NativeAOTCSharpPatches()

	var applied string
	for _, p := range patches {
		if strings.Contains(p.Description, "GetDCName") &&
			strings.Contains(p.Description, "host bridge") {
			applied = strings.ReplaceAll(original, p.Old, p.New)
			break
		}
	}

	require.NotEmpty(t, applied, "no GetDCName rule found in NativeAOTCSharpPatches")

	// Verify the replacement happened (content changed).
	assert.NotEqual(t, original, applied, "patch must modify the source")

	// Verify the bridge redirect is present.
	assert.Contains(t, applied, "WasmForge.Bridge.NetworkHostHelper.GetDCIP",
		"patched source must contain host bridge call")

	// Verify the OOB-prone Marshal.PtrToStructure path is no longer reached
	// without first returning via the bridge (bridge returns early before the
	// original body executes).
	assert.Contains(t, applied, "if (wfResult != null) return",
		"patched source must have early return on successful bridge call")
}
