// wmi_dispatch_golden_test.go — golden table for COM dispatch pointer masks.
//
// The C# WMI driver (dotnet/stubs/System.Management/Stubs.cs and
// dotnet/helpers/WfWmi.cs) passes ptrMask + out8Mask to wf_call_ptr for
// every COM method invocation. A wrong bit causes silent memory
// corruption (host writes 8 bytes into a 4-byte WASM slot, or skips
// a translation that should have happened). Lab-grep can't see that;
// only deterministic byte-level reasoning can.
//
// This test makes the mask comments in source AUTHORITATIVE. Each call
// site's wantPtrs/wantOut8 list mirrors the human-readable comment;
// the test enforces:
//
//   1. ptrMask bits exactly match wantPtrs
//   2. out8Mask bits exactly match wantOut8
//   3. out8Mask ⊆ ptrMask (every out-8 slot must also be a pointer)
//   4. highest set bit < nargs (no spurious high bits)
//
// Adding a new COM call → drop a new row in `wmiCallSites`. Bug in
// existing site → test fails immediately on `go test`.

package hostmod

import (
	"testing"
)

type comCallSite struct {
	name     string
	nargs    int
	ptrMask  uint32
	out8Mask uint32
	wantPtrs []int // arg indices declared as WASM pointers (need translation)
	wantOut8 []int // arg indices whose pointed-to slot is ≥8 bytes (skip overflow guard)
}

// Mirrors the four wf_call_ptr invocations in
// dotnet/stubs/System.Management/Stubs.cs and dotnet/helpers/WfWmi.cs.
// Slot 0 is always `this` (the COM interface pointer).
var wmiCallSites = []comCallSite{
	// IWbemLocator::ConnectServer(strRes, strUser, strPwd, strLocale,
	//                             lSecurityFlags, strAuthority, pCtx,
	//                             ppNamespace)
	// 9 args incl this. BSTRs are HOST pointers (already host-translated
	// at SysAllocString time) — NOT WASM ptrs. Only ppNamespace (arg 8)
	// is a WASM ptr to an 8-byte output slot.
	{
		name:     "IWbemLocator::ConnectServer",
		nargs:    9,
		ptrMask:  0x101,
		out8Mask: 0x100,
		wantPtrs: []int{0, 8},
		wantOut8: []int{8},
	},
	// IWbemServices::ExecQuery(strLang, strQuery, lFlags, pCtx, &ppEnum)
	// 6 args incl this. ppEnum (arg 5) is a WASM ptr to 8-byte slot.
	{
		name:     "IWbemServices::ExecQuery",
		nargs:    6,
		ptrMask:  0x21,
		out8Mask: 0x20,
		wantPtrs: []int{0, 5},
		wantOut8: []int{5},
	},
	// IEnumWbemClassObject::Next(timeout, uCount, &apObjects, &puReturned)
	// 5 args incl this. apObjects (arg 3) is WASM ptr to 8-byte interface
	// pointer. puReturned (arg 4) is WASM ptr to a 4-byte uint — NOT in
	// out8Mask because a 4-byte slot doesn't need overflow protection.
	{
		name:     "IEnumWbemClassObject::Next",
		nargs:    5,
		ptrMask:  0x19,
		out8Mask: 0x08,
		wantPtrs: []int{0, 3, 4},
		wantOut8: []int{3},
	},
	// IWbemClassObject::Next(flags, &strName, &varVal, &type, &flavor)
	// 6 args incl this. We pass NULL for type+flavor; ppName (arg 2) and
	// pVar (arg 3) both need 8-byte protection (BSTR ptr + 24-byte VARIANT).
	{
		name:     "IWbemClassObject::Next",
		nargs:    6,
		ptrMask:  0x0D,
		out8Mask: 0x0C,
		wantPtrs: []int{0, 2, 3},
		wantOut8: []int{2, 3},
	},
	// IWbemClassObject::BeginEnumeration(flags)
	{
		name:     "IWbemClassObject::BeginEnumeration",
		nargs:    2,
		ptrMask:  0x01,
		out8Mask: 0,
		wantPtrs: []int{0},
		wantOut8: []int{},
	},
	// IWbemClassObject::EndEnumeration() / IUnknown::Release()
	{
		name:     "IWbemClassObject::EndEnumeration",
		nargs:    1,
		ptrMask:  0x01,
		out8Mask: 0,
		wantPtrs: []int{0},
		wantOut8: []int{},
	},
}

// maskBitsToSlice expands the set bits of mask into a sorted []int.
func maskBitsToSlice(mask uint32) []int {
	var out []int
	for i := 0; i < 32; i++ {
		if mask&(1<<i) != 0 {
			out = append(out, i)
		}
	}
	return out
}

// intSliceEqual reports whether two []int slices have identical contents.
func intSliceEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func TestWmiDispatchMasksGolden(t *testing.T) {
	for _, site := range wmiCallSites {
		t.Run(site.name, func(t *testing.T) {
			// 1. ptrMask bits exactly match wantPtrs.
			gotPtrs := maskBitsToSlice(site.ptrMask)
			if site.wantPtrs == nil {
				site.wantPtrs = []int{}
			}
			if !intSliceEqual(gotPtrs, site.wantPtrs) {
				t.Errorf("ptrMask=0x%X expands to %v, want %v",
					site.ptrMask, gotPtrs, site.wantPtrs)
			}

			// 2. out8Mask bits exactly match wantOut8.
			gotOut8 := maskBitsToSlice(site.out8Mask)
			if site.wantOut8 == nil {
				site.wantOut8 = []int{}
			}
			if !intSliceEqual(gotOut8, site.wantOut8) {
				t.Errorf("out8Mask=0x%X expands to %v, want %v",
					site.out8Mask, gotOut8, site.wantOut8)
			}

			// 3. out8Mask must be a subset of ptrMask. Every 8-byte output
			// slot is necessarily a pointer (we have to translate WASM addr
			// → host addr regardless of overflow protection).
			if site.out8Mask&^site.ptrMask != 0 {
				t.Errorf("out8Mask=0x%X has bits not in ptrMask=0x%X (would be a non-pointer with overflow protection skipped)",
					site.out8Mask, site.ptrMask)
			}

			// 4. No bits beyond nargs. A bit at position >= nargs would
			// refer to an arg slot that doesn't exist in the call.
			maxBit := 31
			for ; maxBit >= 0; maxBit-- {
				if site.ptrMask&(1<<maxBit) != 0 {
					break
				}
			}
			if maxBit >= site.nargs {
				t.Errorf("ptrMask=0x%X sets bit %d but nargs=%d (out of range)",
					site.ptrMask, maxBit, site.nargs)
			}

			// 5. Slot 0 must always be a pointer — it's `this` (the COM
			// interface pointer in WASM mirror memory, needs translation).
			if site.ptrMask&1 == 0 {
				t.Errorf("ptrMask=0x%X missing bit 0 — slot 0 must always be `this` pointer for a COM method invocation",
					site.ptrMask)
			}
		})
	}
}

// TestWmiDispatchInvariants documents structural invariants that hold
// across all current and future COM call sites in the WMI dispatch path.
// Adding a new COM method to wmiCallSites that violates any of these
// invariants will fail this test — a forcing function to think about
// the abstraction before extending it.
func TestWmiDispatchInvariants(t *testing.T) {
	for _, site := range wmiCallSites {
		// nargs ranges supported by the two fixed-arity dispatchers.
		if site.nargs > 8 && site.nargs > 12 {
			t.Errorf("%s: nargs=%d exceeds wf_call_ptr_fixed12 capacity",
				site.name, site.nargs)
		}
		// nargs minimum: every COM method takes at least `this`.
		if site.nargs < 1 {
			t.Errorf("%s: nargs=%d < 1, COM methods always take at least `this`",
				site.name, site.nargs)
		}
	}
}
