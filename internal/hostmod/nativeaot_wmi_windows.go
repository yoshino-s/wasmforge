//go:build nativeaot && windows

package hostmod

import (
	"encoding/json"
	"fmt"
	"sync"
	"syscall"
	"unsafe"
)

// WMI COM GUIDs
var (
	clsidWbemLocator = syscall.GUID{0x4590f811, 0x1d3a, 0x11d0, [8]byte{0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24}}
	iidWbemLocator   = syscall.GUID{0xdc12a687, 0x737f, 0x11cf, [8]byte{0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24}}
)

var (
	oleaut32          = syscall.NewLazyDLL("oleaut32.dll")
	pSysAllocString   = oleaut32.NewProc("SysAllocString")
	pSysFreeString    = oleaut32.NewProc("SysFreeString")
	pVariantClear     = oleaut32.NewProc("VariantClear")
	ole32DLL          = syscall.NewLazyDLL("ole32.dll")
	pCoCreateInstance = ole32DLL.NewProc("CoCreateInstance")
	pCoInitializeEx   = ole32DLL.NewProc("CoInitializeEx")

	wmiInitOnce sync.Once
)

func bstr(s string) uintptr {
	u, _ := syscall.UTF16PtrFromString(s)
	r, _, _ := pSysAllocString.Call(uintptr(unsafe.Pointer(u)))
	return r
}

// variant is a simplified VARIANT struct (24 bytes on x64).
type variant struct {
	VT   uint16
	_    [6]byte // padding
	Val  int64
	_pad int64
}

const (
	vtEmpty   = 0
	vtNull    = 1
	vtI4      = 3
	vtBSTR    = 8
	vtBool    = 11
	vtUI4     = 19
	vtI8      = 20
	vtUI8     = 21
	clsctxAll = 0x17
)

// comCall calls a COM vtable method. obj is the COM interface pointer,
// idx is the vtable slot index, args are the method parameters.
func comCall(obj uintptr, idx int, args ...uintptr) (uintptr, error) {
	vtbl := *(*uintptr)(unsafe.Pointer(obj))
	method := *(*uintptr)(unsafe.Pointer(vtbl + uintptr(idx)*unsafe.Sizeof(uintptr(0))))

	allArgs := append([]uintptr{obj}, args...)
	var r1 uintptr
	var err error

	switch len(allArgs) {
	case 1:
		r1, _, err = syscall.SyscallN(method, allArgs[0])
	case 2:
		r1, _, err = syscall.SyscallN(method, allArgs[0], allArgs[1])
	case 3:
		r1, _, err = syscall.SyscallN(method, allArgs[0], allArgs[1], allArgs[2])
	case 4:
		r1, _, err = syscall.SyscallN(method, allArgs[0], allArgs[1], allArgs[2], allArgs[3])
	case 5:
		r1, _, err = syscall.SyscallN(method, allArgs[0], allArgs[1], allArgs[2], allArgs[3], allArgs[4])
	case 6:
		r1, _, err = syscall.SyscallN(method, allArgs[0], allArgs[1], allArgs[2], allArgs[3], allArgs[4], allArgs[5])
	case 7:
		r1, _, err = syscall.SyscallN(method, allArgs[0], allArgs[1], allArgs[2], allArgs[3], allArgs[4], allArgs[5], allArgs[6])
	case 8:
		r1, _, err = syscall.SyscallN(method, allArgs[0], allArgs[1], allArgs[2], allArgs[3], allArgs[4], allArgs[5], allArgs[6], allArgs[7])
	default:
		r1, _, err = syscall.SyscallN(method, allArgs...)
	}
	if r1 != 0 && r1 < 0x80000000 {
		return r1, nil // Success HRESULT
	}
	if r1 >= 0x80000000 {
		return r1, fmt.Errorf("COM HRESULT 0x%x", r1)
	}
	_ = err
	return r1, nil
}

// wmiQueryJSON executes a WQL query and returns results as JSON.
// Uses native COM: CoCreateInstance(WbemLocator) → ConnectServer → ExecQuery.
func wmiQueryJSON(namespace, query string) (string, error) {
	// Dispatch WMI COM work to the STA worker thread. WMI COM objects
	// require STA apartment threading; the COM worker already has CoInitializeEx(STA).
	return ComRunOnSTA(func() (string, error) {
		// CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_ALL, IID_IWbemLocator, &locator)
		// NOTE: No CoInitializeEx needed — the STA worker already initialized COM.
		var locator uintptr
		hr, _, _ := pCoCreateInstance.Call(
			uintptr(unsafe.Pointer(&clsidWbemLocator)),
			0,
			clsctxAll,
			uintptr(unsafe.Pointer(&iidWbemLocator)),
			uintptr(unsafe.Pointer(&locator)),
		)
		if hr != 0 || locator == 0 {
			return "", fmt.Errorf("CoCreateInstance(WbemLocator) failed: 0x%x", hr)
		}
		defer comCall(locator, 2) // Release

		// IWbemLocator::ConnectServer (vtable slot 3)
		bstrNS := bstr(namespace)
		defer pSysFreeString.Call(bstrNS)
		var services uintptr
		hr2, err := comCall(locator, 3,
			bstrNS,     // strNetworkResource
			0, 0,       // strUser, strPassword
			0,          // strLocale
			0,          // lSecurityFlags
			0,          // strAuthority
			0,          // pCtx
			uintptr(unsafe.Pointer(&services)),
		)
		if err != nil || hr2 >= 0x80000000 || services == 0 {
			return "", fmt.Errorf("ConnectServer failed: 0x%x %v", hr2, err)
		}
		defer comCall(services, 2) // Release

		// Set security levels on the WMI connection proxy.
		// Without this, WMI providers deny access to security-sensitive data.
		pSetProxy := ole32DLL.NewProc("CoSetProxyBlanket")
		const (
			rpcCAuthNDefault        = 0xFFFFFFFF // RPC_C_AUTHN_DEFAULT
			rpcCAuthZDefault        = 0xFFFFFFFF // RPC_C_AUTHZ_DEFAULT
			rpcCAuthnLevelCall      = 3          // RPC_C_AUTHN_LEVEL_CALL
			rpcCImpLevelImpersonate = 3          // RPC_C_IMP_LEVEL_IMPERSONATE
			eoNone                  = 0          // EOAC_NONE
		)
		pSetProxy.Call(
			services,
			rpcCAuthNDefault,
			rpcCAuthZDefault,
			0, // pServerPrincName
			rpcCAuthnLevelCall,
			rpcCImpLevelImpersonate,
			0, // pAuthInfo
			eoNone,
		)

		// IWbemServices::ExecQuery (vtable slot 20)
		bstrWQL := bstr("WQL")
		defer pSysFreeString.Call(bstrWQL)
		bstrQuery := bstr(query)
		defer pSysFreeString.Call(bstrQuery)

		const wbemFlagForwardOnly = 0x20
		const wbemFlagReturnImmediately = 0x10
		var enumerator uintptr
		hr2, err = comCall(services, 20,
			bstrWQL,
			bstrQuery,
			wbemFlagForwardOnly|wbemFlagReturnImmediately,
			0,
			uintptr(unsafe.Pointer(&enumerator)),
		)
		if err != nil || hr2 >= 0x80000000 || enumerator == 0 {
			return "", fmt.Errorf("ExecQuery failed: 0x%x %v", hr2, err)
		}
		defer comCall(enumerator, 2) // Release

		// Iterate results: IEnumWbemClassObject::Next
		var rows []map[string]interface{}
		for {
			var obj uintptr
			var returned uint32
			const wbemInfinite = 0xFFFFFFFF
			hr2, _ = comCall(enumerator, 4, // Next
				wbemInfinite,
				1,
				uintptr(unsafe.Pointer(&obj)),
				uintptr(unsafe.Pointer(&returned)),
			)
			if hr2 != 0 || returned == 0 || obj == 0 {
				break
			}

			// IWbemClassObject::GetNames (vtable slot 7) → get property names
			var namesArr uintptr // SAFEARRAY*
			hr2, _ = comCall(obj, 7,
				0, // qualifierName
				0, // flags
				0, // pQualifierVal
				uintptr(unsafe.Pointer(&namesArr)),
			)
			if hr2 != 0 || namesArr == 0 {
				comCall(obj, 2) // Release
				continue
			}

			row := make(map[string]interface{})
			// Parse SAFEARRAY of BSTRs
			names := parseSafeArrayBSTR(namesArr)
			for _, name := range names {
				if name == "" || name[0] == '_' {
					continue // Skip system properties
				}
				bstrName := bstr(name)
				var val variant
				hr3, _ := comCall(obj, 4, // Get
					bstrName,
					0,
					uintptr(unsafe.Pointer(&val)),
					0, 0,
				)
				pSysFreeString.Call(bstrName)
				if hr3 != 0 {
					continue
				}
				row[name] = variantToGo(&val)
				pVariantClear.Call(uintptr(unsafe.Pointer(&val)))
			}
			// SafeArrayDestroy
			pSafeArrayDestroy := oleaut32.NewProc("SafeArrayDestroy")
			pSafeArrayDestroy.Call(namesArr)

			if len(row) > 0 {
				rows = append(rows, row)
			}
			comCall(obj, 2) // Release
		}

		jsonBytes, err := json.Marshal(rows)
		if err != nil {
			return "", err
		}
		return string(jsonBytes), nil
	})
}

// parseSafeArrayBSTR extracts string values from a SAFEARRAY of BSTRs.
func parseSafeArrayBSTR(sa uintptr) []string {
	// SAFEARRAY layout: cDims(2), fFeatures(2), cbElements(4), cLocks(4), pvData(ptr), rgsabound[]{cElements(4), lLbound(4)}
	// On x64: pvData at offset 16, rgsabound at offset 24
	type safeArray struct {
		CDims      uint16
		FFeatures  uint16
		CbElements uint32
		CLocks     uint32
		PvData     uintptr
		CElements  uint32
		LLbound    int32
	}

	s := (*safeArray)(unsafe.Pointer(sa))
	if s.CDims == 0 || s.CElements == 0 || s.PvData == 0 {
		return nil
	}

	var names []string
	for i := uint32(0); i < s.CElements; i++ {
		bstrPtr := *(*uintptr)(unsafe.Pointer(s.PvData + uintptr(i)*unsafe.Sizeof(uintptr(0))))
		if bstrPtr != 0 {
			name := bstrToString(bstrPtr)
			names = append(names, name)
		}
	}
	return names
}

func bstrToString(b uintptr) string {
	if b == 0 {
		return ""
	}
	// BSTR has a 4-byte length prefix before the data
	length := *(*uint32)(unsafe.Pointer(b - 4))
	if length == 0 {
		return ""
	}
	chars := length / 2
	if chars > 4096 {
		chars = 4096
	}
	utf16 := unsafe.Slice((*uint16)(unsafe.Pointer(b)), chars)
	return syscall.UTF16ToString(utf16)
}

func variantToGo(v *variant) interface{} {
	// VT_ARRAY (0x2000) flag indicates a SAFEARRAY of the base type.
	// MSFT_NetFirewallRule.LocalPort is VT_ARRAY|VT_BSTR; common Win32
	// classes also use VT_ARRAY|VT_I4 etc.
	const vtArray = 0x2000
	if v.VT&vtArray != 0 {
		base := v.VT &^ vtArray
		sa := uintptr(v.Val)
		if sa == 0 {
			return nil
		}
		switch base {
		case vtBSTR:
			return parseSafeArrayBSTR(sa)
		default:
			// Other array element types not yet handled — return nil so
			// the C# side sees no value rather than a misleading int.
			return nil
		}
	}
	switch v.VT {
	case vtEmpty, vtNull:
		return nil
	case vtBSTR:
		return bstrToString(uintptr(v.Val))
	case vtI4:
		return int32(v.Val)
	case vtUI4:
		return uint32(v.Val)
	case vtI8:
		return v.Val
	case vtUI8:
		return uint64(v.Val)
	case vtBool:
		return v.Val != 0
	default:
		// For other types, try to represent as the raw int64 value
		if v.Val != 0 {
			return v.Val
		}
		return nil
	}
}


// wmiMethodJSON invokes a WMI method on a class (e.g., "Win32_Process.Create")
// and returns the output parameters as JSON. inputJSON is a flat object whose
// keys map to in-parameter names. Used for SharpWMI exec, registry method
// invocations, and other WMI ExecMethod call paths.
//
//	classPath    e.g., "Win32_Process" (just the class, not full object path)
//	methodName   e.g., "Create"
//	inputJSON    e.g., {"CommandLine":"cmd.exe /c whoami"} — values become VT_BSTR/VT_I4
//	             string values → VT_BSTR; numeric → VT_I4
func wmiMethodJSON(namespace, classPath, methodName, inputJSON string) (string, error) {
	return ComRunOnSTA(func() (string, error) {
		// Parse the input parameters JSON
		var inputs map[string]interface{}
		if inputJSON != "" {
			if err := json.Unmarshal([]byte(inputJSON), &inputs); err != nil {
				return "", fmt.Errorf("parsing inputJSON: %w", err)
			}
		}

		// CoCreateInstance(WbemLocator)
		var locator uintptr
		hr, _, _ := pCoCreateInstance.Call(
			uintptr(unsafe.Pointer(&clsidWbemLocator)),
			0,
			clsctxAll,
			uintptr(unsafe.Pointer(&iidWbemLocator)),
			uintptr(unsafe.Pointer(&locator)),
		)
		if hr != 0 || locator == 0 {
			return "", fmt.Errorf("CoCreateInstance(WbemLocator) failed: 0x%x", hr)
		}
		defer comCall(locator, 2)

		// ConnectServer
		bstrNS := bstr(namespace)
		defer pSysFreeString.Call(bstrNS)
		var services uintptr
		hr2, err := comCall(locator, 3,
			bstrNS, 0, 0, 0, 0, 0, 0,
			uintptr(unsafe.Pointer(&services)),
		)
		if err != nil || hr2 >= 0x80000000 || services == 0 {
			return "", fmt.Errorf("ConnectServer failed: 0x%x %v", hr2, err)
		}
		defer comCall(services, 2)

		// Set proxy blanket for impersonation
		pSetProxy := ole32DLL.NewProc("CoSetProxyBlanket")
		pSetProxy.Call(services, 0xFFFFFFFF, 0xFFFFFFFF, 0, 3, 3, 0, 0)

		// IWbemServices::GetObject (vtable slot 6) — fetch the class definition
		// so we can find its method and build an in-parameter instance.
		bstrClass := bstr(classPath)
		defer pSysFreeString.Call(bstrClass)
		var classObj uintptr
		hr2, err = comCall(services, 6,
			bstrClass,
			0,
			0,
			uintptr(unsafe.Pointer(&classObj)),
			0,
		)
		if err != nil || hr2 >= 0x80000000 || classObj == 0 {
			return "", fmt.Errorf("GetObject(%s) failed: 0x%x %v", classPath, hr2, err)
		}
		defer comCall(classObj, 2)

		// IWbemClassObject::GetMethod (vtable slot 19) — get the in/out signatures
		bstrMethod := bstr(methodName)
		defer pSysFreeString.Call(bstrMethod)
		var inSig, outSig uintptr
		hr2, err = comCall(classObj, 19,
			bstrMethod,
			0,
			uintptr(unsafe.Pointer(&inSig)),
			uintptr(unsafe.Pointer(&outSig)),
		)
		if err != nil || hr2 >= 0x80000000 {
			return "", fmt.Errorf("GetMethod(%s) failed: 0x%x %v", methodName, hr2, err)
		}
		if inSig != 0 {
			defer comCall(inSig, 2)
		}
		if outSig != 0 {
			defer comCall(outSig, 2)
		}

		// SpawnInstance on the in-signature to build the IWbemClassObject* we pass.
		// IWbemClassObject::SpawnInstance is vtable slot 15.
		var inParams uintptr
		if inSig != 0 && len(inputs) > 0 {
			hr2, _ = comCall(inSig, 15, 0, uintptr(unsafe.Pointer(&inParams)))
			if hr2 < 0x80000000 && inParams != 0 {
				defer comCall(inParams, 2)
				// Set properties via IWbemClassObject::Put (vtable slot 5)
				for name, val := range inputs {
					var v variant
					switch tv := val.(type) {
					case string:
						v.VT = 8 // VT_BSTR
						v.Val = int64(bstr(tv))
						defer pSysFreeString.Call(uintptr(v.Val))
					case float64:
						v.VT = 3 // VT_I4
						v.Val = int64(int32(tv))
					case bool:
						v.VT = 11 // VT_BOOL
						if tv {
							v.Val = int64(int16(-1))
						}
					default:
						continue
					}
					bstrName := bstr(name)
					comCall(inParams, 5, bstrName, 0, uintptr(unsafe.Pointer(&v)), 0)
					pSysFreeString.Call(bstrName)
				}
			}
		}

		// IWbemServices::ExecMethod (vtable slot 24)
		// HRESULT ExecMethod(BSTR strObjectPath, BSTR strMethodName, long lFlags,
		//                    IWbemContext* pCtx, IWbemClassObject* pInParams,
		//                    IWbemClassObject** ppOutParams, IWbemCallResult** ppCallResult)
		var outParams uintptr
		hr2, err = comCall(services, 24,
			bstrClass,
			bstrMethod,
			0,
			0,
			inParams,
			uintptr(unsafe.Pointer(&outParams)),
			0,
		)
		if err != nil || hr2 >= 0x80000000 {
			return "", fmt.Errorf("ExecMethod(%s.%s) failed: 0x%x %v", classPath, methodName, hr2, err)
		}
		if outParams == 0 {
			// Method returned but produced no out-params; just return empty.
			return "{}", nil
		}
		defer comCall(outParams, 2)

		// Enumerate output property names and values, same as wmiQueryJSON.
		var namesArr uintptr
		hr2, _ = comCall(outParams, 7, 0, 0, 0, uintptr(unsafe.Pointer(&namesArr)))
		if hr2 != 0 || namesArr == 0 {
			return "{}", nil
		}
		row := make(map[string]interface{})
		names := parseSafeArrayBSTR(namesArr)
		for _, name := range names {
			if name == "" || name[0] == '_' {
				continue
			}
			bstrName := bstr(name)
			var val variant
			hr3, _ := comCall(outParams, 4, bstrName, 0, uintptr(unsafe.Pointer(&val)), 0, 0)
			pSysFreeString.Call(bstrName)
			if hr3 != 0 {
				continue
			}
			row[name] = variantToGo(&val)
			pVariantClear.Call(uintptr(unsafe.Pointer(&val)))
		}
		pSafeArrayDestroy := oleaut32.NewProc("SafeArrayDestroy")
		pSafeArrayDestroy.Call(namesArr)

		jsonBytes, err := json.Marshal(row)
		if err != nil {
			return "", err
		}
		return string(jsonBytes), nil
	})
}
