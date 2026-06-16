// Package darwin provides macOS framework access for Go programs compiled with wasmforge.
//
// This package uses go:wasmimport to call wasmforge host functions for macOS
// framework operations (dlopen/dlsym). Darwin APIs are automatically enabled
// when building with GOOS=darwin and are only available when running on a macOS host.
//
// On non-macOS hosts, Available() returns false and all API calls return ErrNotAvailable.
//
// Example usage:
//
//	if !darwin.Available() {
//	    log.Fatal("Darwin APIs not available")
//	}
//
//	fw, err := darwin.LoadFramework("Security")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	sym, err := fw.GetSymbol("SecItemCopyMatching")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	ret, err := sym.Call(arg1, arg2)
package darwin
