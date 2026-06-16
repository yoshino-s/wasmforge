//go:build !windows

package hostmod

import "os"

// nonBlockingPipeRead on non-Windows platforms falls back to blocking read.
// The WASM deadlock issue only affects Windows (CLR stdout/stderr redirection).
func nonBlockingPipeRead(f *os.File, buf []byte) (int, uint32) {
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return 0, errnoFromError(err)
	}
	return n, errnoSuccess
}
