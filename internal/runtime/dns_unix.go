//go:build !windows

package runtime

// synthResolvConf creates a synthetic /etc/resolv.conf directory for the
// WASM guest. On Unix, /etc/resolv.conf already exists so this returns
// empty string (no synthetic needed).
func synthResolvConf() (tmpDir string, cleanup func()) {
	return "", nil
}
