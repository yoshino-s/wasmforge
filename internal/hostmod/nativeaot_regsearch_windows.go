//go:build nativeaot && windows

// NativeAOT-specific host-side registry walker for SharpDPAPI's `search` verb.
//
// Mirrors the behaviour of SharpDPAPI.Commands.Search.FindRegistryBlobs:
// BFS over a registry hive starting at the supplied subpath (empty = hive
// root), scanning every value for the DPAPI provider GUID signature in
// REG_BINARY, REG_SZ/REG_EXPAND_SZ, or REG_MULTI_SZ form.
//
// Why this is host-side (Category C):
//
// The wasmforge bridge cannot afford O(N) wf_calls per visited registry
// key — a fresh RegOpenKeyExW + EnumValueW + EnumKeyW chain for each of
// ~500K HKLM keys exceeds the lab's 5-minute exec timeout. Doing the BFS
// here uses native Win32 handle propagation (parent → child via the
// already-open HKEY) at native speed, completing both hives in seconds.
// Same architectural choice as `wmi_query_r` and `xc_op`/`xi_op`.
//
// Wire format (output buffer):
//
//   Each record is a UTF-8 string, records separated by a single NUL byte.
//   The first record is the literal string "Root: <HIVE_PREFIX>\" to match
//   native's `Console.WriteLine("Root: " + root)` where root.Name returns
//   the hive prefix with trailing backslash. Subsequent records are full
//   match lines in the form `<HIVE_PREFIX>\\<subpath> ! <valueName>` —
//   note the DOUBLE backslash, mirroring native's RegistryKey.Name format
//   when the root was opened as Registry.X.OpenSubKey("\\"). When a value
//   has no name (the "default" value) the name is rendered as "Default".

package hostmod

import (
	"bytes"
	"context"
	"errors"
	"strings"

	"github.com/tetratelabs/wazero/api"
	"golang.org/x/sys/windows/registry"
)

// DPAPI provider GUID (df9d8cd0-1501-11d1-8c7a-00c04fc297eb) prefixed with
// the 4-byte version field. Matches SharpDPAPI's `dpapiBlobHeader`.
var dpapiBlobHeader = []byte{
	0x01, 0x00, 0x00, 0x00,
	0xD0, 0x8C, 0x9D, 0xDF, 0x01, 0x15, 0xD1, 0x11,
	0x8C, 0x7A, 0x00, 0xC0, 0x4F, 0xC2, 0x97, 0xEB,
}

// ASCII representations of the DPAPI provider GUID that show up inside
// otherwise-textual REG_BINARY values (typically SOAP envelopes or base64-
// stamped DeviceTicket blobs in HKU\…\IdentityCRL\…). Same byte sequences
// SharpDPAPI checks against; we only need them for REG_BINARY values
// since REG_SZ/MULTI_SZ paths use the regex match below.
var dpapiAsciiSigs = [][]byte{
	[]byte("AAAA0Iyd3wEV0RGMegDAT8KX6"),
	[]byte("AQAAANCMnd8BFdERjHoAwE/Cl+"),
	[]byte("EAAADQjJ3fARXREYx6AMBPwpfr"),
	[]byte("01000000D08C9DDF0115D1118C7A00C04FC297EB"),
}

// String alternation for REG_SZ / REG_EXPAND_SZ / REG_MULTI_SZ values.
// The header GUID itself is never in a text value, so the header bytes
// are omitted here.
var dpapiStringSigs = []string{
	"AAAA0Iyd3wEV0RGMegDAT8KX6",
	"AQAAANCMnd8BFdERjHoAwE/Cl+",
	"EAAADQjJ3fARXREYx6AMBPwpfr",
	"01000000D08C9DDF0115D1118C7A00C04FC297EB",
}

// nativeaotRegSearch BFS-walks the given hive and writes match lines to
// out_buf as null-separated UTF-8 records. Returns the number of bytes
// written, or 0 on hive open failure / buffer too small.
//
// Stack ABI (matches the registration in nativeaot.go):
//
//	stack[0] = hive (HKEY constant; 0x80000002 = HKLM, 0x80000003 = HKU)
//	stack[1] = out_buf_ptr
//	stack[2] = out_buf_cap
//	stack[0] (return) = bytes written
func nativeaotRegSearch(_ context.Context, mod api.Module, stack []uint64) {
	hive := uint32(stack[0])
	outPtr := uint32(stack[1])
	outCap := uint32(stack[2])

	prefix, root, ok := hivePrefixAndRoot(hive)
	if !ok {
		stack[0] = 0
		return
	}

	var buf bytes.Buffer
	// First record: "Root: <hive-prefix>\"
	buf.WriteString("Root: ")
	buf.WriteString(prefix)
	buf.WriteByte(0)

	walkHive(root, prefix, &buf)

	data := buf.Bytes()
	if uint32(len(data)) > outCap {
		// Buffer too small. Returning 0 forces the caller to either grow
		// the buffer and retry or report the gap. Truncating mid-record
		// would yield a corrupt last entry.
		stack[0] = 0
		return
	}
	if !mod.Memory().Write(outPtr, data) {
		stack[0] = 0
		return
	}
	stack[0] = uint64(len(data))
}

func hivePrefixAndRoot(hive uint32) (string, registry.Key, bool) {
	switch hive {
	case 0x80000002:
		return "HKEY_LOCAL_MACHINE\\", registry.LOCAL_MACHINE, true
	case 0x80000003:
		return "HKEY_USERS\\", registry.USERS, true
	case 0x80000001:
		return "HKEY_CURRENT_USER\\", registry.CURRENT_USER, true
	case 0x80000000:
		return "HKEY_CLASSES_ROOT\\", registry.CLASSES_ROOT, true
	case 0x80000005:
		return "HKEY_CURRENT_CONFIG\\", registry.CURRENT_CONFIG, true
	}
	return "", 0, false
}

// walkHive implements the BFS. Uses a parent-handle queue so each child
// open is RegOpenKeyEx(parent_handle, child_name, ...) at native speed —
// no full-path lookup per key. Closes every opened child handle to avoid
// leaking handles into the host process.
func walkHive(root registry.Key, prefix string, buf *bytes.Buffer) {
	type queued struct {
		key  registry.Key
		path string
		// owned reports whether `key` was opened by walkHive and must be
		// closed before the entry is dropped. The initial hive root is
		// a predefined HKEY and must NOT be closed.
		owned bool
	}
	queue := []queued{{key: root, path: "", owned: false}}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		fullName := prefix
		if cur.path != "" {
			fullName = prefix + "\\" + cur.path
		}

		// Enumerate values at this key. ReadValueNames(-1) is the full
		// list — the registry package handles internal buffer growth.
		names, err := cur.key.ReadValueNames(-1)
		if err == nil {
			for _, name := range names {
				if valueMatchesDpapi(cur.key, name) {
					out := name
					if out == "" {
						out = "Default"
					}
					buf.WriteString(fullName)
					buf.WriteString(" ! ")
					buf.WriteString(out)
					buf.WriteByte(0)
				}
			}
		}

		subkeys, err := cur.key.ReadSubKeyNames(-1)
		if err == nil {
			for _, sub := range subkeys {
				if sub == "" {
					continue
				}
				child, err := registry.OpenKey(cur.key, sub, registry.READ)
				if err != nil {
					continue
				}
				var childPath string
				if cur.path == "" {
					childPath = sub
				} else {
					childPath = cur.path + "\\" + sub
				}
				queue = append(queue, queued{key: child, path: childPath, owned: true})
			}
		}

		if cur.owned {
			_ = cur.key.Close()
		}
	}
}

// valueMatchesDpapi reads `name` from `key` and decides whether the value
// contains a DPAPI blob signature. Returns false for any error (deleted
// in flight, permission denied, OOM, etc.) — matches native's silent-skip
// semantics inside FindRegistryBlobs.
func valueMatchesDpapi(key registry.Key, name string) bool {
	// First attempt: read as binary. GetBinaryValue returns ErrUnexpectedType
	// with the actual value type in `valtype` when the value isn't REG_BINARY,
	// so we get the type for free even on the "wrong type" path.
	data, valtype, err := key.GetBinaryValue(name)
	if err == nil {
		return containsDpapiBytes(data)
	}
	if !errors.Is(err, registry.ErrUnexpectedType) {
		return false
	}
	switch valtype {
	case registry.SZ, registry.EXPAND_SZ:
		s, _, err := key.GetStringValue(name)
		if err != nil {
			return false
		}
		return containsDpapiString(s)
	case registry.MULTI_SZ:
		sa, _, err := key.GetStringsValue(name)
		if err != nil {
			return false
		}
		// SharpDPAPI joins with empty separator before regex match.
		return containsDpapiString(strings.Join(sa, ""))
	}
	return false
}

func containsDpapiBytes(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	if bytes.Contains(data, dpapiBlobHeader) {
		return true
	}
	for _, sig := range dpapiAsciiSigs {
		if bytes.Contains(data, sig) {
			return true
		}
	}
	return false
}

func containsDpapiString(s string) bool {
	if s == "" {
		return false
	}
	for _, sig := range dpapiStringSigs {
		if strings.Contains(s, sig) {
			return true
		}
	}
	return false
}
