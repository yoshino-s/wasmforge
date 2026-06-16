// Command live-import-probe reports whether named functions are still
// resolved through the WASI env module or have been statically linked
// into the WASM payload by the C# DllImport("*"...) pattern.
//
// Usage:
//
//	live-import-probe <Rubeus.wasm> <name1> [<name2> ...]
//
// Output format (one line per name):
//
//	<name>: env       — still imported from env (Go-side host)
//	<name>: local     — not in any import; resolved at C link time
//	<name>: other(<m>) — imported from a non-env module <m>
//
// The probe reads the raw .wasm produced by `dotnet publish -r wasi-wasm`
// directly, NOT the wrapped wasmforge PE (whose payload is XOR-encoded
// and distributed across debug sections).
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
)

const (
	wasmMagic   = "\x00asm"
	importsKind = 2
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: live-import-probe <wasm-path> <name1> [<name2> ...]")
		os.Exit(2)
	}
	wasmPath := os.Args[1]
	names := os.Args[2:]

	imports, err := readImports(wasmPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	for _, n := range names {
		mod, ok := imports[n]
		switch {
		case !ok:
			fmt.Printf("%s: local\n", n)
		case mod == "env":
			fmt.Printf("%s: env\n", n)
		default:
			fmt.Printf("%s: other(%s)\n", n, mod)
		}
	}
}

// readImports parses the WASM file at path and returns a map from
// imported function/global name to its module name.
func readImports(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading wasm: %w", err)
	}
	if len(data) < 8 || string(data[:4]) != wasmMagic {
		return nil, fmt.Errorf("%s: not a WASM file (magic mismatch)", path)
	}

	out := map[string]string{}
	pos := 8 // skip magic + version
	for pos < len(data) {
		sectID := data[pos]
		pos++
		sectLen, n, err := readVaruint32(data[pos:])
		if err != nil {
			return nil, fmt.Errorf("section length at %d: %w", pos, err)
		}
		pos += n
		sectEnd := pos + int(sectLen)
		if sectEnd > len(data) {
			return nil, fmt.Errorf("section %d overruns file (need %d, have %d)", sectID, sectEnd, len(data))
		}
		if sectID == importsKind {
			if err := parseImports(data[pos:sectEnd], out); err != nil {
				return nil, fmt.Errorf("parsing imports section: %w", err)
			}
		}
		pos = sectEnd
	}
	return out, nil
}

func parseImports(body []byte, out map[string]string) error {
	count, n, err := readVaruint32(body)
	if err != nil {
		return err
	}
	pos := n
	for i := uint32(0); i < count; i++ {
		modLen, n, err := readVaruint32(body[pos:])
		if err != nil {
			return fmt.Errorf("import[%d] mod len: %w", i, err)
		}
		pos += n
		if pos+int(modLen) > len(body) {
			return fmt.Errorf("import[%d] mod overruns", i)
		}
		mod := string(body[pos : pos+int(modLen)])
		pos += int(modLen)

		fldLen, n, err := readVaruint32(body[pos:])
		if err != nil {
			return fmt.Errorf("import[%d] fld len: %w", i, err)
		}
		pos += n
		if pos+int(fldLen) > len(body) {
			return fmt.Errorf("import[%d] fld overruns", i)
		}
		fld := string(body[pos : pos+int(fldLen)])
		pos += int(fldLen)

		out[fld] = mod

		if pos >= len(body) {
			return fmt.Errorf("import[%d] missing kind", i)
		}
		kind := body[pos]
		pos++
		switch kind {
		case 0: // function: u32 typeidx
			_, n, err := readVaruint32(body[pos:])
			if err != nil {
				return fmt.Errorf("import[%d] func typeidx: %w", i, err)
			}
			pos += n
		case 1: // table: reftype + limits
			if pos >= len(body) {
				return fmt.Errorf("import[%d] table truncated", i)
			}
			pos++
			n, err := skipLimits(body[pos:])
			if err != nil {
				return fmt.Errorf("import[%d] table limits: %w", i, err)
			}
			pos += n
		case 2: // memory: limits
			n, err := skipLimits(body[pos:])
			if err != nil {
				return fmt.Errorf("import[%d] memory limits: %w", i, err)
			}
			pos += n
		case 3: // global: valtype + mut
			if pos+2 > len(body) {
				return fmt.Errorf("import[%d] global truncated", i)
			}
			pos += 2
		default:
			return fmt.Errorf("import[%d] unknown kind %d", i, kind)
		}
	}
	return nil
}

func skipLimits(body []byte) (int, error) {
	if len(body) == 0 {
		return 0, errors.New("empty limits")
	}
	flag := body[0]
	pos := 1
	_, n, err := readVaruint32(body[pos:])
	if err != nil {
		return 0, err
	}
	pos += n
	if flag&1 != 0 {
		_, n, err := readVaruint32(body[pos:])
		if err != nil {
			return 0, err
		}
		pos += n
	}
	return pos, nil
}

// readVaruint32 reads an LEB128-encoded uint32 and returns (value, bytes-consumed).
func readVaruint32(buf []byte) (uint32, int, error) {
	var v uint64
	var shift uint
	for i, b := range buf {
		if i >= binary.MaxVarintLen32+1 {
			return 0, 0, errors.New("varuint32 too long")
		}
		v |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			if v > 0xffffffff {
				return 0, 0, errors.New("varuint32 overflow")
			}
			return uint32(v), i + 1, nil
		}
		shift += 7
	}
	return 0, 0, errors.New("varuint32 truncated")
}
