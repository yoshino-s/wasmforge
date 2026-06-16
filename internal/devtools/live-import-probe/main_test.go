package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// fakeWasm builds a minimal WASM binary with one import section whose
// entries are the supplied (module, field) pairs. Each import is typed as
// a function with type-index 0 so the parser advances correctly.
func fakeWasm(imports [][2]string) []byte {
	var buf bytes.Buffer
	buf.WriteString("\x00asm")
	buf.Write([]byte{0x01, 0x00, 0x00, 0x00})

	var body bytes.Buffer
	body.Write(uvarint32(uint32(len(imports))))
	for _, im := range imports {
		body.Write(uvarint32(uint32(len(im[0]))))
		body.WriteString(im[0])
		body.Write(uvarint32(uint32(len(im[1]))))
		body.WriteString(im[1])
		body.WriteByte(0)
		body.Write(uvarint32(0))
	}
	buf.WriteByte(byte(importsKind))
	buf.Write(uvarint32(uint32(body.Len())))
	buf.Write(body.Bytes())
	return buf.Bytes()
}

func uvarint32(v uint32) []byte {
	var b [binary.MaxVarintLen32]byte
	n := binary.PutUvarint(b[:], uint64(v))
	return b[:n]
}

func TestReadImports_ClassifyEnvVsLocal(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "fake.wasm")
	wasm := fakeWasm([][2]string{
		{"env", "mod_invoke"},
		{"env", "rpc_enumeps"},
		{"wasi_snapshot_preview1", "fd_read"},
	})
	if err := os.WriteFile(tmp, wasm, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readImports(tmp)
	if err != nil {
		t.Fatalf("readImports: %v", err)
	}
	if got["mod_invoke"] != "env" {
		t.Errorf("mod_invoke: want env, got %q", got["mod_invoke"])
	}
	if got["rpc_enumeps"] != "env" {
		t.Errorf("rpc_enumeps: want env, got %q", got["rpc_enumeps"])
	}
	if got["fd_read"] != "wasi_snapshot_preview1" {
		t.Errorf("fd_read: want wasi_snapshot_preview1, got %q", got["fd_read"])
	}
	if _, ok := got["never_imported"]; ok {
		t.Errorf("never_imported should be absent")
	}
}
