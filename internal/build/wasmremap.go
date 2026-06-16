package build

import (
	"fmt"
	"strings"
)

// immFormat describes the immediate operand format after an opcode byte.
type immFormat int

const (
	immNone         immFormat = iota // no operands (i32.add, drop, nop, ...)
	immBlock                        // s33 block type (block, loop, if)
	immLEB                          // 1 unsigned LEB128 (local.get, br, call, ...)
	immLEB2                         // 2 unsigned LEB128s (load/store: align + offset)
	immI32                          // signed LEB128 s32 (i32.const)
	immI64                          // signed LEB128 s64 (i64.const)
	immF32                          // 4 fixed bytes (f32.const)
	immF64                          // 8 fixed bytes (f64.const)
	immBrTable                      // LEB128 count + count+1 LEB128 labels
	immCallIndirect                 // 2 LEB128s (typeidx + tableidx)
	immMemory                       // 1 byte (memory.size/grow reserved byte)
	immPrefix                       // multi-byte: prefix remapped, LEB128 sub-opcode, sub-immediates
	immTypedSelect                  // LEB128 count + count value-type bytes
	immRefNull                      // 1 byte (reftype)
)

// wasmCodeSectionID is the standard WASM code section ID (0x0A).
const wasmCodeSectionID = 10

// opcodeFormats maps each standard WASM opcode byte to its immediate format.
// Unrecognized bytes default to immNone (zero value).
var opcodeFormats [256]immFormat

func init() {
	// Block instructions.
	opcodeFormats[0x02] = immBlock // block
	opcodeFormats[0x03] = immBlock // loop
	opcodeFormats[0x04] = immBlock // if

	// Branch.
	opcodeFormats[0x0C] = immLEB     // br
	opcodeFormats[0x0D] = immLEB     // br_if
	opcodeFormats[0x0E] = immBrTable // br_table

	// Call.
	opcodeFormats[0x10] = immLEB          // call
	opcodeFormats[0x11] = immCallIndirect // call_indirect

	// Typed select.
	opcodeFormats[0x1C] = immTypedSelect

	// Variable instructions.
	opcodeFormats[0x20] = immLEB // local.get
	opcodeFormats[0x21] = immLEB // local.set
	opcodeFormats[0x22] = immLEB // local.tee
	opcodeFormats[0x23] = immLEB // global.get
	opcodeFormats[0x24] = immLEB // global.set

	// Table instructions.
	opcodeFormats[0x25] = immLEB // table.get
	opcodeFormats[0x26] = immLEB // table.set

	// Memory load/store (all take align + offset as 2 LEB128s).
	for op := byte(0x28); op <= 0x3E; op++ {
		opcodeFormats[op] = immLEB2
	}

	// Memory size/grow (1 reserved byte).
	opcodeFormats[0x3F] = immMemory // memory.size
	opcodeFormats[0x40] = immMemory // memory.grow

	// Constants.
	opcodeFormats[0x41] = immI32 // i32.const
	opcodeFormats[0x42] = immI64 // i64.const
	opcodeFormats[0x43] = immF32 // f32.const
	opcodeFormats[0x44] = immF64 // f64.const

	// 0x45-0xC4: numeric/comparison/conversion/sign-extension → immNone (default).

	// Reference types.
	opcodeFormats[0xD0] = immRefNull // ref.null (1 byte reftype)
	// 0xD1 ref.is_null: immNone (default).
	opcodeFormats[0xD2] = immLEB // ref.func (funcidx)

	// Multi-byte prefixes.
	opcodeFormats[0xFC] = immPrefix // misc
	opcodeFormats[0xFD] = immPrefix // vector
	opcodeFormats[0xFE] = immPrefix // atomic
}

// remapWASM transforms a standard WASM binary by applying per-build
// opcode permutation, section ID mapping, custom magic bytes, and
// export name rewriting in the import section.
//
// Four transformation levels:
//   - Level 1 — Header: replace magic bytes
//   - Level 2 — Sections: remap section IDs
//   - Level 3 — Import section: rewrite "env" field names via exportNames
//   - Level 4 — Code section function bodies: remap opcode bytes,
//     preserve all immediate operands unchanged
//
// exportNames maps old anonymized names to new per-build random names.
// Pass nil or an empty map to skip import section rewriting.
func remapWASM(data []byte, perm [256]byte, sectionMap [13]byte, magic [4]byte, exportNames map[string]string, wasiNames ...map[string]string) ([]byte, error) {
	var wasiNameMap map[string]string
	if len(wasiNames) > 0 {
		wasiNameMap = wasiNames[0]
	}
	if len(data) < 8 {
		return nil, fmt.Errorf("WASM binary too short: %d bytes", len(data))
	}

	out := make([]byte, 0, len(data))
	pos := 0

	// Level 1 — Header: replace magic, pass through version.
	out = append(out, magic[:]...)
	pos = 4
	out = append(out, data[4:8]...) // version bytes unchanged
	pos = 8

	// Level 2 — Sections.
	for pos < len(data) {
		// Read section ID (1 byte).
		sectionID := data[pos]
		pos++

		if int(sectionID) >= len(sectionMap) {
			return nil, fmt.Errorf("invalid section ID %d at offset %d", sectionID, pos-1)
		}
		out = append(out, sectionMap[sectionID])

		// Read section size (LEB128) — pass through unchanged.
		sectionSize, n, err := readLEB128u(data, pos)
		if err != nil {
			return nil, fmt.Errorf("reading section size at %d: %w", pos, err)
		}
		out = append(out, data[pos:pos+n]...)
		pos += n

		sectionEnd := pos + int(sectionSize)
		if sectionEnd > len(data) {
			return nil, fmt.Errorf("section %d size %d extends past end at offset %d", sectionID, sectionSize, pos)
		}

		switch sectionID {
		case 2: // Import section: rewrite "env" + "wasi_snapshot_preview1" field names.
			if len(exportNames) > 0 || len(wasiNameMap) > 0 {
				remapped, err := remapImportSection(data[pos:sectionEnd], exportNames, wasiNameMap)
				if err != nil {
					return nil, fmt.Errorf("remapping import section: %w", err)
				}
				// The import section may grow/shrink. Rewrite the section size.
				// Replace the already-emitted size LEB128 with the new size.
				// The size LEB128 was appended at len(out)-n to len(out).
				// We need to rewrite the last n bytes of out with the new size.
				newSize := uint64(len(remapped))
				newSizeLEB := encodeLEB128u(newSize)
				// Remove the old size bytes and append new size + new payload.
				out = out[:len(out)-n]
				out = append(out, newSizeLEB...)
				out = append(out, remapped...)
			} else {
				out = append(out, data[pos:sectionEnd]...)
			}

		case wasmCodeSectionID:
			// Level 4 — Code section: remap function body opcodes.
			remapped, err := remapCodeSection(data[pos:sectionEnd], perm)
			if err != nil {
				return nil, fmt.Errorf("remapping code section: %w", err)
			}
			out = append(out, remapped...)

		case 6: // Global section: remap constant expression opcodes.
			remapped, err := remapGlobalSection(data[pos:sectionEnd], perm)
			if err != nil {
				return nil, fmt.Errorf("remapping global section: %w", err)
			}
			out = append(out, remapped...)

		case 9: // Element section: remap constant expression opcodes.
			remapped, err := remapElementSection(data[pos:sectionEnd], perm)
			if err != nil {
				return nil, fmt.Errorf("remapping element section: %w", err)
			}
			out = append(out, remapped...)

		case 11: // Data section: remap constant expression opcodes.
			remapped, err := remapDataSection(data[pos:sectionEnd], perm)
			if err != nil {
				return nil, fmt.Errorf("remapping data section: %w", err)
			}
			out = append(out, remapped...)

		default:
			// Other sections: copy payload verbatim.
			out = append(out, data[pos:sectionEnd]...)
		}
		pos = sectionEnd
	}

	return out, nil
}

// remapCodeSection processes the code section payload, remapping opcodes
// in each function body while preserving immediate operands unchanged.
func remapCodeSection(data []byte, perm [256]byte) ([]byte, error) {
	out := make([]byte, 0, len(data))
	pos := 0

	// Read number of functions.
	numFuncs, n, err := readLEB128u(data, pos)
	if err != nil {
		return nil, fmt.Errorf("reading function count: %w", err)
	}
	out = append(out, data[pos:pos+n]...)
	pos += n

	for i := 0; i < int(numFuncs); i++ {
		// Read body size — pass through.
		bodySize, n, err := readLEB128u(data, pos)
		if err != nil {
			return nil, fmt.Errorf("func %d: reading body size: %w", i, err)
		}
		out = append(out, data[pos:pos+n]...)
		pos += n

		bodyStart := pos
		bodyEnd := pos + int(bodySize)
		if bodyEnd > len(data) {
			return nil, fmt.Errorf("func %d: body extends past section end", i)
		}

		// Read local declarations — pass through verbatim.
		localCount, n, err := readLEB128u(data, pos)
		if err != nil {
			return nil, fmt.Errorf("func %d: reading local count: %w", i, err)
		}
		out = append(out, data[pos:pos+n]...)
		pos += n

		for j := 0; j < int(localCount); j++ {
			// count (LEB128)
			_, n, err := readLEB128u(data, pos)
			if err != nil {
				return nil, fmt.Errorf("func %d: local decl %d: %w", i, j, err)
			}
			out = append(out, data[pos:pos+n]...)
			pos += n
			// type (1 byte)
			if pos >= len(data) {
				return nil, fmt.Errorf("func %d: local decl %d: type byte truncated", i, j)
			}
			out = append(out, data[pos])
			pos++
		}

		// Walk instruction stream — remap opcodes, pass through immediates.
		for pos < bodyEnd {
			opcode := data[pos]
			pos++

			// Remap the opcode byte.
			out = append(out, perm[opcode])

			// Copy immediates based on the opcode's format.
			switch opcodeFormats[opcode] {
			case immNone:
				// No operands.

			case immBlock:
				// s33 block type (signed LEB128).
				n, err := skipSignedLEB128(data, pos, 5)
				if err != nil {
					return nil, fmt.Errorf("func %d: block type at %d: %w", i, pos, err)
				}
				out = append(out, data[pos:pos+n]...)
				pos += n

			case immLEB:
				_, n, err := readLEB128u(data, pos)
				if err != nil {
					return nil, fmt.Errorf("func %d: LEB at %d: %w", i, pos, err)
				}
				out = append(out, data[pos:pos+n]...)
				pos += n

			case immLEB2:
				for k := 0; k < 2; k++ {
					_, n, err := readLEB128u(data, pos)
					if err != nil {
						return nil, fmt.Errorf("func %d: LEB2[%d] at %d: %w", i, k, pos, err)
					}
					out = append(out, data[pos:pos+n]...)
					pos += n
				}

			case immI32:
				n, err := skipSignedLEB128(data, pos, 5)
				if err != nil {
					return nil, fmt.Errorf("func %d: i32.const at %d: %w", i, pos, err)
				}
				out = append(out, data[pos:pos+n]...)
				pos += n

			case immI64:
				n, err := skipSignedLEB128(data, pos, 10)
				if err != nil {
					return nil, fmt.Errorf("func %d: i64.const at %d: %w", i, pos, err)
				}
				out = append(out, data[pos:pos+n]...)
				pos += n

			case immF32:
				if pos+4 > len(data) {
					return nil, fmt.Errorf("func %d: f32.const at %d: truncated", i, pos)
				}
				out = append(out, data[pos:pos+4]...)
				pos += 4

			case immF64:
				if pos+8 > len(data) {
					return nil, fmt.Errorf("func %d: f64.const at %d: truncated", i, pos)
				}
				out = append(out, data[pos:pos+8]...)
				pos += 8

			case immBrTable:
				// LEB128 count, then count+1 LEB128 labels.
				count, n, err := readLEB128u(data, pos)
				if err != nil {
					return nil, fmt.Errorf("func %d: br_table count at %d: %w", i, pos, err)
				}
				out = append(out, data[pos:pos+n]...)
				pos += n
				for k := 0; k <= int(count); k++ {
					_, n, err := readLEB128u(data, pos)
					if err != nil {
						return nil, fmt.Errorf("func %d: br_table label %d at %d: %w", i, k, pos, err)
					}
					out = append(out, data[pos:pos+n]...)
					pos += n
				}

			case immCallIndirect:
				for k := 0; k < 2; k++ {
					_, n, err := readLEB128u(data, pos)
					if err != nil {
						return nil, fmt.Errorf("func %d: call_indirect[%d] at %d: %w", i, k, pos, err)
					}
					out = append(out, data[pos:pos+n]...)
					pos += n
				}

			case immMemory:
				// 1 reserved byte.
				if pos >= len(data) {
					return nil, fmt.Errorf("func %d: memory op at %d: truncated", i, pos)
				}
				out = append(out, data[pos])
				pos++

			case immRefNull:
				// 1 byte reftype.
				if pos >= len(data) {
					return nil, fmt.Errorf("func %d: ref.null at %d: truncated", i, pos)
				}
				out = append(out, data[pos])
				pos++

			case immTypedSelect:
				// LEB128 count + count value-type bytes.
				count, n, err := readLEB128u(data, pos)
				if err != nil {
					return nil, fmt.Errorf("func %d: typed select at %d: %w", i, pos, err)
				}
				out = append(out, data[pos:pos+n]...)
				pos += n
				end := pos + int(count)
				if end > len(data) {
					return nil, fmt.Errorf("func %d: typed select types at %d: truncated", i, pos)
				}
				out = append(out, data[pos:end]...)
				pos = end

			case immPrefix:
				// Read sub-opcode as LEB128 (NOT remapped — it's an index).
				subOp, n, err := readLEB128u(data, pos)
				if err != nil {
					return nil, fmt.Errorf("func %d: prefix sub-opcode at %d: %w", i, pos, err)
				}
				out = append(out, data[pos:pos+n]...)
				pos += n

				// Skip sub-immediates.
				skip, err := skipPrefixImmediate(opcode, uint32(subOp), data, pos)
				if err != nil {
					return nil, fmt.Errorf("func %d: prefix 0x%02X sub %d at %d: %w", i, opcode, subOp, pos, err)
				}
				if skip > 0 {
					out = append(out, data[pos:pos+skip]...)
					pos += skip
				}
			}
		}

		// Verify exact body consumption.
		if pos != bodyEnd {
			return nil, fmt.Errorf("func %d: consumed %d bytes, expected %d", i, pos-bodyStart, bodySize)
		}
	}

	return out, nil
}

// ──────────────────────────────────────────────────────────────────────
// Constant expression remapping (global, element, data sections)
// ──────────────────────────────────────────────────────────────────────

// remapConstExpr remaps the opcode and end bytes of a single constant
// expression starting at data[0], preserving all immediate operands.
// Returns (remapped bytes, bytes consumed, error).
func remapConstExpr(data []byte, perm [256]byte) ([]byte, int, error) {
	if len(data) < 2 {
		return nil, 0, fmt.Errorf("const expr too short")
	}

	opcode := data[0]
	pos := 1

	// Skip immediate based on the ORIGINAL opcode value.
	switch opcode {
	case 0x41: // i32.const — signed LEB128 (up to 5 bytes)
		n, err := skipSignedLEB128(data, pos, 5)
		if err != nil {
			return nil, 0, err
		}
		pos += n
	case 0x42: // i64.const — signed LEB128 (up to 10 bytes)
		n, err := skipSignedLEB128(data, pos, 10)
		if err != nil {
			return nil, 0, err
		}
		pos += n
	case 0x43: // f32.const — 4 fixed bytes
		if pos+4 > len(data) {
			return nil, 0, fmt.Errorf("f32.const truncated")
		}
		pos += 4
	case 0x44: // f64.const — 8 fixed bytes
		if pos+8 > len(data) {
			return nil, 0, fmt.Errorf("f64.const truncated")
		}
		pos += 8
	case 0x23: // global.get — unsigned LEB128
		_, n, err := readLEB128u(data, pos)
		if err != nil {
			return nil, 0, err
		}
		pos += n
	case 0xD0: // ref.null — 1 byte reftype
		if pos >= len(data) {
			return nil, 0, fmt.Errorf("ref.null truncated")
		}
		pos++
	case 0xD2: // ref.func — unsigned LEB128 funcidx
		_, n, err := readLEB128u(data, pos)
		if err != nil {
			return nil, 0, err
		}
		pos += n
	case 0xFD: // vec prefix — LEB128 sub-opcode + 16 bytes for v128.const
		_, n, err := readLEB128u(data, pos)
		if err != nil {
			return nil, 0, err
		}
		pos += n
		if pos+16 > len(data) {
			return nil, 0, fmt.Errorf("v128.const truncated")
		}
		pos += 16
	default:
		return nil, 0, fmt.Errorf("unknown const expr opcode 0x%02X", opcode)
	}

	if pos >= len(data) || data[pos] != 0x0B {
		return nil, 0, fmt.Errorf("const expr not terminated with end (0x0B) at offset %d", pos)
	}

	// Build output: remapped opcode + unchanged immediates + remapped end.
	out := make([]byte, 0, pos+1)
	out = append(out, perm[opcode])
	out = append(out, data[1:pos]...)
	out = append(out, perm[0x0B])

	return out, pos + 1, nil
}

// remapGlobalSection remaps constant expressions in global initializers.
// Format: num_globals, then for each: value_type(1) + mutability(1) + init_expr.
func remapGlobalSection(data []byte, perm [256]byte) ([]byte, error) {
	out := make([]byte, 0, len(data))
	pos := 0

	numGlobals, n, err := readLEB128u(data, pos)
	if err != nil {
		return nil, fmt.Errorf("reading global count: %w", err)
	}
	out = append(out, data[pos:pos+n]...)
	pos += n

	for i := 0; i < int(numGlobals); i++ {
		// Global type: value_type (1 byte) + mutability (1 byte).
		if pos+2 > len(data) {
			return nil, fmt.Errorf("global %d: type truncated", i)
		}
		out = append(out, data[pos:pos+2]...)
		pos += 2

		// Init expression.
		remapped, consumed, err := remapConstExpr(data[pos:], perm)
		if err != nil {
			return nil, fmt.Errorf("global %d init expr: %w", i, err)
		}
		out = append(out, remapped...)
		pos += consumed
	}

	return out, nil
}

// remapDataSection remaps constant expressions in data segment offsets.
// Format: num_data, then for each: flags + optional offset expr + data bytes.
func remapDataSection(data []byte, perm [256]byte) ([]byte, error) {
	out := make([]byte, 0, len(data))
	pos := 0

	numData, n, err := readLEB128u(data, pos)
	if err != nil {
		return nil, fmt.Errorf("reading data count: %w", err)
	}
	out = append(out, data[pos:pos+n]...)
	pos += n

	for i := 0; i < int(numData); i++ {
		flags, n, err := readLEB128u(data, pos)
		if err != nil {
			return nil, fmt.Errorf("data %d: reading flags: %w", i, err)
		}
		out = append(out, data[pos:pos+n]...)
		pos += n

		switch flags {
		case 0: // active, memory 0: offset expr + data
			remapped, consumed, err := remapConstExpr(data[pos:], perm)
			if err != nil {
				return nil, fmt.Errorf("data %d offset expr: %w", i, err)
			}
			out = append(out, remapped...)
			pos += consumed

		case 1: // passive: just data (no offset expr)
			// fall through to data copy below

		case 2: // active, explicit memory: memidx + offset expr + data
			_, n, err := readLEB128u(data, pos) // memidx
			if err != nil {
				return nil, fmt.Errorf("data %d memidx: %w", i, err)
			}
			out = append(out, data[pos:pos+n]...)
			pos += n

			remapped, consumed, err := remapConstExpr(data[pos:], perm)
			if err != nil {
				return nil, fmt.Errorf("data %d offset expr: %w", i, err)
			}
			out = append(out, remapped...)
			pos += consumed

		default:
			return nil, fmt.Errorf("data %d: unknown flags %d", i, flags)
		}

		// Data payload: LEB128 length + bytes.
		dataLen, n, err := readLEB128u(data, pos)
		if err != nil {
			return nil, fmt.Errorf("data %d: reading data length: %w", i, err)
		}
		out = append(out, data[pos:pos+n]...)
		pos += n
		end := pos + int(dataLen)
		if end > len(data) {
			return nil, fmt.Errorf("data %d: data extends past section end", i)
		}
		out = append(out, data[pos:end]...)
		pos = end
	}

	return out, nil
}

// remapElementSection remaps constant expressions in element segments.
// The element section has a complex flag-based format (8 variants).
func remapElementSection(data []byte, perm [256]byte) ([]byte, error) {
	out := make([]byte, 0, len(data))
	pos := 0

	numElems, n, err := readLEB128u(data, pos)
	if err != nil {
		return nil, fmt.Errorf("reading element count: %w", err)
	}
	out = append(out, data[pos:pos+n]...)
	pos += n

	for i := 0; i < int(numElems); i++ {
		flags, n, err := readLEB128u(data, pos)
		if err != nil {
			return nil, fmt.Errorf("elem %d: reading flags: %w", i, err)
		}
		out = append(out, data[pos:pos+n]...)
		pos += n

		hasTable := flags&0x02 != 0     // bit 1: explicit table index
		isPassive := flags&0x01 != 0     // bit 0: passive/declarative (no offset)
		usesExprs := flags&0x04 != 0     // bit 2: init expressions (not funcidx vec)

		// Table index (if bit 1 set and not passive).
		if hasTable && !isPassive {
			_, n, err := readLEB128u(data, pos)
			if err != nil {
				return nil, fmt.Errorf("elem %d tableidx: %w", i, err)
			}
			out = append(out, data[pos:pos+n]...)
			pos += n
		}

		// Offset expression (if active: bit 0 clear, or flags == 0/2/4/6).
		if !isPassive {
			remapped, consumed, err := remapConstExpr(data[pos:], perm)
			if err != nil {
				return nil, fmt.Errorf("elem %d offset expr: %w", i, err)
			}
			out = append(out, remapped...)
			pos += consumed
		}

		// Element kind or reftype (for flags 1-3 and 5-7).
		if flags != 0 && flags != 4 {
			if pos >= len(data) {
				return nil, fmt.Errorf("elem %d: elemkind/reftype truncated", i)
			}
			out = append(out, data[pos])
			pos++
		}

		// Vector of items.
		vecLen, n, err := readLEB128u(data, pos)
		if err != nil {
			return nil, fmt.Errorf("elem %d: reading vec length: %w", i, err)
		}
		out = append(out, data[pos:pos+n]...)
		pos += n

		if usesExprs {
			// Vector of const expressions (flags 4-7).
			for j := 0; j < int(vecLen); j++ {
				remapped, consumed, err := remapConstExpr(data[pos:], perm)
				if err != nil {
					return nil, fmt.Errorf("elem %d init expr %d: %w", i, j, err)
				}
				out = append(out, remapped...)
				pos += consumed
			}
		} else {
			// Vector of funcidx (LEB128, not opcodes).
			for j := 0; j < int(vecLen); j++ {
				_, n, err := readLEB128u(data, pos)
				if err != nil {
					return nil, fmt.Errorf("elem %d funcidx %d: %w", i, j, err)
				}
				out = append(out, data[pos:pos+n]...)
				pos += n
			}
		}
	}

	return out, nil
}

// skipPrefixImmediate returns the number of bytes to skip for the
// immediate operands of a prefixed instruction.
func skipPrefixImmediate(prefix byte, subOp uint32, data []byte, pos int) (int, error) {
	switch prefix {
	case 0xFC: // misc prefix
		return skipMiscImmediate(subOp, data, pos)
	case 0xFD:
		// Go's WASM backend does not emit SIMD instructions.
		return 0, fmt.Errorf("unsupported vector sub-opcode %d", subOp)
	case 0xFE:
		// Go's WASM backend does not emit atomic instructions.
		return 0, fmt.Errorf("unsupported atomic sub-opcode %d", subOp)
	default:
		return 0, fmt.Errorf("unknown prefix 0x%02X", prefix)
	}
}

// skipMiscImmediate handles 0xFC prefix sub-opcode immediates.
func skipMiscImmediate(subOp uint32, data []byte, pos int) (int, error) {
	switch {
	case subOp <= 7:
		// Non-trapping float-to-int conversions: no immediates.
		return 0, nil

	case subOp == 8: // memory.init: dataidx (LEB) + memidx (LEB)
		return skipNLEB128(data, pos, 2)

	case subOp == 9: // data.drop: dataidx (LEB)
		_, n, err := readLEB128u(data, pos)
		return n, err

	case subOp == 10: // memory.copy: src memidx + dst memidx (2 bytes)
		if pos+2 > len(data) {
			return 0, fmt.Errorf("memory.copy truncated at %d", pos)
		}
		return 2, nil

	case subOp == 11: // memory.fill: memidx (1 byte)
		if pos+1 > len(data) {
			return 0, fmt.Errorf("memory.fill truncated at %d", pos)
		}
		return 1, nil

	case subOp == 12: // table.init: elemidx (LEB) + tableidx (LEB)
		return skipNLEB128(data, pos, 2)

	case subOp == 13: // elem.drop: elemidx (LEB)
		_, n, err := readLEB128u(data, pos)
		return n, err

	case subOp == 14: // table.copy: tableidx (LEB) + tableidx (LEB)
		return skipNLEB128(data, pos, 2)

	case subOp >= 15 && subOp <= 17: // table.grow/size/fill: tableidx (LEB)
		_, n, err := readLEB128u(data, pos)
		return n, err

	default:
		return 0, fmt.Errorf("unknown misc sub-opcode %d", subOp)
	}
}

// ──────────────────────────────────────────────────────────────────────
// LEB128 helpers
// ──────────────────────────────────────────────────────────────────────

// readLEB128u reads an unsigned LEB128 value. Returns (value, bytesRead, error).
func readLEB128u(data []byte, pos int) (uint64, int, error) {
	var result uint64
	var shift uint
	for i := 0; ; i++ {
		if pos+i >= len(data) {
			return 0, 0, fmt.Errorf("LEB128 extends past end at offset %d", pos)
		}
		b := data[pos+i]
		result |= uint64(b&0x7F) << shift
		shift += 7
		if b&0x80 == 0 {
			return result, i + 1, nil
		}
		if shift >= 64 {
			return 0, 0, fmt.Errorf("LEB128 overflow at offset %d", pos)
		}
	}
}

// skipSignedLEB128 skips a signed LEB128 of up to maxBytes bytes.
func skipSignedLEB128(data []byte, pos int, maxBytes int) (int, error) {
	for i := 0; i < maxBytes; i++ {
		if pos+i >= len(data) {
			return 0, fmt.Errorf("signed LEB128 extends past end at offset %d", pos)
		}
		if data[pos+i]&0x80 == 0 {
			return i + 1, nil
		}
	}
	return 0, fmt.Errorf("signed LEB128 too long at offset %d", pos)
}

// skipNLEB128 reads and skips n consecutive unsigned LEB128 values,
// returning the total bytes consumed.
func skipNLEB128(data []byte, pos int, count int) (int, error) {
	total := 0
	for i := 0; i < count; i++ {
		_, n, err := readLEB128u(data, pos+total)
		if err != nil {
			return 0, err
		}
		total += n
	}
	return total, nil
}

// encodeLEB128u encodes a uint64 as an unsigned LEB128 byte sequence.
func encodeLEB128u(v uint64) []byte {
	var out []byte
	for {
		b := byte(v & 0x7F)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		out = append(out, b)
		if v == 0 {
			break
		}
	}
	return out
}

// ──────────────────────────────────────────────────────────────────────
// Import section rewriting — per-build export name randomization
// ──────────────────────────────────────────────────────────────────────

// remapImportSection rewrites the WASM import section payload, replacing
// field names for imports from the "env" module using exportNames.
// The module name "env" is NOT changed — only the function field names.
//
// WASM import section payload format:
//
//	[count: varuint32]
//	[import]*
//	import := [module_len][module_str][field_len][field_str][kind][type_info...]
//
// kind == 0x00 (function) is the only case we encounter for WasmForge imports.
// Other kinds (table=1, memory=2, global=3) are passed through unchanged.
func remapImportSection(data []byte, exportNames map[string]string, wasiNames ...map[string]string) ([]byte, error) {
	var wasiNameMap map[string]string
	if len(wasiNames) > 0 {
		wasiNameMap = wasiNames[0]
	}
	pos := 0

	count, n, err := readLEB128u(data, pos)
	if err != nil {
		return nil, fmt.Errorf("reading import count: %w", err)
	}
	pos += n

	// Build output: write count first, then process each import.
	out := encodeLEB128u(count)

	for i := 0; i < int(count); i++ {
		// Read module string.
		modLen, n, err := readLEB128u(data, pos)
		if err != nil {
			return nil, fmt.Errorf("import %d: reading module len: %w", i, err)
		}
		pos += n
		if pos+int(modLen) > len(data) {
			return nil, fmt.Errorf("import %d: module string truncated", i)
		}
		modStr := string(data[pos : pos+int(modLen)])
		pos += int(modLen)

		// Read field string.
		fieldLen, n, err := readLEB128u(data, pos)
		if err != nil {
			return nil, fmt.Errorf("import %d: reading field len: %w", i, err)
		}
		pos += n
		if pos+int(fieldLen) > len(data) {
			return nil, fmt.Errorf("import %d: field string truncated", i)
		}
		fieldStr := string(data[pos : pos+int(fieldLen)])
		pos += int(fieldLen)

		// Read kind byte.
		if pos >= len(data) {
			return nil, fmt.Errorf("import %d: kind byte missing", i)
		}
		kind := data[pos]
		pos++

		// Determine final field name: replace if this is an "env" import
		// (exportNames) or "wasi_snapshot_preview1" import (wasiNameMap).
		finalField := fieldStr
		if strings.EqualFold(modStr, "env") {
			if newName, ok := exportNames[fieldStr]; ok {
				finalField = newName
			}
		} else if modStr == "wasi_snapshot_preview1" && wasiNameMap != nil {
			if newName, ok := wasiNameMap[fieldStr]; ok {
				finalField = newName
			}
		}

		// Write module string (unchanged).
		out = append(out, encodeLEB128u(uint64(len(modStr)))...)
		out = append(out, []byte(modStr)...)

		// Write field string (possibly replaced).
		out = append(out, encodeLEB128u(uint64(len(finalField)))...)
		out = append(out, []byte(finalField)...)

		// Write kind byte.
		out = append(out, kind)

		// Copy kind-specific type info.
		switch kind {
		case 0x00: // function: type index (LEB128)
			typeIdx, n, err := readLEB128u(data, pos)
			if err != nil {
				return nil, fmt.Errorf("import %d: reading function type index: %w", i, err)
			}
			out = append(out, encodeLEB128u(typeIdx)...)
			pos += n

		case 0x01: // table: reftype (1 byte) + limits
			if pos+1 > len(data) {
				return nil, fmt.Errorf("import %d: table reftype truncated", i)
			}
			out = append(out, data[pos])
			pos++
			limitsBytes, n, err := copyLimits(data, pos)
			if err != nil {
				return nil, fmt.Errorf("import %d: table limits: %w", i, err)
			}
			out = append(out, limitsBytes...)
			pos += n

		case 0x02: // memory: limits
			limitsBytes, n, err := copyLimits(data, pos)
			if err != nil {
				return nil, fmt.Errorf("import %d: memory limits: %w", i, err)
			}
			out = append(out, limitsBytes...)
			pos += n

		case 0x03: // global: valtype (1 byte) + mutability (1 byte)
			if pos+2 > len(data) {
				return nil, fmt.Errorf("import %d: global type truncated", i)
			}
			out = append(out, data[pos:pos+2]...)
			pos += 2

		default:
			return nil, fmt.Errorf("import %d: unknown import kind 0x%02X", i, kind)
		}
	}

	return out, nil
}

// copyLimits reads a WASM limits structure (flags + min [+ max]) and returns
// the raw bytes plus the number of bytes consumed.
func copyLimits(data []byte, pos int) ([]byte, int, error) {
	if pos >= len(data) {
		return nil, 0, fmt.Errorf("limits: flags byte missing")
	}
	flags := data[pos]
	start := pos
	pos++

	// min: LEB128
	_, n, err := readLEB128u(data, pos)
	if err != nil {
		return nil, 0, fmt.Errorf("limits: reading min: %w", err)
	}
	pos += n

	// max: present if flags bit 0 is set
	if flags&0x01 != 0 {
		_, n, err := readLEB128u(data, pos)
		if err != nil {
			return nil, 0, fmt.Errorf("limits: reading max: %w", err)
		}
		pos += n
	}

	consumed := pos - start
	return data[start:pos], consumed, nil
}
