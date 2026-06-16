//go:build darwin && arm64

#include "textflag.h"

// func dlopen_trampoline(name uintptr, mode uintptr) uintptr
// Frame size $0 (assembler auto-allocates space for LR+FP save on arm64).
// NOFRAME is intentionally omitted: BL clobbers LR, so the assembler-generated
// prologue must save LR to allow RET to return to the caller.
TEXT ·dlopen_trampoline(SB), NOSPLIT, $0-24
	MOVD name+0(FP), R0
	MOVD mode+8(FP), R1
	BL dlopen(SB)
	MOVD R0, ret+16(FP)
	RET

// func dlsym_trampoline(handle uintptr, name uintptr) uintptr
TEXT ·dlsym_trampoline(SB), NOSPLIT, $0-24
	MOVD handle+0(FP), R0
	MOVD name+8(FP), R1
	BL dlsym(SB)
	MOVD R0, ret+16(FP)
	RET

// func ccall9(fn uintptr, a0, a1, a2, a3, a4, a5, a6, a7, a8 uintptr) uintptr
// Calls a C function pointer with up to 9 arguments using ARM64 AAPCS64.
// Args 0-7 in registers (X0-X7), arg 8 on the stack.
//
// Stack layout (AAPCS64 §5.2.5):
//   Frame size $16 provides 16 bytes of local space. The Go assembler
//   adjusts SP before entry, so SP is 16-byte aligned at the BL site.
//   Arg 8 is stored at SP+0 (the first stack-passed argument slot).
//   The $16 frame satisfies the 16-byte stack alignment required by AAPCS64.
//
// Note: Most macOS framework APIs use ≤8 args (fitting entirely in registers).
// The 9th-arg path is provided for completeness; if >9 args are needed,
// extend this trampoline with additional stack slots.
TEXT ·ccall9(SB), NOSPLIT, $16-88
	MOVD fn+0(FP), R9
	MOVD a0+8(FP), R0
	MOVD a1+16(FP), R1
	MOVD a2+24(FP), R2
	MOVD a3+32(FP), R3
	MOVD a4+40(FP), R4
	MOVD a5+48(FP), R5
	MOVD a6+56(FP), R6
	MOVD a7+64(FP), R7
	// Arg 8 goes on the C call stack (SP+0, first stack slot per AAPCS64).
	MOVD a8+72(FP), R10
	MOVD R10, (RSP)
	BL (R9)
	MOVD R0, ret+80(FP)
	RET
