//go:build darwin && amd64

#include "textflag.h"

// func dlopen_trampoline(name uintptr, mode uintptr) uintptr
TEXT ·dlopen_trampoline(SB), NOSPLIT|NOFRAME, $0-24
	MOVQ name+0(FP), DI
	MOVQ mode+8(FP), SI
	CALL dlopen(SB)
	MOVQ AX, ret+16(FP)
	RET

// func dlsym_trampoline(handle uintptr, name uintptr) uintptr
TEXT ·dlsym_trampoline(SB), NOSPLIT|NOFRAME, $0-24
	MOVQ handle+0(FP), DI
	MOVQ name+8(FP), SI
	CALL dlsym(SB)
	MOVQ AX, ret+16(FP)
	RET

// func ccall9(fn uintptr, a0, a1, a2, a3, a4, a5, a6, a7, a8 uintptr) uintptr
// Calls a C function pointer with up to 9 arguments using SysV AMD64 ABI.
// Args 0-5 in registers (RDI, RSI, RDX, RCX, R8, R9), args 6-8 on the stack.
TEXT ·ccall9(SB), NOSPLIT, $48-88
	MOVQ fn+0(FP), R11
	MOVQ a0+8(FP), DI
	MOVQ a1+16(FP), SI
	MOVQ a2+24(FP), DX
	MOVQ a3+32(FP), CX
	MOVQ a4+40(FP), R8
	MOVQ a5+48(FP), R9
	// Args 6-8 go on the C call stack.
	MOVQ a6+56(FP), AX
	MOVQ AX, 0(SP)
	MOVQ a7+64(FP), AX
	MOVQ AX, 8(SP)
	MOVQ a8+72(FP), AX
	MOVQ AX, 16(SP)
	CALL R11
	MOVQ AX, ret+80(FP)
	RET
