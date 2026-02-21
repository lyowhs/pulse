//go:build !gccgo && !fndsa_fp_emu

#include "textflag.h"

TEXT ·f64_rint(SB),NOSPLIT,$0-12
	MOVSD       x+0(FP), X0
	CVTSD2SL    X0, AX
	MOVL        AX, ret+8(FP)
	RET

TEXT ·f64_floor(SB),NOSPLIT,$0-12
	MOVSD       x+0(FP), X0
	CVTSD2SL    X0, AX
	CVTSL2SD    AX, X1
	COMISD      X1, X0
	SBBL        $0, AX
	MOVL        AX, ret+8(FP)
	RET

TEXT ·f64_sqrt(SB),NOSPLIT,$0-16
	MOVSD       x+0(FP), X0
	SQRTSD      X0, X0
	MOVSD       X0, ret+8(FP)
	RET
