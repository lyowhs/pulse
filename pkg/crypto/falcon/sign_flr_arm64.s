//go:build !gccgo && !fndsa_fp_emu

#include "textflag.h"

TEXT ·f64_rint(SB),NOSPLIT,$0-12
	FMOVD       x+0(FP), F0
	FRINTND     F0, F0
	FCVTZSD     F0, R0
	MOVW        R0, ret+8(FP)
	RET

TEXT ·f64_floor(SB),NOSPLIT,$0-12
	FMOVD       x+0(FP), F0
	FRINTMD     F0, F0
	FCVTZSD     F0, R0
	MOVW        R0, ret+8(FP)
	RET

TEXT ·f64_sqrt(SB),NOSPLIT,$0-16
	FMOVD       x+0(FP), F0
	FSQRTD      F0, F0
	FMOVD       F0, ret+8(FP)
	RET
