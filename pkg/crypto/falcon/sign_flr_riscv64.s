//go:build !gccgo && !fndsa_fp_emu

#include "textflag.h"

TEXT ·f64_rint(SB),NOSPLIT,$0-12
	MOVD        x+0(FP), F0
	FCVTWD.RNE  F0, X5
	MOVW        X5, ret+8(FP)
	RET

TEXT ·f64_floor(SB),NOSPLIT,$0-12
	MOVD        x+0(FP), F0
	FCVTWD.RDN  F0, X5
	MOVW        X5, ret+8(FP)
	RET

TEXT ·f64_sqrt(SB),NOSPLIT,$0-16
	MOVD        x+0(FP), F0
	FSQRTD      F0, F0
	MOVD        F0, ret+8(FP)
	RET
