//	sneik_f512_armv7_small.S
//	2019-02-06	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (C) 2019, PQShield Ltd. Please see LICENSE.

//	SNEIK f512 implementation for ARMv7 (including ARMv7-m), smaller

//	C prototype: void sneik_f512(void *state, uint8_t dom, uint8_t rounds);

		.text
		.global sneik_f512
		.syntax unified
		.type	sneik_f512, %function

//		mixing function for 4 rotating registers (r3 is temporary)

.macro	mix_f	t0, t1, t2, t3
		add		\t0, \t0, \t3				// t0 += t3;
		eor		r3,	 \t0, \t0, ror #8		// t0 = t0 ^ ROR32(t0, 8)
		eor		\t0, r3,  \t0, ror #7		//		   ^ ROR32(t0, 7);
		eor		\t0, \t0, \t2				// t0 ^= t2;
		ldr		\t2, [r8], #4				// t2 = vec[(pos + 2) & 0xF];
		add		\t0, \t0, \t2				// t0 += t2;
		eor		r3,	 \t0, \t0, ror #8		// t0 = t0 ^ ROR32(t0, 15)
		eor		\t0, \t0, r3,  ror #15		//		   ^ ROR32(t0, 23);
		eor		\t0, \t0, \t1				// t0 ^= t1
		str		\t0, [r0], #4				// vec[pos] = t0;
		.endm

.mixf4: mix_f	r4, r5, r6, r7				// 4 steps as a subroutine
		mix_f	r5, r6, r7, r4
		sub		r8, r8, r9					// conditional wrap-around
		mix_f	r6, r7, r4, r5
		mix_f	r7, r4, r5, r6
		bx		lr

sneik_f512:

		push	{r4, r5, r6, r7, r8, r9, lr}
		ldr		ip, .rcptr					// table of round constants
		mov		r8, r0
		ldr		r4, [r8], #4
		ldr		r5, [r8], #4
		ldr		r6, [r0, #4*14]
		ldr		r7, [r0, #4*15]

.round:
		ldrb	r3, [ip], #1				// round constant
		eor		r4, r4, r3
		eor		r5, r5, r1					// domain

		mov		r9, #0
		bl		.mixf4
		bl		.mixf4
		bl		.mixf4
		mov		r9, #64
		bl		.mixf4
		sub		r0, r0, #64

		subs	r2, r2, #1					// loop
		bne		.round

		pop		{r4, r5, r6, r7, r8, r9, pc}

		.align	2
.rcptr: .word	.rc

		.size		sneik_f512, .-sneik_f512
		.section	.rodata

.rc:	.byte	0xEF, 0xE0, 0xD9, 0xD6, 0xBA, 0xB5, 0x8C, 0x83
		.byte	0x10, 0x1F, 0x26, 0x29, 0x45, 0x4A, 0x73, 0x7C

