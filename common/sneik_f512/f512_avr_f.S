//  f512_avr_f.S
//  2019-02-14  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (C) 2019, PQShield Ltd. Please see LICENSE.

//  8-bit Atmel AVR implementation for the f512 function, fully unrolled.

//  Prototype:
//      void sneik_f512(void *s, uint8_t dom, uint8_t rounds);

__zero_reg__ = 1

        .text

// load 4 bytes to 4 registers

.macro  ldzv4   rr, pos, rv
        ldd     \rr,        z + (4 * ((\pos + \rv) % 16))
        ldd     \rr + 1,    z + (4 * ((\pos + \rv) % 16) + 1)
        ldd     \rr + 2,    z + (4 * ((\pos + \rv) % 16) + 2)
        ldd     \rr + 3,    z + (4 * ((\pos + \rv) % 16) + 3)
        .endm

// store 4 bytes from 4 registers

.macro  stzv4   pos, rv, rr
        std     z + (4 * ((\pos + \rv) % 16)), \rr
        std     z + (4 * ((\pos + \rv) % 16) + 1), \rr + 1
        std     z + (4 * ((\pos + \rv) % 16) + 2), \rr + 2
        std     z + (4 * ((\pos + \rv) % 16) + 3), \rr + 3
        .endm

// mixing function. macro loads v1

.macro  mix_f   pos, t0, t1, t2, t3, tmp

        //      inner feedback left
        add     \t0,        \t3         //  t0 += t3;
        adc     \t0 + 1,    \t3 + 1
        adc     \t0 + 2,    \t3 + 2
        adc     \t0 + 3,    \t3 + 3

        //      p = x^25 + x^24 + 1
        mov     \tmp + 3,   \t0         //  tmp = t0 <<< 24
        mov     \tmp,       \t0 + 1
        mov     \tmp + 1,   \t0 + 2
        mov     \tmp + 2,   \t0 + 3
        eor     \t0,        \tmp        //  t0 = t0 ^ (t0 <<< 24)
        eor     \t0 + 1,    \tmp + 1
        eor     \t0 + 2,    \tmp + 2
        eor     \t0 + 3,    \tmp + 3
        lsl     \tmp                    //  tmp = t0 <<< 25
        rol     \tmp + 1
        rol     \tmp + 2
        rol     \tmp + 3
        adc     \tmp,   __zero_reg__
        eor     \t0,        \tmp        //  t0 ^ (t0 <<< 24) ^ (t0 <<< 25)
        eor     \t0 + 1,    \tmp + 1
        eor     \t0 + 2,    \tmp + 2
        eor     \t0 + 3,    \tmp + 3

        //      outer feedback
        eor     \t0,        \t2         //  t0 ^= t2;
        eor     \t0 + 1,    \t2 + 1
        eor     \t0 + 2,    \t2 + 2
        eor     \t0 + 3,    \t2 + 3

        ldzv4   \t2, \pos,  2           //  vec[(pos + 2) & 0xF];

        add     \t0,        \t2         //  t0 += t2;
        adc     \t0 + 1,    \t2 + 1
        adc     \t0 + 2,    \t2 + 2
        adc     \t0 + 3,    \t2 + 3

        //      p = x^17 + x^9 + 1
        mov     \tmp + 1,   \t0         //  tmp = t0 <<< 8
        mov     \tmp + 2,   \t0 + 1
        mov     \tmp + 3,   \t0 + 2
        mov     \tmp,       \t0 + 3
        eor     \tmp + 2,   \t0         //  tmp = (t0 <<< 8) ^ (t0 <<< 16)
        eor     \tmp + 3,   \t0 + 1
        eor     \tmp,       \t0 + 2
        eor     \tmp + 1,   \t0 + 3
        lsl     \tmp                    //  tmp = (t0 <<< 9) ^ (t0 <<< 17)
        rol     \tmp + 1
        rol     \tmp + 2
        rol     \tmp + 3
        adc     \tmp,   __zero_reg__
        eor     \t0,        \tmp        //  t0 ^ (t0 <<< 9) ^ (t0 <<< 17)
        eor     \t0 + 1,    \tmp + 1
        eor     \t0 + 2,    \tmp + 2
        eor     \t0 + 3,    \tmp + 3

        //      inner feedback right
        eor     \t0,        \t1         //  t0 ^= t1;
        eor     \t0 + 1,    \t1 + 1
        eor     \t0 + 2,    \t1 + 2
        eor     \t0 + 3,    \t1 + 3

        //      store v[0]
        stzv4   \pos, 0,    \t0

        .endm

//  The C call convention with AVR is that:
//  R2  - R17, R28, R29 are call-saved
//  R18 - R27, R30, R31 are call-globbered

.global sneik_f512
        .type   sneik_f512, @function

sneik_f512:
        push    r4
        push    r5
        push    r6
        push    r7
        push    r8
        push    r9
        push    r10
        push    r11
        push    r12
        push    r13
        push    r14
        push    r15
        push    r16
        push    r17

        movw    z,      r24             // state pointer (arg 0 = r25:r24)
        mov     r21,    r22             // domain (arg 1 = 23:22)

        ldi     xl,     lo8(rc)         // round constant
        ldi     xh,     hi8(rc)

        //  aliases for 32-bit register sets
        W0      = 4                     //  "W0" is ( r4,  r5,  r6,  r7  )
        W1      = 8                     //  "W1" is ( r8,  r9,  r10, r11 )
        W2      = 12                    //  "W2" is ( r12, r13, r14, r15 )
        W3      = 16                    //  "W3" is ( r16, r17, r18, r19 )
        WT      = 22                    //  "WT" is ( r22, r23, r24, r25 )

        ldzv4   W0, 0,  0               //  W0 = v[ 0]
        ldzv4   W1, 0,  1               //  W1 = v[ 1]
        ldzv4   W2, 0,  14              //  W2 = v[14]
        ldzv4   W3, 0,  15              //  W3 = v[15]

.round:
        ld      WT, x+                  // round constant
        eor     W0, WT
        eor     W1, r21                 // domain

        mix_f   0,  W0, W1, W2, W3, WT
        mix_f   1,  W1, W2, W3, W0, WT
        mix_f   2,  W2, W3, W0, W1, WT
        mix_f   3,  W3, W0, W1, W2, WT
        mix_f   4,  W0, W1, W2, W3, WT
        mix_f   5,  W1, W2, W3, W0, WT
        mix_f   6,  W2, W3, W0, W1, WT
        mix_f   7,  W3, W0, W1, W2, WT
        mix_f   8,  W0, W1, W2, W3, WT
        mix_f   9,  W1, W2, W3, W0, WT
        mix_f   10, W2, W3, W0, W1, WT
        mix_f   11, W3, W0, W1, W2, WT
        mix_f   12, W0, W1, W2, W3, WT
        mix_f   13, W1, W2, W3, W0, WT
        mix_f   14, W2, W3, W0, W1, WT
        mix_f   15, W3, W0, W1, W2, WT

        dec     r20                     //  round count (arg 2 = r21:r20)
        breq    .done
        jmp     .round
.done:
        pop     r17
        pop     r16
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     r11
        pop     r10
        pop     r9
        pop     r8
        pop     r7
        pop     r6
        pop     r5
        pop     r4

        ret

        // round constants
        .section    .rodata
rc:     .byte   0xEF, 0xE0, 0xD9, 0xD6, 0xBA, 0xB5, 0x8C, 0x83
        .byte   0x10, 0x1F, 0x26, 0x29, 0x45, 0x4A, 0x73, 0x7C

.global __do_copy_data
.global __do_clear_bss


