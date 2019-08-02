//  sneik_f512_armv7_fast.S
//  2019-02-06  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (C) 2019, PQShield Ltd. Please see LICENSE.

//  SNEIK f512 v1.1 implementation for ARMv7 (including ARMv7-m), unrolled.

//  Two implementation macros

.macro SNEIK1   x, y, z                     // s[i], s[(i+14)%16], s[(i+15)%16]
        ADD     \x, \x, \z                  // x += z;
        EOR     R3, \x, \x, ROR #8          // x ^= (x <<< 24)
        EOR     \x, R3, \x, ROR #7          //    ^ (x <<< 25);
        EOR     \x, \x, \y, ROR #31         // x ^= (y <<< 1);
.endm

.macro SNEIK2   x, y, z                     // s[i], s[(i+1)%16], s[(i+2)%16]
        ADD     \x, \x, \z                  // x += z;
        EOR     R3, \x, \x, ROR #23         // x ^= (x <<< 9)
        EOR     \x, R3, \x, ROR #15         //    ^ (x <<< 17);
        EOR     \x, \x, \y                  // x ^= y;
.endm

//  C prototype: void sneik_f512(void *state, uint8_t dom, uint8_t rounds);

        .text
        .global sneik_f512
        .syntax unified
        .type   sneik_f512, %function

sneik_f512:

        push    {r4-r11, lr}
        ldr     ip,     .rcptr              //  table of round constants

        ldr     r4,     [r0]
        ldr     r5,     [r0, #4]
        ldr     r6,     [r0, #56]
        ldr     r7,     [r0, #60]

        ldr     r8,     [r0, #8];
        ldr     r9,     [r0, #12];
        ldr     r10,    [r0, #16];
        ldr     r11,    [r0, #20];
        ldr     lr,     [r0, #24];

.round:
        ldrb    r3, [ip], #1                //  round constant
        eor     r4, r4, r3
        eor     r5, r5, r1                  //  domain

        SNEIK1  r4, r6, r7                  //  step 0
        SNEIK2  r4, r5, r8
        str     r4, [r0, #0]

        SNEIK1  r5, r7, r4                  //  step 1
        SNEIK2  r5, r8, r9
        str     r5, [r0, #4]

        SNEIK1  r8, r4, r5                  //  step 2
        SNEIK2  r8, r9, r10

        SNEIK1  r9, r5, r8                  //  step 3
        SNEIK2  r9, r10, r11

        SNEIK1  r10, r8, r9                 //  step 4
        SNEIK2  r10, r11, lr

        SNEIK1  r11, r9, r10                //  step 5
        ldr     r7, [r0, #28]
        SNEIK2  r11, lr, r7

        SNEIK1  lr, r10, r11                //  step 6
        ldr     r4, [r0, #32]
        SNEIK2  lr, r7, r4

        SNEIK1  r7, r11, lr                 //  step 7
        ldr     r5, [r0, #36]
        SNEIK2  r7, r4, r5
        str     r7, [r0, #28]

        SNEIK1  r4, lr, r7                  //  step 8
        ldr     r6, [r0, #40]
        SNEIK2  r4, r5, r6
        str     r4, [r0, #32]

        SNEIK1  r5, r7, r4                  //  step 9
        ldr     r7, [r0, #44]
        SNEIK2  r5, r6, r7
        str     r5, [r0, #36]

        SNEIK1  r6, r4, r5                  //  step 10
        ldr     r4, [r0, #48]
        SNEIK2  r6, r7, r4
        str     r6, [r0, #40]

        SNEIK1  r7, r5, r6                  //  step 11
        ldr     r5, [r0, #52]
        SNEIK2  r7, r4, r5
        str     r7, [r0, #44]

        SNEIK1  r4, r6, r7                  //  step 12
        ldr     r6, [r0, #56]
        SNEIK2  r4, r5, r6
        str     r4, [r0, #48]

        SNEIK1  r5, r7, r4                  //  step 13
        ldr     r7, [r0, #60]
        SNEIK2  r5, r6, r7
        str     r5, [r0, #52]

        SNEIK1  r6, r4, r5                  //  step 14
        ldr     r4, [r0, #0]
        SNEIK2  r6, r7, r4
        str     r6, [r0, #56]

        SNEIK1  r7, r5, r6                  //  step 15
        ldr     r5, [r0, #4]
        SNEIK2  r7, r4, r5
        str     r7, [r0, #60]

        subs    r2, r2, #1                  // loop
        bne     .round

        str     r8,  [r0, #8];
        str     r9,  [r0, #12];
        str     r10, [r0, #16];
        str     r11, [r0, #20];
        str     lr,  [r0, #24];

        pop     {r4-r11, pc}

        .align  2
.rcptr: .word   .rc

        .size       sneik_f512, .-sneik_f512
        .section    .rodata

.rc:    .byte   0xEF, 0xE0, 0xD9, 0xD6, 0xBA, 0xB5, 0x8C, 0x83
        .byte   0x10, 0x1F, 0x26, 0x29, 0x45, 0x4A, 0x73, 0x7C

