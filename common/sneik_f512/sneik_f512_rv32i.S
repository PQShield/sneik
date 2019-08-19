//  sneik_f512_rv32i.S
//  2019-07-28  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (C) 2019, PQShield Ltd. Please see LICENSE.

/*
    RISC-V calling convention is

    Reg === Name == Description ======================= Saver ==
    x0      zero    Hard-wired zero                     -
    x1      ra      Return address                      Caller
    x2      sp      Stack pointer                       Callee
    x3      gp      Global pointer                      -
    x4      tp      Thread pointer                      -
    x5-x7   t0-t2   Temporaries                         Caller
    x8      s0/fp   Saved register/frame pointer        Callee
    x9      s1      Saved register                      Callee
    x10-x11 a0-a1   Function arguments/return values    Caller
    x12-x17 a2-a7   Function arguments                  Caller
    x18-x27 s2-s11  Saved registers                     Callee
    x28-x31 t3-t6   Temporaries                         Caller

    The 16-word state is kept in registers during run:

    word index:    0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
    reg name:   [ t0 t1 t2 t3 t4 t5 t6 a3 a4 a5 a6 a7 s0 s1 s2 s3 ]
*/

//  preamble

        .option nopic
        .text
        .align  4

//  A SNEIK Step. Window: s[0], s[1], s[2], s[14], s[15]

.macro SNEIKS  a, b, c, d, e
        ADD   \a, \a, \e                    // a += e;  a=s[i], e=s[(i+15)%16]
        SLLI  a2, \a, 24                    // a ^= (a <<< 24)
        SRLI  s6, \a,  8
        XOR   a2, a2, s6
        SLLI  s6, \a, 25                    //    ^ (a <<< 25);
        XOR   a2, a2, s6
        SRLI  s6, \a,  7
        XOR   a2, a2, s6
        XOR   \a, \a, a2
        SLLI  a2, \d,  1                    // a ^= (d <<< 1);  d=s[(i+14)%16]
        SRLI  s6, \d, 31
        XOR   a2, a2, s6
        XOR   \a, \a, a2
        ADD   \a, \a, \c                    // a += c;          c=s[(i+2)%16]
        SLLI  a2, \a,  9                    // a ^= (a <<< 9)
        SRLI  s6, \a, 23
        XOR   a2, a2, s6
        SLLI  s6, \a, 17                    //    ^ (a <<< 17);
        XOR   a2, a2, s6
        SRLI  s6, \a, 15
        XOR   a2, a2, s6
        XOR   \a, \a, a2
        XOR   \a, \a, \b                    // a ^= b;          b=s[(i+1)%16]
.endm

//  C protype: void sneik_f512(void *state, uint8_t dom, uint8_t rounds)
//  a0=state (16 words), a1=dom, a2=rounds.

        .globl  sneik_f512
        .type   sneik_f512,  @function

sneik_f512:
        addi    sp, sp, -28                 //  28 byte stack frame

        sw      s0, 0(sp)                   //  stash registers in stack
        sw      s1, 4(sp)
        sw      s2, 8(sp)
        sw      s3, 12(sp)
        sw      s4, 16(sp)
        sw      s5, 20(sp)
        sw      s6, 24(sp)

        lw      t0, 0(a0)                   //  get the 16 state values
        lw      t1, 4(a0)
        lw      t2, 8(a0)
        lw      t3, 12(a0)
        lw      t4, 16(a0)
        lw      t5, 20(a0)
        lw      t6, 24(a0)
        lw      a3, 28(a0)
        lw      a4, 32(a0)
        lw      a5, 36(a0)
        lw      a6, 40(a0)
        lw      a7, 44(a0)
        lw      s0, 48(a0)
        lw      s1, 52(a0)
        lw      s2, 56(a0)
        lw      s3, 60(a0)

        lui     s4,     %hi(.rc)            //  pointer to round constants
        addi    s4, s4, %lo(.rc)

        add     s5, s4, a2                  //  s5  pointer to last rc

.loop:
        lbu     a2, 0(s4)                   //  get rc byte
        xor     t0, t0, a2                  //  st[0] ^= rc[r]
        xor     t1, t1, a1                  //  st[1] ^= dom

        SNEIKS	t0, t1, t2, s2, s3          //  whole round unrolled
        SNEIKS  t1, t2, t3, s3, t0
        SNEIKS  t2, t3, t4, t0, t1
        SNEIKS  t3, t4, t5, t1, t2
        SNEIKS  t4, t5, t6, t2, t3
        SNEIKS  t5, t6, a3, t3, t4
        SNEIKS  t6, a3, a4, t4, t5
        SNEIKS  a3, a4, a5, t5, t6
        SNEIKS  a4, a5, a6, t6, a3
        SNEIKS  a5, a6, a7, a3, a4
        SNEIKS  a6, a7, s0, a4, a5
        SNEIKS  a7, s0, s1, a5, a6
        SNEIKS  s0, s1, s2, a6, a7
        SNEIKS  s1, s2, s3, a7, s0
        SNEIKS  s2, s3, t0, s0, s1
        SNEIKS  s3, t0, t1, s1, s2

        addi    s4, s4, 1                   //  rc index is loop counter
        bne     s5, s4, .loop               //  finished ?

        sw      t0, 0(a0)                   //  save the state
        sw      t1, 4(a0)
        sw      t2, 8(a0)
        sw      t3, 12(a0)
        sw      t4, 16(a0)
        sw      t5, 20(a0)
        sw      t6, 24(a0)
        sw      a3, 28(a0)
        sw      a4, 32(a0)
        sw      a5, 36(a0)
        sw      a6, 40(a0)
        sw      a7, 44(a0)
        sw      s0, 48(a0)
        sw      s1, 52(a0)
        sw      s2, 56(a0)
        sw      s3, 60(a0)

        lw      s0, 0(sp)                   //  load stashed values from stack
        lw      s1, 4(sp)
        lw      s2, 8(sp)
        lw      s3, 12(sp)
        lw      s4, 16(sp)
        lw      s5, 20(sp)
        lw      s6, 24(sp)

        addi    sp, sp, 28                  //  restore stack pointer
        jr      ra                          //  return
        .size   sneik_f512,  .-sneik_f512

        //      round constants
        .section    .rodata
.rc:    .byte   0xEF, 0xE0, 0xD9, 0xD6, 0xBA, 0xB5, 0x8C, 0x83
        .byte   0x10, 0x1F, 0x26, 0x29, 0x45, 0x4A, 0x73, 0x7C

