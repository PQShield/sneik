//  test_aead.c
//  2019-02-22  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (C) 2019, PQShield Ltd. Please see LICENSE.

//  Super simple test code

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "api.h"
#include "crypto_aead.h"
#include "f512_param.h"

// print byte vectors

void debug_vec(const void *p, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        switch (i & 0xF) {
            case 0:
                if (i > 0)
                    printf("\n");
                printf("\t");
                break;

            case 4:
            case 8:
            case 12:
                printf("  ");
                break;

            default:
                printf(" ");
                break;
        }
        printf("%02X", ((const uint8_t *) p)[i]);
    }
    printf("\n");
}

// randomize a buffer in testing

void rand_fill(void *p, size_t l)
{
    size_t i;

    for (i = 0; i < l; i++)
        ((uint8_t *) p)[i] = rand() & 0xFF;
}

// quick known-answer and randomized self-test

int blnk_selftest()
{
    // test vector for the pi permutation
    const uint8_t pi_test[64] = {
        0x87, 0x04, 0x50, 0x6B, 0xDA, 0x36, 0x68, 0x4C,
        0x79, 0x3F, 0xF4, 0xA9, 0xC3, 0xD0, 0xBA, 0x56,
        0xE4, 0xF5, 0x14, 0xEB, 0xB4, 0xDE, 0x2C, 0x83,
        0xC2, 0x92, 0x51, 0xB2, 0xA0, 0x41, 0xE7, 0x80,
        0x2C, 0xB8, 0xA4, 0xA0, 0x56, 0x62, 0x5B, 0x18,
        0xA4, 0xEF, 0x20, 0xDD, 0xD9, 0x1A, 0x64, 0xE8,
        0x88, 0x25, 0xE8, 0x89, 0x66, 0xE6, 0xCD, 0x76,
        0xA0, 0x30, 0x60, 0x9B, 0x11, 0x15, 0x78, 0xE1
    };

    size_t i;
    uint8_t s[BLNK_BLOCK];
    unsigned long long mlen, clen, alen, xlen;

    uint8_t pt[0x100];
    uint8_t ad[0x100];
    uint8_t ct[0x100 + CRYPTO_ABYTES];
    uint8_t xt[0x100];
    uint8_t key[CRYPTO_KEYBYTES];
    uint8_t npub[CRYPTO_NPUBBYTES];

    // known plaintext test on the Pi
    for (i = 0; i < 64; i++)
        s[i] = 111 + i;

    sneik_f512(s, 234, 8);

    if (memcmp(s, pi_test, sizeof(pi_test)) != 0) {
        return (-(__LINE__));
    }

    //  print the last KAT line

    memset(ct, 0, sizeof(ct));
    for (i = 0; i < 32; i++)
        pt[i] = i;

    clen = 0;
    if (crypto_aead_encrypt(ct, &clen, pt, 32, pt, 32, NULL, pt, pt) != 0) {
        return (-(__LINE__));
    }

    if (clen != 32 + CRYPTO_ABYTES) {
        return (-(__LINE__));
    }

    printf("CT = ");
    for (i = 0; i < clen; i++)
        printf("%02X", ct[i]);
    printf("\n");


    // now test encrypt and decrypt functions

    for (i = 0; i < 10000; i++) {

        mlen = rand() & 0xFF;
        rand_fill(pt, (size_t) mlen);
        alen = rand() & 0xFF;
        rand_fill(ad, (size_t) alen);
        rand_fill(key, CRYPTO_KEYBYTES);
        rand_fill(npub, CRYPTO_NPUBBYTES);

        if (crypto_aead_encrypt(ct, &clen, pt, mlen, ad, alen, NULL,
            npub, key) != 0)
            return (-(__LINE__));

        if (crypto_aead_decrypt(xt, &xlen, NULL, ct, clen, ad, alen,
            npub, key) != 0)
            return (-(__LINE__));

        // compare the plaintext
        if (xlen != mlen)
            return (-(__LINE__));
        if (memcmp(xt, pt, (size_t) mlen) != 0)
            return (-(__LINE__));

        // random change
        switch(rand() % 4) {
            case 0:
                if (clen > 0)
                    ct[rand() % clen] ^= 0x01 << (rand() & 7);
                else
                    ct[clen++] = rand() & 0xFF;
                break;

            case 1:
                key[rand() % CRYPTO_KEYBYTES] ^= 0x01 << (rand() & 7);
                break;

            case 2:
                if (alen > 0)
                    ad[rand() % alen] ^= 0x01 << (rand() & 7);
                else
                    ad[alen++] = rand() & 0xFF;;
                break;

            case 3:
                npub[rand() % CRYPTO_NPUBBYTES] ^= 0x01 << (rand() & 7);
                break;
        }

        // fail if successful decryption
        if (crypto_aead_decrypt(xt, &xlen, NULL, ct, clen, ad, alen,
            npub, key) == 0)
            return (-(__LINE__));
    }

    return 0;
}

// speed test (just on the compression function)

void blnk_pi_speed()
{
    uint64_t i, n;
    clock_t clk;
    double kb, sec;
    uint8_t s[BLNK_BLOCK];

    n = 100000;

    for (i = 0; i < BLNK_BLOCK; i++)
        s[i] = i;

    do {
        clk = clock();
        for (i = 0; i < n; i++) {
            s[0] ^= i;
            sneik_f512(s, 234, SNEIK_ROUNDS);
        }
        clk = clock() - clk;
        sec = ((double) clk) / ((double) CLOCKS_PER_SEC);
        kb = ((double) BLNK_RATE) * ((double) n) / 1000.0;
        n <<= 1;
    } while (clk < CLOCKS_PER_SEC);

    printf("%.2f kB/s (%gkB/%gs)\n", kb / sec, kb, sec);
}

// stub main

int main()
{
    int err;

    err = blnk_selftest();
    if (err != 0) {
        printf("blnk_selftest() = %d\n", err);
        return err;
    } else {
        printf("blnk_selftest() PASS\n");
    }

    blnk_pi_speed();

    return 0;
}

