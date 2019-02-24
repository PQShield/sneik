//  hash.c
//  2019-02-24  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (C) 2019, PQShield Ltd. Please see LICENSE.

//  "Optimized" (self-contained) hash

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "api.h"
#include "crypto_hash.h"
#include "f512_param.h"

#define BLNK_LAST   0x01                    // Last (padded) block of domain
#define BLNK_AD     0x10                    // Authenticated data (in)
#define BLNK_HASH   0x40                    // Hash/Authentication tag (out)

//  Single-call NIST interface

int crypto_hash(
    unsigned char *out,
    const unsigned char *in,
    unsigned long long inlen)
{
    uint8_t s[BLNK_BLOCK];                  //  Local state
    size_t  i, l;

    memset(s, 0x00, BLNK_BLOCK);            //  Initialize state

    l = (size_t) inlen;                     //  Use a natural-sized type
    while (l >= BLNK_RATE) {                //  Absorb blocks
        for (i = 0; i < BLNK_RATE; i++) {
            s[i] ^= in[i];
        }
        sneik_f512(s, BLNK_AD, SNEIK_ROUNDS);
        in += BLNK_RATE;
        l -= BLNK_RATE;
    }
    for (i = 0; i < l; i++) {               //  Last block
        s[i] ^= in[i];
    }
    s[l] ^= 0x01;                           //  "last" padding
    s[BLNK_RATE - 1] ^= 0x80;               //  rate padding
    in += l;
    sneik_f512(s, BLNK_AD | BLNK_LAST, SNEIK_ROUNDS);

    i = CRYPTO_BYTES;
    while (i > BLNK_RATE) {
        memcpy(out, s, BLNK_RATE);
        out += BLNK_RATE;
        i -= BLNK_RATE;
        sneik_f512(s, BLNK_HASH, SNEIK_ROUNDS);
    }
    memcpy(out, s, i);                      //  last partial block

    return 0;                               //  Success
}

