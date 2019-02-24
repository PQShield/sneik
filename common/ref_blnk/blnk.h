//  blnk.h
//  2019-02-23  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (C) 2019, PQShield Ltd. Please see LICENSE.

//  BLNK2 modes.

#ifndef _BLNK_H_
#define _BLNK_H_

#include <stdint.h>
#include <stddef.h>
#include "f512_param.h"

#define BLNK_LAST   0x01                    // Last (padded) block of domain
#define BLNK_FULL   0x02                    // Full state input (0: RATE input)
#define BLNK_A2B    0x04                    // Alice -> Bob
#define BLNK_B2A    0x08                    // Bob -> Alice
#define BLNK_AD     0x10                    // Authenticated data (in)
#define BLNK_ADF    (BLNK_AD | BLNK_FULL)   // Full-state assoc. data (in)
#define BLNK_KEY    0x20                    // Secret key (in)
#define BLNK_KEYF   (BLNK_KEY | BLNK_FULL)  // Secret key/nonce block (in)
#define BLNK_HASH   0x40                    // Hash/Authentication tag (out)
#define BLNK_PTCT   0x70                    // Plaintext or Ciphertext (in/out)
#define BLNK_BIT7   0x80                    // Reserved

// Internal errors indicate a line in the code
#define BLNK_ERR   (-(__LINE__))

// Domain indicator
typedef uint8_t blnk_dom_t;

//  State
typedef struct {
    uint8_t s[BLNK_BLOCK];                  // state
    size_t i;                               // data position (byte) in state
} blnk_t;

//  Initialize
void blnk_clr(blnk_t *st);

//  End a data element (compulsory between different types)
void blnk_fin(blnk_t *st, blnk_dom_t dom);

//  Absorb data
void blnk_put(blnk_t *st, blnk_dom_t dom, const void *in, size_t len);

//  Squeze data
void blnk_get(blnk_t *st, blnk_dom_t dom, void *out, size_t len);

//  Encrypt data
void blnk_enc(blnk_t *st, blnk_dom_t dom,
        void *out, const void *in, size_t len);

//  Decrypt data
void blnk_dec(blnk_t *st, blnk_dom_t dom,
        void *out, const void *in, size_t len);

// Compare to output (0 == equal)
int blnk_cmp(blnk_t *st, blnk_dom_t dom, const void *in, size_t len);

#endif

