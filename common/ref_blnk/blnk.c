//  blnk.c
//  2019-02-20  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (C) 2019, PQShield Ltd. Please see LICENSE.

//  The BLNK2 core.

#include <string.h>
#include "blnk.h"

//  Clear state

void blnk_clr(blnk_t *st)
{
    memset(st->s, 0, BLNK_BLOCK);
    st->i = 0;
}

//  End a data element (compulsory between different domain types)

void blnk_fin(blnk_t *st, blnk_dom_t dom)
{
    const uint8_t pad[1] = { 0x01 };

    blnk_put(st, dom, pad, 1);              // padding bit
    if ((dom & BLNK_FULL) == 0) {           // not a full-state input domain?
        st->s[BLNK_RATE - 1] ^= 0x80;       // flip last bit before capacity
    }
    BLNK_PI(&st->s, dom | BLNK_LAST);       // finalize
    st->i = 0;
}

//  Absorb data

void blnk_put(blnk_t *st, blnk_dom_t dom, const void *in, size_t len)
{
    size_t j, rate;

    //  full state-absorption ?
    rate = dom & BLNK_FULL ? BLNK_BLOCK : BLNK_RATE;

    for (j = 0; j < len; j++) {
        if (st->i >= rate) {
            BLNK_PI(&st->s, dom);
            st->i = 0;
        }
        st->s[st->i++] ^= ((const uint8_t *) in)[j];
    }
}

//  Squeeze data

void blnk_get(blnk_t *st, blnk_dom_t dom, void *out, size_t len)
{
    size_t j;

    for (j = 0; j < len; j++) {
        if (st->i >= BLNK_RATE) {
            BLNK_PI(&st->s, dom);
            st->i = 0;
        }
        ((uint8_t *) out)[j] = st->s[st->i++];
    }
}

//  Encrypt data

void blnk_enc(blnk_t *st, blnk_dom_t dom,
    void *out, const void *in, size_t len)
{
    size_t j;

    for (j = 0; j < len; j++) {
        if (st->i >= BLNK_RATE) {
            BLNK_PI(&st->s, dom);
            st->i = 0;
        }
        st->s[st->i] ^= ((const uint8_t *) in)[j];
        ((uint8_t *) out)[j] = st->s[st->i++];
    }
}

//  Decrypt data

void blnk_dec(blnk_t *st, blnk_dom_t dom,
    void *out, const void *in, size_t len)
{
    size_t j;
    uint8_t t;

    for (j = 0; j < len; j++) {
        if (st->i >= BLNK_RATE) {
            BLNK_PI(&st->s, dom);
            st->i = 0;
        }
        t = ((const uint8_t *) in)[j];
        ((uint8_t *) out)[j] = st->s[st->i] ^ t;
        st->s[st->i++] = t;
    }
}

// Compare to output (0 == equal)

int blnk_cmp(blnk_t *st, blnk_dom_t dom, const void *in, size_t len)
{
    size_t j;
    uint8_t d;

    d = 0;
    for (j = 0; j < len; j++) {
        if (st->i >= BLNK_RATE) {
            BLNK_PI(&st->s, dom);
            st->i = 0;
        }
        d |= ((const uint8_t *) in)[j] ^ st->s[st->i++];
    }

    return d != 0;
}

