//  hash.c
//  2019-02-20  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (C) 2019, PQShield Ltd. Please see LICENSE.

//  Reference hash using the BLNK calls

#include "api.h"
#include "crypto_hash.h"
#include "blnk.h"

//  Single-call NIST interface

int crypto_hash(
    unsigned char *out,
    const unsigned char *in,
    unsigned long long inlen)
{
    blnk_t  cb;                         //  Local state

    blnk_clr(&cb);                      //  Clear state

    //  Process input
    blnk_put(&cb, BLNK_AD, in, (size_t) inlen);
    blnk_fin(&cb, BLNK_AD);

    //  Get the hash
    blnk_get(&cb, BLNK_HASH, out, CRYPTO_BYTES);

    //  blnk_fin(&cb, BLNK_HASH);       //  For intermediate hashes
    blnk_clr(&cb);                      //  Clear out sensitive data

    return 0;                           //  Success
}

