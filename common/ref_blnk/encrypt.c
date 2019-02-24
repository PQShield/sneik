//  encrypt.c
//  2019-02-23  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (C) 2019, PQShield Ltd. Please see LICENSE.

//  Refenrece AEAD using the shared BLNK calls.

#include "api.h"
#include "crypto_aead.h"
#include "blnk.h"

// Encryption

int crypto_aead_encrypt(
    unsigned char *c, unsigned long long *clen,         // Ciphertext out
    const unsigned char *m, unsigned long long mlen,    // Plaintext in
    const unsigned char *ad, unsigned long long adlen,  // AAD in
    const unsigned char *nsec,                          // Secret Nonce in
    const unsigned char *npub,                          // Public Nonce in
    const unsigned char *k)                             // Secret Key in
{
    const uint8_t id[6] = { 'a', 'e',
        BLNK_RATE, CRYPTO_KEYBYTES, CRYPTO_NPUBBYTES, CRYPTO_ABYTES };
    blnk_t  cb;                         //  Local state

    (void)(nsec);                       //  (Supress unused parameter warning)

    blnk_clr(&cb);                      //  Clear state

    //  Key block: id | k | iv
    blnk_put(&cb, BLNK_KEYF, id, sizeof(id));
    blnk_put(&cb, BLNK_KEYF, k, CRYPTO_KEYBYTES);
    blnk_put(&cb, BLNK_KEYF, npub, CRYPTO_NPUBBYTES);
    blnk_fin(&cb, BLNK_KEYF);

    //  Associated Data (full state)
    blnk_put(&cb, BLNK_ADF, ad, (size_t) adlen);
    blnk_fin(&cb, BLNK_ADF);

    // Encrypt Message (this version doesn't handle overlap)
    blnk_enc(&cb, BLNK_PTCT, c, m, (size_t) mlen);
    blnk_fin(&cb, BLNK_PTCT);

    //  Get MAC
    blnk_get(&cb, BLNK_HASH, c + mlen, CRYPTO_ABYTES);

    //  blnk_fin(&cb, BLNK_HASH);       //  Required for MAC-and-Continue
    blnk_clr(&cb);                      //  Clear sensitive data

    *clen = mlen + CRYPTO_ABYTES;       //  store length

    return 0;                           //  Success.
}


// Decryption

int crypto_aead_decrypt(
    unsigned char *m, unsigned long long *outputmlen,   // Plaintext out
    unsigned char *nsec,                                // Secret Nonce out
    const unsigned char *c, unsigned long long clen,    // Ciphertext in
    const unsigned char *ad, unsigned long long adlen,  // AAD in
    const unsigned char *npub,                          // Public Nonce in
    const unsigned char *k)                             // Secret Key in
{
    const uint8_t id[6] = { 'a', 'e',
        BLNK_RATE, CRYPTO_KEYBYTES, CRYPTO_NPUBBYTES, CRYPTO_ABYTES };
    blnk_t  cb;                         //  Local state

    (void)(nsec);                       //  (Supress unused parameter warning)

    if (clen < CRYPTO_ABYTES)           //  Invalid length
        return -1;
    clen -= CRYPTO_ABYTES;              //  clen = mlen now
    *outputmlen = clen;

    blnk_clr(&cb);                      //  Clear state

    //  Key block: id | k | iv
    blnk_put(&cb, BLNK_KEYF, id, sizeof(id));
    blnk_put(&cb, BLNK_KEYF, k, CRYPTO_KEYBYTES);
    blnk_put(&cb, BLNK_KEYF, npub, CRYPTO_NPUBBYTES);
    blnk_fin(&cb, BLNK_KEYF);

    //  Associated Data (full state)
    blnk_put(&cb, BLNK_ADF, ad, (size_t) adlen);
    blnk_fin(&cb, BLNK_ADF);

    //  Decrypt Message (can't handle overlap)
    blnk_dec(&cb, BLNK_PTCT, m, c, (size_t) clen);
    blnk_fin(&cb, BLNK_PTCT);

    //  Compare MAC
    if (blnk_cmp(&cb, BLNK_HASH, c + clen, CRYPTO_ABYTES) != 0) {
        blnk_clr(&cb);                  //  Clear sensitive data
        return -1;                      //  Authentication failure
    }

    //  blnk_fin(&cb, BLNK_HASH);       //  Required for MAC-and-Continue
    blnk_clr(&cb);                      //  Clear sensitive data

    return 0;                           //  Success
}

