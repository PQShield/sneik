//  f512_param.h
//  2019-02-19  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (C) 2019, PQShield Ltd. Please see LICENSE.

//  This file provides parametrizations for the SNEIK family.

#ifndef _F512_PARAM_H_
#define _F512_PARAM_H_

#include <stdint.h>
#include "api.h"

// Compression function prototype
void sneik_f512(void *state, uint8_t dom, uint8_t rounds);

// Parameters (sizes are in bytes)
#define BLNK_BLOCK 64
#define BLNK_PI(x, dom) sneik_f512(x, dom, SNEIK_ROUNDS)
#undef SNEIK_ROUNDS

// == SNEIKEN AEADs ==

#ifdef CRYPTO_KEYBYTES

#define BLNK_RATE (BLNK_BLOCK - CRYPTO_KEYBYTES)

//  SNEIKEN128
#if (CRYPTO_KEYBYTES == 16 && CRYPTO_NPUBBYTES == 16)
#define SNEIK_ROUNDS 6
#endif

//  SNEIKEN256
#if (CRYPTO_KEYBYTES == 32 && CRYPTO_NPUBBYTES == 16)
#define SNEIK_ROUNDS 8
#endif

//  SNEIQEN128
#if (CRYPTO_KEYBYTES == 16 && CRYPTO_NPUBBYTES == 12)
#define SNEIK_ROUNDS 4
#endif

#endif

//  == SNEIKHA Hashes ==

#ifdef CRYPTO_BYTES

#define BLNK_RATE (BLNK_BLOCK - CRYPTO_BYTES)

//  SNEIKHA256
#if (CRYPTO_BYTES == 32)
#define SNEIK_ROUNDS 8
#endif

//  SNEIKHA384
#if (CRYPTO_BYTES == 48)
#define SNEIK_ROUNDS 8
#endif

//  SNEIGEN128 (it's a XOF so CRYPTO_BYTES is really just a marker)
#if (CRYPTO_BYTES == 16)
#define SNEIK_ROUNDS 4
#endif

//  A fall-through ?

#ifndef SNEIK_ROUNDS
#error "SNEIK: Invalid parameters in api.h"
#endif

#endif

#endif

