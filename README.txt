README.txt
2019-02-24  Markku-Juhani O. Saarinen <mjos@pqshield.com>
Copyright (C) 2019, PQShield Ltd. Please see LICENSE.

This is the source code package for the SNEIKEN family of lightweight
cryptographic algorithms.

Root level files:

    sneik_spec.pdf      Algorithm specification and supporting documentation.
    LICENSE             A non-commercial / research / evaluation license.
    README.txt          This file.
    testkat.sh          Verify "ref" and "opt" implementations against kat.
    genkat.sh           Generate KAT files (you don't need to do this).

Source code and test vectors for SNEIKEN AEADs:

    crypto_aead/sneiken128/ ref opt arm avr LWC_AEAD_KAT_128_128.txt
    crypto_aead/sneiken256/ ref opt arm avr LWC_AEAD_KAT_256_128.txt
    crypto_aead/sneiqen128/ ref opt arm avr LWC_AEAD_KAT_128_96.txt

Source code and test vectors for SNEIKHA hash functions:

    crypto_hash/sneikha256/ ref opt arm avr LWC_HASH_KAT_256.txt
    crypto_hash/sneikha384/ ref opt arm avr LWC_HASH_KAT_384.txt
    crypto_hash/sneigen128/ ref opt arm avr LWC_HASH_KAT_128.txt

Each directory has a "ref" portable reference implementation, somewhat smaller
"opt" optimized version (which assumes that the platform is little-endian) and
versions utilizing assembly-optimized permutations: "avr" for 8-bit Atmel AVR,
and "arm" for 32-bit ARM Cortex M3/M4 platforms.

Each directory contains test vectors generated with NIST's standard
`genkat_aead.c` and `genkat_hash.c` programs. Most of the source code is
usually symlinked from the common directory:

    common/sneik_f512   Implementations of the sneik_f512() permutation.
    common/ref_blnk     Reference implementation, using BLNK code.
    common/opt          Smaller implementation for single-call API.
    common/nist         NIST's headers and KAT generation code.
    common/test         Some test code.


