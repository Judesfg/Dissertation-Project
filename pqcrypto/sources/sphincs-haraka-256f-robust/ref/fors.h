#ifndef FORS_H
#define FORS_H

#include <stdint.h>

#include "hash_state.h"
#include "params.h"

/**
 * Signs a message m, deriving the secret key from sk_seed and the FTS address.
 * Assumes m contains at least FORS_HEIGHT * FORS_TREES bits.
 */
void fors_sign(
    unsigned char *sig, unsigned char *pk,
    const unsigned char *m,
    const unsigned char *sk_seed, const unsigned char *pub_seed,
    const uint32_t fors_addr[8], const hash_state *hash_state_seeded);

/**
 * Derives the FORS public key from a signature.
 * This can be used for verification by comparing to a known public key, or to
 * subsequently verify a signature on the derived public key. The latter is the
 * typical use-case when used as an FTS below an OTS in a hypertree.
 * Assumes m contains at least FORS_HEIGHT * FORS_TREES bits.
 */
void fors_pk_from_sig(
    unsigned char *pk,
    const unsigned char *sig, const unsigned char *m,
    const unsigned char *pub_seed, const uint32_t fors_addr[8],
    const hash_state *hash_state_seeded);

#endif
