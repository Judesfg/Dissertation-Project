#ifndef SYMMETRIC_H
#define SYMMETRIC_H

#include "params.h"


#include "fips202.h"

#include <stdint.h>

typedef shake128ctx keccak_state;

void kyber_shake128_absorb(keccak_state *s, const uint8_t *input, uint8_t x, uint8_t y);
void kyber_shake128_squeezeblocks(uint8_t *output, size_t nblocks, keccak_state *s);
void shake256_prf(uint8_t *output, size_t outlen, const uint8_t *key, uint8_t nonce);

#define hash_h(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
#define xof_absorb(STATE, IN, X, Y) kyber_shake128_absorb(STATE, IN, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) kyber_shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define xof_ctx_release(STATE) shake128_ctx_release(STATE)
#define prf(OUT, OUTBYTES, KEY, NONCE) shake256_prf(OUT, OUTBYTES, KEY, NONCE)
#define kdf(OUT, IN, INBYTES) shake256(OUT, KYBER_SSBYTES, IN, INBYTES)

#define XOF_BLOCKBYTES 168

typedef keccak_state xof_state;


#endif /* SYMMETRIC_H */
