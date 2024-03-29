#include <stdint.h>
#include <string.h>

#include "fips202.h"
#include "packing.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "randombytes.h"
#include "sign.h"
#include "symmetric.h"

/*************************************************
* Name:        expand_mat
*
* Description: Implementation of ExpandA. Generates matrix A with uniformly
*              random coefficients a_{i,j} by performing rejection
*              sampling on the output stream of SHAKE128(rho|i|j).
*
* Arguments:   - polyvecl mat[K]: output matrix
*              - const uint8_t rho[]: byte array containing seed rho
**************************************************/
void expand_mat(polyvecl mat[K], const uint8_t rho[SEEDBYTES]) {
    for (size_t i = 0; i < K; ++i) {
        for (size_t j = 0; j < L; ++j) {
            poly_uniform(&mat[i].vec[j], rho, (uint16_t)((i << 8) + j));
        }
    }
}

/*************************************************
* Name:        challenge
*
* Description: Implementation of H. Samples polynomial with 60 nonzero
*              coefficients in {-1,1} using the output stream of
*              SHAKE256(mu|w1).
*
* Arguments:   - poly *c: pointer to output polynomial
*              - const uint8_t mu[]: byte array containing mu
*              - const polyveck *w1: pointer to vector w1
**************************************************/
void challenge(poly *c,
                                        const uint8_t mu[CRHBYTES],
                                        const polyveck *w1) {
    uint64_t signs;
    uint8_t inbuf[CRHBYTES + K * POLW1_SIZE_PACKED];
    uint8_t outbuf[SHAKE256_RATE];
    shake256ctx state;
    uint8_t b;
    size_t pos;

    for (size_t i = 0; i < CRHBYTES; ++i) {
        inbuf[i] = mu[i];
    }
    for (size_t i = 0; i < K; ++i) {
        polyw1_pack(inbuf + CRHBYTES + i * POLW1_SIZE_PACKED, &w1->vec[i]);
    }

    shake256_absorb(&state, inbuf, sizeof(inbuf));
    shake256_squeezeblocks(outbuf, 1, &state);

    signs = 0;
    for (size_t i = 0; i < 8; ++i) {
        signs |= (uint64_t)outbuf[i] << 8 * i;
    }

    pos = 8;

    for (size_t i = 0; i < N; ++i) {
        c->coeffs[i] = 0;
    }

    for (size_t i = 196; i < 256; ++i) {
        do {
            if (pos >= SHAKE256_RATE) {
                shake256_squeezeblocks(outbuf, 1, &state);
                pos = 0;
            }

            b = outbuf[pos++];
        } while (b > i);

        c->coeffs[i] = c->coeffs[b];
        c->coeffs[b] = 1;
        c->coeffs[b] ^= -((int32_t)signs & 1) & (1 ^ (Q - 1));
        signs >>= 1;
    }
    shake256_ctx_release(&state);
}

/*************************************************
* Name:        crypto_sign_keypair
*
* Description: Generates public and private key.
*
* Arguments:   - uint8_t *pk: pointer to output public key (allocated
*                                   array of CRYPTO_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key (allocated
*                                   array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_sign_keypair(uint8_t *pk, uint8_t *sk) {
    uint8_t seedbuf[3 * SEEDBYTES];
    uint8_t tr[CRHBYTES];
    const uint8_t *rho, *rhoprime, *key;
    uint16_t nonce = 0;
    polyvecl mat[K];
    polyvecl s1, s1hat;
    polyveck s2, t, t1, t0;

    /* Expand 32 bytes of randomness into rho, rhoprime and key */
    randombytes(seedbuf, 3 * SEEDBYTES);
    rho = seedbuf;
    rhoprime = seedbuf + SEEDBYTES;
    key = seedbuf + 2 * SEEDBYTES;

    /* Expand matrix */
    expand_mat(mat, rho);

    /* Sample short vectors s1 and s2 */
    for (size_t i = 0; i < L; ++i) {
        poly_uniform_eta(&s1.vec[i], rhoprime, nonce++);
    }
    for (size_t i = 0; i < K; ++i) {
        poly_uniform_eta(&s2.vec[i], rhoprime, nonce++);
    }

    /* Matrix-vector multiplication */
    s1hat = s1;
    polyvecl_ntt(&s1hat);
    for (size_t i = 0; i < K; ++i) {
        polyvecl_pointwise_acc_invmontgomery(&t.vec[i], &mat[i], &s1hat);
        poly_reduce(&t.vec[i]);
        poly_invntt_montgomery(&t.vec[i]);
    }

    /* Add error vector s2 */
    polyveck_add(&t, &t, &s2);

    /* Extract t1 and write public key */
    polyveck_freeze(&t);
    polyveck_power2round(&t1, &t0, &t);
    pack_pk(pk, rho, &t1);

    /* Compute CRH(rho, t1) and write secret key */
    crh(tr, pk, CRYPTO_PUBLICKEYBYTES);
    pack_sk(sk, rho, key, tr, &s1, &s2, &t0);

    return 0;
}

/*************************************************
* Name:        crypto_sign_signature
*
* Description: Compute signed message.
*
* Arguments:   - uint8_t *sig:  pointer to output signature (CRYPTO_BYTES
*                               of len)
*              - size_t *smlen: pointer to output length of signed message
*                               (should be CRYPTO_BYTES)
*              - uint8_t *m:    pointer to message to be signed
*              - size_t mlen:   length of message
*              - uint8_t *sk:   pointer to bit-packed secret key
*
* Returns 0 (success)
**************************************************/
int crypto_sign_signature(
    uint8_t *sig, size_t *siglen,
    const uint8_t *msg, size_t mlen,
    const uint8_t *sk) {
    uint8_t seedbuf[2 * SEEDBYTES + 3 * CRHBYTES];
    uint8_t *rho, *tr, *key, *mu, *rhoprime;
    uint32_t n;
    uint16_t nonce = 0;
    poly c, chat;
    polyvecl mat[K], s1, y, yhat, z;
    polyveck t0, s2, w, w1, w0;
    polyveck h, cs2, ct0;

    rho = seedbuf;
    tr = rho + SEEDBYTES;
    key = tr + CRHBYTES;
    mu = key + SEEDBYTES;
    rhoprime = mu + CRHBYTES;
    unpack_sk(rho, key, tr, &s1, &s2, &t0, sk);

    // use incremental hash API instead of copying around buffers
    /* Compute CRH(tr, msg) */
    shake256incctx state;
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, tr, CRHBYTES);
    shake256_inc_absorb(&state, msg, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state);
    shake256_inc_ctx_release(&state);

    crh(rhoprime, key, SEEDBYTES + CRHBYTES);

    /* Expand matrix and transform vectors */
    expand_mat(mat, rho);
    polyvecl_ntt(&s1);
    polyveck_ntt(&s2);
    polyveck_ntt(&t0);

rej:
    /* Sample intermediate vector y */
    for (size_t i = 0; i < L; ++i) {
        poly_uniform_gamma1m1(&y.vec[i], rhoprime, nonce++);
    }

    /* Matrix-vector multiplication */
    yhat = y;
    polyvecl_ntt(&yhat);
    for (size_t i = 0; i < K; ++i) {
        polyvecl_pointwise_acc_invmontgomery(&w.vec[i], &mat[i], &yhat);
        poly_reduce(&w.vec[i]);
        poly_invntt_montgomery(&w.vec[i]);
    }

    /* Decompose w and call the random oracle */
    polyveck_csubq(&w);
    polyveck_decompose(&w1, &w0, &w);
    challenge(&c, mu, &w1);
    chat = c;
    poly_ntt(&chat);

    /* Check that subtracting cs2 does not change high bits of w and low bits
     * do not reveal secret information */
    for (size_t i = 0; i < K; ++i) {
        poly_pointwise_invmontgomery(&cs2.vec[i], &chat, &s2.vec[i]);
        poly_invntt_montgomery(&cs2.vec[i]);
    }
    polyveck_sub(&w0, &w0, &cs2);
    polyveck_freeze(&w0);
    if (polyveck_chknorm(&w0, GAMMA2 - BETA)) {
        goto rej;
    }

    /* Compute z, reject if it reveals secret */
    for (size_t i = 0; i < L; ++i) {
        poly_pointwise_invmontgomery(&z.vec[i], &chat, &s1.vec[i]);
        poly_invntt_montgomery(&z.vec[i]);
    }
    polyvecl_add(&z, &z, &y);
    polyvecl_freeze(&z);
    if (polyvecl_chknorm(&z, GAMMA1 - BETA)) {
        goto rej;
    }

    /* Compute hints for w1 */
    for (size_t i = 0; i < K; ++i) {
        poly_pointwise_invmontgomery(&ct0.vec[i], &chat, &t0.vec[i]);
        poly_invntt_montgomery(&ct0.vec[i]);
    }

    polyveck_csubq(&ct0);
    if (polyveck_chknorm(&ct0, GAMMA2)) {
        goto rej;
    }

    polyveck_add(&w0, &w0, &ct0);
    polyveck_csubq(&w0);
    n = polyveck_make_hint(&h, &w0, &w1);
    if (n > OMEGA) {
        goto rej;
    }

    /* Write signature */
    pack_sig(sig, &z, &h, &c);
    *siglen = CRYPTO_BYTES;
    return 0;
}

/*************************************************
* Name:        crypto_sign
*
* Description: Compute signed message.
*
* Arguments:   - uint8_t *sm: pointer to output signed message (allocated
*                             array with CRYPTO_BYTES + mlen bytes),
*                             can be equal to m
*              - size_t *smlen: pointer to output length of signed
*                                           message
*              - const uint8_t *m: pointer to message to be signed
*              - size_t mlen: length of message
*              - const uint8_t *sk: pointer to bit-packed secret key
*
* Returns 0 (success)
**************************************************/
int crypto_sign(
    uint8_t *sm, size_t *smlen,
    const uint8_t *m, size_t mlen,
    const uint8_t *sk) {
    int rc;
    memmove(sm + CRYPTO_BYTES, m, mlen);
    rc = crypto_sign_signature(sm, smlen, m, mlen, sk);
    *smlen += mlen;
    return rc;
}


/*************************************************
* Name:        crypto_sign_verify
*
* Description: Verify signed message.
*
* Arguments:   - uint8_t *sig:  signature
*              - size_t siglen: length of signature (CRYPTO_BYTES)
*              - uint8_t *m:    pointer to message
*              - size_t *mlen:  pointer to output length of message
*              - uint8_t *pk:   pointer to bit-packed public key
*
* Returns 0 if signed message could be verified correctly and -1 otherwise
**************************************************/
int crypto_sign_verify(
    const uint8_t *sig, size_t siglen,
    const uint8_t *m, size_t mlen, const uint8_t *pk) {
    uint8_t rho[SEEDBYTES];
    uint8_t mu[CRHBYTES];
    poly c, chat, cp;
    polyvecl mat[K], z;
    polyveck t1, w1, h, tmp1, tmp2;

    if (siglen < CRYPTO_BYTES) {
        return -1;
    }

    unpack_pk(rho, &t1, pk);
    if (unpack_sig(&z, &h, &c, sig)) {
        return -1;
    }
    if (polyvecl_chknorm(&z, GAMMA1 - BETA)) {
        return -1;
    }

    /* Compute CRH(CRH(rho, t1), msg) */
    crh(mu, pk, CRYPTO_PUBLICKEYBYTES);

    shake256incctx state;
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, CRHBYTES);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state);
    shake256_inc_ctx_release(&state);

    /* Matrix-vector multiplication; compute Az - c2^dt1 */
    expand_mat(mat, rho);

    polyvecl_ntt(&z);
    for (size_t i = 0; i < K ; ++i) {
        polyvecl_pointwise_acc_invmontgomery(&tmp1.vec[i], &mat[i], &z);
    }

    chat = c;
    poly_ntt(&chat);
    polyveck_shiftl(&t1);
    polyveck_ntt(&t1);
    for (size_t i = 0; i < K; ++i) {
        poly_pointwise_invmontgomery(&tmp2.vec[i], &chat, &t1.vec[i]);
    }

    polyveck_sub(&tmp1, &tmp1, &tmp2);
    polyveck_reduce(&tmp1);
    polyveck_invntt_montgomery(&tmp1);

    /* Reconstruct w1 */
    polyveck_csubq(&tmp1);
    polyveck_use_hint(&w1, &tmp1, &h);

    /* Call random oracle and verify challenge */
    challenge(&cp, mu, &w1);
    for (size_t i = 0; i < N; ++i) {
        if (c.coeffs[i] != cp.coeffs[i]) {
            return -1;
        }
    }

    // All good
    return 0;
}

/*************************************************
* Name:        crypto_sign_open
*
* Description: Verify signed message.
*
* Arguments:   - uint8_t *m: pointer to output message (allocated
*                                  array with smlen bytes), can be equal to sm
*              - size_t *mlen: pointer to output length of message
*              - const uint8_t *sm: pointer to signed message
*              - size_t smlen: length of signed message
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signed message could be verified correctly and -1 otherwise
**************************************************/
int crypto_sign_open(
    uint8_t *m, size_t *mlen,
    const uint8_t *sm, size_t smlen,
    const uint8_t *pk) {
    if (smlen < CRYPTO_BYTES) {
        goto badsig;
    }
    *mlen = smlen - CRYPTO_BYTES;

    if (crypto_sign_verify(sm, CRYPTO_BYTES,
            sm + CRYPTO_BYTES, *mlen, pk)) {
        goto badsig;
    } else {
        /* All good, copy msg, return 0 */
        for (size_t i = 0; i < *mlen; ++i) {
            m[i] = sm[CRYPTO_BYTES + i];
        }
        return 0;
    }

    /* Signature verification failed */
badsig:
    *mlen = (size_t) -1;
    for (size_t i = 0; i < smlen; ++i) {
        m[i] = 0;
    }

    return -1;
}

