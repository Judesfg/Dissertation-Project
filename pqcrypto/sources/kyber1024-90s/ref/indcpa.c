#include "indcpa.h"
#include "ntt.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "randombytes.h"
#include "symmetric.h"

#include <stdint.h>

/*************************************************
* Name:        pack_pk
*
* Description: Serialize the public key as concatenation of the
*              serialized vector of polynomials pk
*              and the public seed used to generate the matrix A.
*
* Arguments:   uint8_t *r:          pointer to the output serialized public key
*              const poly *pk:            pointer to the input public-key polynomial
*              const uint8_t *seed: pointer to the input public seed
**************************************************/
static void pack_pk(uint8_t *r, polyvec *pk, const uint8_t *seed) {
    polyvec_tobytes(r, pk);
    for (size_t i = 0; i < KYBER_SYMBYTES; i++) {
        r[i + KYBER_POLYVECBYTES] = seed[i];
    }
}

/*************************************************
* Name:        unpack_pk
*
* Description: De-serialize public key from a byte array;
*              approximate inverse of pack_pk
*
* Arguments:   - polyvec *pk:                   pointer to output public-key vector of polynomials
*              - uint8_t *seed:           pointer to output seed to generate matrix A
*              - const uint8_t *packedpk: pointer to input serialized public key
**************************************************/
static void unpack_pk(polyvec *pk, uint8_t *seed, const uint8_t *packedpk) {
    polyvec_frombytes(pk, packedpk);
    for (size_t i = 0; i < KYBER_SYMBYTES; i++) {
        seed[i] = packedpk[i + KYBER_POLYVECBYTES];
    }
}

/*************************************************
* Name:        pack_sk
*
* Description: Serialize the secret key
*
* Arguments:   - uint8_t *r:  pointer to output serialized secret key
*              - const polyvec *sk: pointer to input vector of polynomials (secret key)
**************************************************/
static void pack_sk(uint8_t *r, polyvec *sk) {
    polyvec_tobytes(r, sk);
}

/*************************************************
* Name:        unpack_sk
*
* Description: De-serialize the secret key;
*              inverse of pack_sk
*
* Arguments:   - polyvec *sk:                   pointer to output vector of polynomials (secret key)
*              - const uint8_t *packedsk: pointer to input serialized secret key
**************************************************/
static void unpack_sk(polyvec *sk, const uint8_t *packedsk) {
    polyvec_frombytes(sk, packedsk);
}

/*************************************************
* Name:        pack_ciphertext
*
* Description: Serialize the ciphertext as concatenation of the
*              compressed and serialized vector of polynomials b
*              and the compressed and serialized polynomial v
*
* Arguments:   uint8_t *r:          pointer to the output serialized ciphertext
*              const poly *pk:            pointer to the input vector of polynomials b
*              const uint8_t *seed: pointer to the input polynomial v
**************************************************/
static void pack_ciphertext(uint8_t *r, polyvec *b, poly *v) {
    polyvec_compress(r, b);
    poly_compress(r + KYBER_POLYVECCOMPRESSEDBYTES, v);
}

/*************************************************
* Name:        unpack_ciphertext
*
* Description: De-serialize and decompress ciphertext from a byte array;
*              approximate inverse of pack_ciphertext
*
* Arguments:   - polyvec *b:             pointer to the output vector of polynomials b
*              - poly *v:                pointer to the output polynomial v
*              - const uint8_t *c: pointer to the input serialized ciphertext
**************************************************/
static void unpack_ciphertext(polyvec *b, poly *v, const uint8_t *c) {
    polyvec_decompress(b, c);
    poly_decompress(v, c + KYBER_POLYVECCOMPRESSEDBYTES);
}

/*************************************************
* Name:        rej_uniform
*
* Description: Run rejection sampling on uniform random bytes to generate
*              uniform random integers mod q
*
* Arguments:   - int16_t *r:               pointer to output buffer
*              - size_t len:               requested number of 16-bit integers (uniform mod q)
*              - const uint8_t *buf:       pointer to input buffer (assumed to be uniform random bytes)
*              - size_t buflen:            length of input buffer in bytes
*
* Returns number of sampled 16-bit integers (at most len)
**************************************************/
static size_t rej_uniform(int16_t *r, size_t len, const uint8_t *buf, size_t buflen) {
    size_t ctr, pos;
    uint16_t val;

    ctr = pos = 0;
    while (ctr < len && pos + 2 <= buflen) {
        val = (uint16_t)(buf[pos] | ((uint16_t)buf[pos + 1] << 8));
        pos += 2;

        if (val < 19 * KYBER_Q) {
            val -= (uint16_t)((val >> 12) * KYBER_Q); // Barrett reduction
            r[ctr++] = (int16_t)val;
        }
    }

    return ctr;
}

#define gen_a(A,B)  gen_matrix(A,B,0)
#define gen_at(A,B) gen_matrix(A,B,1)

/*************************************************
* Name:        gen_matrix
*
* Description: Deterministically generate matrix A (or the transpose of A)
*              from a seed. Entries of the matrix are polynomials that look
*              uniformly random. Performs rejection sampling on output of
*              a XOF
*
* Arguments:   - polyvec *a:                pointer to ouptput matrix A
*              - const uint8_t *seed: pointer to input seed
*              - int transposed:            boolean deciding whether A or A^T is generated
**************************************************/
#define MAXNBLOCKS ((530+XOF_BLOCKBYTES)/XOF_BLOCKBYTES) /* 530 is expected number of required bytes */
static void gen_matrix(polyvec *a, const uint8_t *seed, int transposed) {
    size_t ctr;
    uint8_t i, j;
    uint8_t buf[XOF_BLOCKBYTES * MAXNBLOCKS + 1];
    xof_state state;

    for (i = 0; i < KYBER_K; i++) {
        for (j = 0; j < KYBER_K; j++) {
            if (transposed) {
                xof_absorb(&state, seed, i, j);
            } else {
                xof_absorb(&state, seed, j, i);
            }

            xof_squeezeblocks(buf, MAXNBLOCKS, &state);
            ctr = rej_uniform(a[i].vec[j].coeffs, KYBER_N, buf, MAXNBLOCKS * XOF_BLOCKBYTES);

            while (ctr < KYBER_N) {
                xof_squeezeblocks(buf, 1, &state);
                ctr += rej_uniform(a[i].vec[j].coeffs + ctr, KYBER_N - ctr, buf, XOF_BLOCKBYTES);
            }
            xof_ctx_release(&state);
        }
    }
}

/*************************************************
* Name:        indcpa_keypair
*
* Description: Generates public and private key for the CPA-secure
*              public-key encryption scheme underlying Kyber
*
* Arguments:   - uint8_t *pk: pointer to output public key (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
**************************************************/
void indcpa_keypair(uint8_t *pk, uint8_t *sk) {
    polyvec a[KYBER_K], e, pkpv, skpv;
    uint8_t buf[2 * KYBER_SYMBYTES];
    uint8_t *publicseed = buf;
    uint8_t *noiseseed = buf + KYBER_SYMBYTES;
    uint8_t nonce = 0;

    randombytes(buf, KYBER_SYMBYTES);
    hash_g(buf, buf, KYBER_SYMBYTES);

    gen_a(a, publicseed);

    for (size_t i = 0; i < KYBER_K; i++) {
        poly_getnoise(skpv.vec + i, noiseseed, nonce++);
    }
    for (size_t i = 0; i < KYBER_K; i++) {
        poly_getnoise(e.vec + i, noiseseed, nonce++);
    }

    polyvec_ntt(&skpv);
    polyvec_ntt(&e);

    // matrix-vector multiplication
    for (size_t i = 0; i < KYBER_K; i++) {
        polyvec_pointwise_acc(&pkpv.vec[i], &a[i], &skpv);
        poly_frommont(&pkpv.vec[i]);
    }

    polyvec_add(&pkpv, &pkpv, &e);
    polyvec_reduce(&pkpv);

    pack_sk(sk, &skpv);
    pack_pk(pk, &pkpv, publicseed);
}

/*************************************************
* Name:        indcpa_enc
*
* Description: Encryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *c:          pointer to output ciphertext (of length KYBER_INDCPA_BYTES bytes)
*              - const uint8_t *m:    pointer to input message (of length KYBER_INDCPA_MSGBYTES bytes)
*              - const uint8_t *pk:   pointer to input public key (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - const uint8_t *coin: pointer to input random coins used as seed (of length KYBER_SYMBYTES bytes)
*                                           to deterministically generate all randomness
**************************************************/
void indcpa_enc(uint8_t *c,
        const uint8_t *m,
        const uint8_t *pk,
        const uint8_t *coins) {
    polyvec sp, pkpv, ep, at[KYBER_K], bp;
    poly v, k, epp;
    uint8_t seed[KYBER_SYMBYTES];
    uint8_t nonce = 0;

    unpack_pk(&pkpv, seed, pk);
    poly_frommsg(&k, m);
    gen_at(at, seed);

    for (size_t i = 0; i < KYBER_K; i++) {
        poly_getnoise(sp.vec + i, coins, nonce++);
    }
    for (size_t i = 0; i < KYBER_K; i++) {
        poly_getnoise(ep.vec + i, coins, nonce++);
    }
    poly_getnoise(&epp, coins, nonce++);

    polyvec_ntt(&sp);

    // matrix-vector multiplication
    for (size_t i = 0; i < KYBER_K; i++) {
        polyvec_pointwise_acc(&bp.vec[i], &at[i], &sp);
    }

    polyvec_pointwise_acc(&v, &pkpv, &sp);

    polyvec_invntt(&bp);
    poly_invntt(&v);

    polyvec_add(&bp, &bp, &ep);
    poly_add(&v, &v, &epp);
    poly_add(&v, &v, &k);
    polyvec_reduce(&bp);
    poly_reduce(&v);

    pack_ciphertext(c, &bp, &v);
}

/*************************************************
* Name:        indcpa_dec
*
* Description: Decryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *m:        pointer to output decrypted message (of length KYBER_INDCPA_MSGBYTES)
*              - const uint8_t *c:  pointer to input ciphertext (of length KYBER_INDCPA_BYTES)
*              - const uint8_t *sk: pointer to input secret key (of length KYBER_INDCPA_SECRETKEYBYTES)
**************************************************/
void indcpa_dec(uint8_t *m,
        const uint8_t *c,
        const uint8_t *sk) {
    polyvec bp, skpv;
    poly v, mp;

    unpack_ciphertext(&bp, &v, c);
    unpack_sk(&skpv, sk);

    polyvec_ntt(&bp);
    polyvec_pointwise_acc(&mp, &skpv, &bp);
    poly_invntt(&mp);

    poly_sub(&mp, &v, &mp);
    poly_reduce(&mp);

    poly_tomsg(m, &mp);
}
