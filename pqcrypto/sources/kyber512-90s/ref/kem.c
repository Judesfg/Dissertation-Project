#include "api.h"
#include "indcpa.h"
#include "params.h"
#include "randombytes.h"
#include "symmetric.h"
#include "verify.h"

#include <stdlib.h>
/*************************************************
* Name:        crypto_kem_keypair
*
* Description: Generates public and private key
*              for CCA-secure Kyber key encapsulation mechanism
*
* Arguments:   - uint8_t *pk: pointer to output public key (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key (an already allocated array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_keypair(uint8_t *pk, uint8_t *sk) {
    size_t i;
    indcpa_keypair(pk, sk);
    for (i = 0; i < KYBER_INDCPA_PUBLICKEYBYTES; i++) {
        sk[i + KYBER_INDCPA_SECRETKEYBYTES] = pk[i];
    }
    hash_h(sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
    randombytes(sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, KYBER_SYMBYTES);    /* Value z for pseudo-random output on reject */
    return 0;
}

/*************************************************
* Name:        crypto_kem_enc
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - uint8_t *ct:       pointer to output cipher text (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes)
*              - uint8_t *ss:       pointer to output shared secret (an already allocated array of CRYPTO_BYTES bytes)
*              - const uint8_t *pk: pointer to input public key (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    uint8_t  kr[2 * KYBER_SYMBYTES];                                   /* Will contain key, coins */
    uint8_t buf[2 * KYBER_SYMBYTES];

    randombytes(buf, KYBER_SYMBYTES);
    hash_h(buf, buf, KYBER_SYMBYTES);                                        /* Don't release system RNG output */

    hash_h(buf + KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);                  /* Multitarget countermeasure for coins + contributory KEM */
    hash_g(kr, buf, 2 * KYBER_SYMBYTES);

    indcpa_enc(ct, buf, pk, kr + KYBER_SYMBYTES);                            /* coins are in kr+KYBER_SYMBYTES */

    hash_h(kr + KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);                  /* overwrite coins in kr with H(c) */
    kdf(ss, kr, 2 * KYBER_SYMBYTES);                                         /* hash concatenation of pre-k and H(c) to k */
    return 0;
}

/*************************************************
* Name:        crypto_kem_dec
*
* Description: Generates shared secret for given
*              cipher text and private key
*
* Arguments:   - uint8_t *ss:       pointer to output shared secret (an already allocated array of CRYPTO_BYTES bytes)
*              - const uint8_t *ct: pointer to input cipher text (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes)
*              - const uint8_t *sk: pointer to input private key (an already allocated array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0.
*
* On failure, ss will contain a pseudo-random value.
**************************************************/
int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    size_t i;
    uint8_t fail;
    uint8_t cmp[KYBER_CIPHERTEXTBYTES];
    uint8_t buf[2 * KYBER_SYMBYTES];
    uint8_t kr[2 * KYBER_SYMBYTES];                                    /* Will contain key, coins */
    const uint8_t *pk = sk + KYBER_INDCPA_SECRETKEYBYTES;

    indcpa_dec(buf, ct, sk);

    for (i = 0; i < KYBER_SYMBYTES; i++) {                                   /* Multitarget countermeasure for coins + contributory KEM */
        buf[KYBER_SYMBYTES + i] = sk[KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES + i];    /* Save hash by storing H(pk) in sk */
    }
    hash_g(kr, buf, 2 * KYBER_SYMBYTES);

    indcpa_enc(cmp, buf, pk, kr + KYBER_SYMBYTES);                           /* coins are in kr+KYBER_SYMBYTES */

    fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

    hash_h(kr + KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);                  /* overwrite coins in kr with H(c)  */

    cmov(kr, sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, KYBER_SYMBYTES, fail); /* Overwrite pre-k with z on re-encryption failure */

    kdf(ss, kr, 2 * KYBER_SYMBYTES);                                         /* hash concatenation of pre-k and H(c) to k */
    return 0;
}
