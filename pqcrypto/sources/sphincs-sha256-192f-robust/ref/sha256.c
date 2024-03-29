/* Based on the public domain implementation in
 * crypto_hash/sha512/ref/ from http://bench.cr.yp.to/supercop.html
 * by D. J. Bernstein */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "sha2.h"
#include "sha256.h"
#include "utils.h"

/*
 * Compresses an address to a 22-byte sequence.
 * This reduces the number of required SHA256 compression calls, as the last
 * block of input is padded with at least 65 bits.
 */
void compress_address(unsigned char *out, const uint32_t addr[8]) {
    ull_to_bytes(out,      1, addr[0]); /* drop 3 bytes of the layer field */
    ull_to_bytes(out + 1,  4, addr[2]); /* drop the highest tree address word */
    ull_to_bytes(out + 5,  4, addr[3]);
    ull_to_bytes(out + 9,  1, addr[4]); /* drop 3 bytes of the type field */
    ull_to_bytes(out + 10, 4, addr[5]);
    ull_to_bytes(out + 14, 4, addr[6]);
    ull_to_bytes(out + 18, 4, addr[7]);
}

/**
 * Requires 'input_plus_four_bytes' to have 'inlen' + 4 bytes, so that the last
 * four bytes can be used for the counter. Typically 'input' is merely a seed.
 * Outputs outlen number of bytes
 */
void mgf1(
    unsigned char *out, unsigned long outlen,
    unsigned char *input_plus_four_bytes, unsigned long inlen) {
    unsigned char outbuf[SHA256_OUTPUT_BYTES];
    unsigned long i;

    /* While we can fit in at least another full block of SHA256 output.. */
    for (i = 0; (i + 1)*SHA256_OUTPUT_BYTES <= outlen; i++) {
        ull_to_bytes(input_plus_four_bytes + inlen, 4, i);
        sha256(out, input_plus_four_bytes, inlen + 4);
        out += SHA256_OUTPUT_BYTES;
    }
    /* Until we cannot anymore, and we fill the remainder. */
    if (outlen > i * SHA256_OUTPUT_BYTES) {
        ull_to_bytes(input_plus_four_bytes + inlen, 4, i);
        sha256(outbuf, input_plus_four_bytes, inlen + 4);
        memcpy(out, outbuf, outlen - i * SHA256_OUTPUT_BYTES);
    }
}


/**
 * Absorb the constant pub_seed using one round of the compression function
 * This initializes hash_state_seeded, which can then be reused in thash
 **/
void seed_state(sha256ctx *hash_state_seeded, const unsigned char *pub_seed) {
    uint8_t block[SHA256_BLOCK_BYTES];
    size_t i;

    for (i = 0; i < N; ++i) {
        block[i] = pub_seed[i];
    }
    for (i = N; i < SHA256_BLOCK_BYTES; ++i) {
        block[i] = 0;
    }

    sha256_inc_init(hash_state_seeded);
    sha256_inc_blocks(hash_state_seeded, block, 1);
}
