#include <stdint.h>
#include <string.h>

#include "address.h"
#include "hash_state.h"
#include "params.h"
#include "thash.h"

#include "haraka.h"

/**
 * Takes an array of inblocks concatenated arrays of N bytes.
 */
static void thash(
    unsigned char *out, unsigned char *buf,
    const unsigned char *in, unsigned int inblocks,
    const unsigned char *pub_seed, uint32_t addr[8],
    const hash_state *hash_state_seeded) {

    unsigned char *bitmask = buf + ADDR_BYTES;
    unsigned char outbuf[32];
    unsigned char buf_tmp[64];
    unsigned int i;

    (void)pub_seed; /* Suppress an 'unused parameter' warning. */

    if (inblocks == 1) {
        /* F function */
        /* Since N may be smaller than 32, we need a temporary buffer. */
        memset(buf_tmp, 0, 64);
        addr_to_bytes(buf_tmp, addr);

        haraka256(outbuf, buf_tmp, hash_state_seeded);
        for (i = 0; i < inblocks * N; i++) {
            buf_tmp[ADDR_BYTES + i] = in[i] ^ outbuf[i];
        }
        haraka512(outbuf, buf_tmp, hash_state_seeded);
        memcpy(out, outbuf, N);
    } else {
        /* All other tweakable hashes*/
        addr_to_bytes(buf, addr);
        haraka_S(
            bitmask, inblocks * N, buf, ADDR_BYTES, hash_state_seeded);

        for (i = 0; i < inblocks * N; i++) {
            buf[ADDR_BYTES + i] = in[i] ^ bitmask[i];
        }

        haraka_S(
            out, N, buf, ADDR_BYTES + inblocks * N, hash_state_seeded);
    }
}

/* The wrappers below ensure that we use fixed-size buffers on the stack */

void thash_1(
    unsigned char *out, const unsigned char *in,
    const unsigned char *pub_seed, uint32_t addr[8],
    const hash_state *hash_state_seeded) {

    unsigned char buf[ADDR_BYTES + 1 * N];
    thash(
        out, buf, in, 1, pub_seed, addr, hash_state_seeded);
}

void thash_2(
    unsigned char *out, const unsigned char *in,
    const unsigned char *pub_seed, uint32_t addr[8],
    const hash_state *hash_state_seeded) {

    unsigned char buf[ADDR_BYTES + 2 * N];
    thash(
        out, buf, in, 2, pub_seed, addr, hash_state_seeded);
}

void thash_WOTS_LEN(
    unsigned char *out, const unsigned char *in,
    const unsigned char *pub_seed, uint32_t addr[8],
    const hash_state *hash_state_seeded) {

    unsigned char buf[ADDR_BYTES + WOTS_LEN * N];
    thash(
        out, buf, in, WOTS_LEN, pub_seed, addr, hash_state_seeded);
}

void thash_FORS_TREES(
    unsigned char *out, const unsigned char *in,
    const unsigned char *pub_seed, uint32_t addr[8],
    const hash_state *hash_state_seeded) {

    unsigned char buf[ADDR_BYTES + FORS_TREES * N];
    thash(
        out, buf, in, FORS_TREES, pub_seed, addr, hash_state_seeded);
}
