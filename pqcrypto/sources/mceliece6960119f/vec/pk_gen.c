/*
  This file is for public-key generation
*/

#include "pk_gen.h"

#include "benes.h"
#include "controlbits.h"
#include "fft.h"
#include "params.h"
#include "transpose.h"
#include "util.h"

#include <stdint.h>

#define min(a, b) (((a) < (b)) ? (a) : (b))

static void de_bitslicing(uint64_t *out, vec in[][GFBITS]) {
    int i, j, r;

    for (i = 0; i < (1 << GFBITS); i++) {
        out[i] = 0 ;
    }

    for (i = 0; i < 128; i++) {
        for (j = GFBITS - 1; j >= 0; j--) {
            for (r = 0; r < 64; r++) {
                out[i * 64 + r] <<= 1;
                out[i * 64 + r] |= (in[i][j] >> r) & 1;
            }
        }
    }
}

static void to_bitslicing_2x(vec out0[][GFBITS], vec out1[][GFBITS], const uint64_t *in) {
    int i, j, r;

    for (i = 0; i < 128; i++) {
        for (j = GFBITS - 1; j >= 0; j--) {
            for (r = 63; r >= 0; r--) {
                out1[i][j] <<= 1;
                out1[i][j] |= (in[i * 64 + r] >> (j + GFBITS)) & 1;
            }
        }

        for (j = GFBITS - 1; j >= 0; j--) {
            for (r = 63; r >= 0; r--) {
                out0[i][GFBITS - 1 - j] <<= 1;
                out0[i][GFBITS - 1 - j] |= (in[i * 64 + r] >> j) & 1;
            }
        }
    }
}

/* return number of trailing zeros of the non-zero input in */
static inline int ctz(uint64_t in) {
    int i, b, m = 0, r = 0;

    for (i = 0; i < 64; i++) {
        b = (int)(in >> i) & 1;
        m |= b;
        r += (m ^ 1) & (b ^ 1);
    }

    return r;
}

static inline uint64_t same_mask(uint16_t x, uint16_t y) {
    uint64_t mask;

    mask = x ^ y;
    mask -= 1;
    mask >>= 63;
    mask = -mask;

    return mask;
}

static int mov_columns(uint64_t mat[][ (SYS_N + 63) / 64 ], uint32_t *perm) {
    int i, j, k, s, block_idx, row, tail;
    uint64_t buf[64], ctz_list[32], t, d, mask;

    row = GFBITS * SYS_T - 32;
    block_idx = row / 64;
    tail = row % 64;

    // extract the 32x64 matrix

    for (i = 0; i < 32; i++) {
        buf[i] = (mat[ row + i ][ block_idx + 0 ] >> tail) |
                 (mat[ row + i ][ block_idx + 1 ] << (64 - tail));
    }

    // compute the column indices of pivots by Gaussian elimination.
    // the indices are stored in ctz_list

    for (i = 0; i < 32; i++) {
        t = buf[i];
        for (j = i + 1; j < 32; j++) {
            t |= buf[j];
        }

        if (t == 0) {
            return -1;    // return if buf is not full rank
        }

        ctz_list[i] = s = ctz(t);

        for (j = i + 1; j < 32; j++) {
            mask = (buf[i] >> s) & 1;
            mask -= 1;
            buf[i] ^= buf[j] & mask;
        }
        for (j =   0; j <  i; j++) {
            mask = (buf[j] >> s) & 1;
            mask = -mask;
            buf[j] ^= buf[i] & mask;
        }
        for (j = i + 1; j < 32; j++) {
            mask = (buf[j] >> s) & 1;
            mask = -mask;
            buf[j] ^= buf[i] & mask;
        }
    }

    // updating permutation

    for (j = 0;   j < 32; j++) {
        for (k = j + 1; k < 64; k++) {
            d = perm[ row + j ] ^ perm[ row + k ];
            d &= same_mask((uint16_t)k, (uint16_t)ctz_list[j]);
            perm[ row + j ] ^= d;
            perm[ row + k ] ^= d;
        }
    }

    // moving columns of mat according to the column indices of pivots

    for (i = 0; i < GFBITS * SYS_T; i += 64) {

        for (j = 0; j < min(64, GFBITS * SYS_T - i); j++) {
            buf[j] = (mat[ i + j ][ block_idx + 0 ] >> tail) |
                     (mat[ i + j ][ block_idx + 1 ] << (64 - tail));
        }

        transpose_64x64(buf, buf);

        for (j = 0; j < 32; j++) {
            for (k = j + 1; k < 64; k++) {
                d = buf[ j ] ^ buf[ k ];
                d &= same_mask((uint16_t)k, (uint16_t)ctz_list[j]);
                buf[ j ] ^= d;
                buf[ k ] ^= d;
            }
        }

        transpose_64x64(buf, buf);

        for (j = 0; j < min(64, GFBITS * SYS_T - i); j++) {
            mat[ i + j ][ block_idx + 0 ] = (mat[ i + j ][ block_idx + 0 ] << (64 - tail) >> (64 - tail)) | (buf[j] << tail);
            mat[ i + j ][ block_idx + 1 ] = (mat[ i + j ][ block_idx + 1 ] >> tail << tail) | (buf[j] >> (64 - tail));
        }
    }

    return 0;
}

int pk_gen(unsigned char *pk, uint32_t *perm, const unsigned char *sk) {
#define NBLOCKS_H ((SYS_N + 63) / 64)
#define NBLOCKS_I ((GFBITS * SYS_T + 63) / 64)
    const int block_idx = NBLOCKS_I - 1;
    int tail = (GFBITS * SYS_T) % 64;

    int i, j, k;
    int row, c;

    uint64_t mat[ GFBITS * SYS_T ][ NBLOCKS_H ];

    uint64_t mask;

    vec irr_int[2][ GFBITS ];

    vec consts[ 128 ][ GFBITS ];
    vec eval[ 128 ][ GFBITS ];
    vec prod[ 128 ][ GFBITS ];
    vec tmp[ GFBITS ];

    uint64_t list[1 << GFBITS];

    // compute the inverses

    irr_load(irr_int, sk);

    fft(eval, irr_int);

    vec_copy(prod[0], eval[0]);

    for (i = 1; i < 128; i++) {
        vec_mul(prod[i], prod[i - 1], eval[i]);
    }

    vec_inv(tmp, prod[127]);

    for (i = 126; i >= 0; i--) {
        vec_mul(prod[i + 1], prod[i], tmp);
        vec_mul(tmp, tmp, eval[i + 1]);
    }

    vec_copy(prod[0], tmp);

    // fill matrix

    de_bitslicing(list, prod);

    for (i = 0; i < (1 << GFBITS); i++) {
        list[i] <<= GFBITS;
        list[i] |= i;
        list[i] |= ((uint64_t) perm[i]) << 31;
    }

    sort_63b(1 << GFBITS, list);

    to_bitslicing_2x(consts, prod, list);

    for (i = 0; i < (1 << GFBITS); i++) {
        perm[i] = list[i] & GFMASK;
    }

    for (j = 0; j < NBLOCKS_H; j++) {
        for (k = 0; k < GFBITS; k++) {
            mat[ k ][ j ] = prod[ j ][ k ];
        }
    }

    for (i = 1; i < SYS_T; i++) {
        for (j = 0; j < NBLOCKS_H; j++) {
            vec_mul(prod[j], prod[j], consts[j]);

            for (k = 0; k < GFBITS; k++) {
                mat[ i * GFBITS + k ][ j ] = prod[ j ][ k ];
            }
        }
    }

    // gaussian elimination

    for (row = 0; row < PK_NROWS; row++) {
        i = row >> 6;
        j = row & 63;

        if (row == GFBITS * SYS_T - 32) {
            if (mov_columns(mat, perm)) {
                return -1;
            }
        }

        for (k = row + 1; k < PK_NROWS; k++) {
            mask = mat[ row ][ i ] >> j;
            mask &= 1;
            mask -= 1;

            for (c = 0; c < NBLOCKS_H; c++) {
                mat[ row ][ c ] ^= mat[ k ][ c ] & mask;
            }
        }

        if ( ((mat[ row ][ i ] >> j) & 1) == 0 ) { // return if not systematic
            return -1;
        }

        for (k = 0; k < row; k++) {
            mask = mat[ k ][ i ] >> j;
            mask &= 1;
            mask = -mask;

            for (c = 0; c < NBLOCKS_H; c++) {
                mat[ k ][ c ] ^= mat[ row ][ c ] & mask;
            }
        }

        for (k = row + 1; k < PK_NROWS; k++) {
            mask = mat[ k ][ i ] >> j;
            mask &= 1;
            mask = -mask;

            for (c = 0; c < NBLOCKS_H; c++) {
                mat[ k ][ c ] ^= mat[ row ][ c ] & mask;
            }
        }
    }

    for (row = 0; row < PK_NROWS; row++) {
        for (k = block_idx; k < NBLOCKS_H - 1; k++) {
            mat[row][k] = (mat[row][k] >> tail) | (mat[row][k + 1] << (64 - tail));
            store8(pk, mat[row][k]);
            pk += 8;
        }

        mat[row][k] >>= tail;
        store_i(pk, mat[row][k], PK_ROW_BYTES % 8);

        pk[ (PK_ROW_BYTES % 8) - 1 ] &= (1 << (PK_NCOLS % 8)) - 1; // removing redundant bits

        pk += PK_ROW_BYTES % 8;
    }

    //

    return 0;
}

