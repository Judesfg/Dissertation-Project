#include "blas.h"
#include "gf.h"

#include <stddef.h>

void gf256v_predicated_add(uint8_t *accu_b, uint8_t predicate, const uint8_t *a, size_t _num_byte) {
    uint8_t pr_u8 = (uint8_t) ((uint8_t) 0 - predicate);
    for (size_t i = 0; i < _num_byte; i++) {
        accu_b[i] ^= (a[i] & pr_u8);
    }
}

void gf256v_add(uint8_t *accu_b, const uint8_t *a, size_t _num_byte) {
    for (size_t i = 0; i < _num_byte; i++) {
        accu_b[i] ^= a[i];
    }
}


void gf16v_mul_scalar(uint8_t *a, uint8_t gf16_b, size_t _num_byte) {
    uint8_t tmp;
    for (size_t i = 0; i < _num_byte; i++) {
        tmp   = gf16_mul(a[i] & 0xF, gf16_b);
        tmp  |= (uint8_t) (gf16_mul(a[i] >> 4,  gf16_b) << 4);
        a[i] = tmp;
    }
}

void gf16v_madd(uint8_t *accu_c, const uint8_t *a, uint8_t gf16_b, size_t _num_byte) {
    for (size_t i = 0; i < _num_byte; i++) {
        accu_c[i] ^= gf16_mul(a[i] & 0xF, gf16_b);
        accu_c[i] ^= (uint8_t) (gf16_mul(a[i] >> 4, gf16_b) << 4);
    }
}

uint8_t gf16v_dot(const uint8_t *a, const uint8_t *b, size_t _num_byte) {
    uint8_t r = 0;
    for (size_t i = 0; i < _num_byte; i++) {
        r ^= gf16_mul(a[i], b[i]);
    }
    return r;
}

