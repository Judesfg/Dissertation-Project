#include "util.h"


void store_i(unsigned char *out, uint64_t in, int i) {
    int j;

    for (j = 0; j < i; j++) {
        out[j] = (in >> (j * 8)) & 0xFF;
    }
}

void store2(unsigned char *dest, gf a) {
    dest[0] = a & 0xFF;
    dest[1] = a >> 8;
}

uint16_t load2(const unsigned char *src) {
    uint16_t a;

    a = src[1];
    a <<= 8;
    a |= src[0];

    return a & GFMASK;
}

uint32_t load4(const unsigned char *src) {
    uint32_t a;

    a  = src[3];
    a <<= 8;
    a |= src[2];
    a <<= 8;
    a |= src[1];
    a <<= 8;
    a |= src[0];

    return a;
}

void irr_load(uint64_t *out, const unsigned char *in) {
    int i, j;
    uint16_t irr[ SYS_T + 1 ];

    for (i = 0; i < SYS_T; i++) {
        irr[i] = load2(in + i * 2);
        irr[i] &= GFMASK;
    }

    irr[ SYS_T ] = 1;

    for (i = 0; i < GFBITS; i++) {
        out[i] = 0;
    }

    for (i = SYS_T; i >= 0; i--) {
        for (j = 0; j < GFBITS; j++) {
            out[j] <<= 1;
            out[j] |= (irr[i] >> j) & 1;
        }
    }
}

void store8(unsigned char *out, uint64_t in) {
    out[0] = (in >> 0x00) & 0xFF;
    out[1] = (in >> 0x08) & 0xFF;
    out[2] = (in >> 0x10) & 0xFF;
    out[3] = (in >> 0x18) & 0xFF;
    out[4] = (in >> 0x20) & 0xFF;
    out[5] = (in >> 0x28) & 0xFF;
    out[6] = (in >> 0x30) & 0xFF;
    out[7] = (in >> 0x38) & 0xFF;
}

uint64_t load8(const unsigned char *in) {
    int i;
    uint64_t ret = in[7];

    for (i = 6; i >= 0; i--) {
        ret <<= 8;
        ret |= in[i];
    }

    return ret;
}

gf bitrev(gf a) {
    a = ((a & 0x00FF) << 8) | ((a & 0xFF00) >> 8);
    a = ((a & 0x0F0F) << 4) | ((a & 0xF0F0) >> 4);
    a = ((a & 0x3333) << 2) | ((a & 0xCCCC) >> 2);
    a = ((a & 0x5555) << 1) | ((a & 0xAAAA) >> 1);

    return a >> 4;
}
