#ifndef CONTROLBITS_H
#define CONTROLBITS_H
/*
  This file is for functions required for generating the control bits of the Benes network w.r.t. a random permutation
  see the Lev-Pippenger-Valiant paper https://www.computer.org/csdl/trans/tc/1981/02/06312171.pdf
*/


#include <stdint.h>

void sort_63b(int n, uint64_t *x);
void controlbits(unsigned char *out, const uint32_t *pi);

#endif

