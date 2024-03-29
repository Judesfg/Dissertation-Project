#ifndef FFT_H
#define FFT_H
/*
  This file is for the Gao-Mateer FFT
  see http://www.math.clemson.edu/~sgao/papers/GM10.pdf
*/

#include <stdint.h>

#include "params.h"
#include "vec.h"

void fft(vec  /*out*/[][GFBITS], vec  /*in*/[][GFBITS]);

#endif

