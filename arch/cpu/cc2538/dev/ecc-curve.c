/*
 * Copyright (c) 2014, Institute for Pervasive Computing, ETH Zurich.
 * All rights reserved.
 *
 * Author: Andreas Dröscher <contiki@anticat.ch>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/**
 * \addtogroup cc2538-ecc-curves
 * @{
 */
#include "contiki.h"
#include "dev/ecc-driver.h"

/* See: https://www.secg.org/sec2-v2.pdf for the definitions */

#if ECC_MAXIMUM_LENGTH*32 >= 256
/* [NIST P-384, X9.62 prime384v1] */
static const uint32_t nist_p_384_p[12] = { 0xFFFFFFFF, 0x00000000, 0x00000000, 0xFFFFFFFF,
                                           0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                                           0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
static const uint32_t nist_p_384_n[12] = { 0xCCC52973, 0xECEC196A, 0x48B0A77A, 0x581A0DB2,
                                           0xF4372DDF, 0xC7634D81, 0xFFFFFFFF, 0xFFFFFFFF,
                                           0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
static const uint32_t nist_p_384_a[12] = { 0xFFFFFFFC, 0x00000000, 0x00000000, 0xFFFFFFFF,
                                           0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                                           0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
static const uint32_t nist_p_384_b[12] = { 0xD3EC2AEF, 0x2A85C8ED, 0x8A2ED19D, 0xC656398D,
                                           0x5013875A, 0x0314088F, 0xFE814112, 0x181D9C6E,
                                           0xE3F82D19, 0x988E056B, 0xE23EE7E4, 0xB3312FA7 };
static const uint32_t nist_p_384_x[12] = { 0x72760AB7, 0x3A545E38, 0xBF55296C, 0x5502F25D,
                                           0x82542A38, 0x59F741E0, 0x8BA79B98, 0x6E1D3B62,
                                           0xF320AD74, 0x8EB1C71E, 0xBE8B0537, 0xAA87CA22 };
static const uint32_t nist_p_384_y[12] = { 0x90EA0E5F, 0x7A431D7C, 0x1D7E819D, 0x0A60B1CE,
                                           0xB5F0B8C0, 0xE9DA3113, 0x289A147C, 0xF8F41DBD,
                                           0x9292DC29, 0x5D9E98BF, 0x96262C6F, 0x3617DE4A };

const ecc_curve_info_t nist_p_384 = {
  .name    = "NIST P-384",
  .size    = 12,
  .prime   = nist_p_384_p,
  .n       = nist_p_384_n,
  .a       = nist_p_384_a,
  .b       = nist_p_384_b,
  .x       = nist_p_384_x,
  .y       = nist_p_384_y
};
#endif

#if ECC_MAXIMUM_LENGTH*32 >= 256
/* [NIST P-256, X9.62 prime256v1] */
static const uint32_t nist_p_256_p[8] = { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
                                          0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF };
static const uint32_t nist_p_256_n[8] = { 0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD,
                                          0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF };
static const uint32_t nist_p_256_a[8] = { 0xFFFFFFFC, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
                                          0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF };
static const uint32_t nist_p_256_b[8] = { 0x27D2604B, 0x3BCE3C3E, 0xCC53B0F6, 0x651D06B0,
                                          0x769886BC, 0xB3EBBD55, 0xAA3A93E7, 0x5AC635D8 };
static const uint32_t nist_p_256_x[8] = { 0xD898C296, 0xF4A13945, 0x2DEB33A0, 0x77037D81,
                                          0x63A440F2, 0xF8BCE6E5, 0xE12C4247, 0x6B17D1F2 };
static const uint32_t nist_p_256_y[8] = { 0x37BF51F5, 0xCBB64068, 0x6B315ECE, 0x2BCE3357,
                                          0x7C0F9E16, 0x8EE7EB4A, 0xFE1A7F9B, 0x4FE342E2 };

const ecc_curve_info_t nist_p_256 = {
  .name    = "NIST P-256",
  .size    = 8,
  .prime   = nist_p_256_p,
  .n       = nist_p_256_n,
  .a       = nist_p_256_a,
  .b       = nist_p_256_b,
  .x       = nist_p_256_x,
  .y       = nist_p_256_y
};
#endif

#if ECC_MAXIMUM_LENGTH*32 >= 192
/* [NIST P-192, X9.62 prime192v1] */
static const uint32_t nist_p_192_p[6] = { 0xffffffff, 0xffffffff, 0xfffffffe, 0xffffffff,
                                          0xffffffff, 0xffffffff };
static const uint32_t nist_p_192_a[6] = { 0xfffffffc, 0xffffffff, 0xfffffffe, 0xffffffff,
                                          0xffffffff, 0xffffffff };
static const uint32_t nist_p_192_b[6] = { 0xc146b9b1, 0xfeb8deec, 0x72243049, 0x0fa7e9ab,
                                          0xe59c80e7, 0x64210519 };
static const uint32_t nist_p_192_x[6] = { 0x82ff1012, 0xf4ff0afd, 0x43a18800, 0x7cbf20eb,
                                          0xb03090f6, 0x188da80e };
static const uint32_t nist_p_192_y[6] = { 0x1e794811, 0x73f977a1, 0x6b24cdd5, 0x631011ed,
                                          0xffc8da78, 0x07192b95 };
static const uint32_t nist_p_192_n[6] = { 0xb4d22831, 0x146bc9b1, 0x99def836, 0xffffffff,
                                          0xffffffff, 0xffffffff };

const ecc_curve_info_t nist_p_192 = {
  .name    = "NIST P-192",
  .size    = 6,
  .prime   = nist_p_192_p,
  .n       = nist_p_192_n,
  .a       = nist_p_192_a,
  .b       = nist_p_192_b,
  .x       = nist_p_192_x,
  .y       = nist_p_192_y
};
#endif

/**
 * @}
 * @}
 */
