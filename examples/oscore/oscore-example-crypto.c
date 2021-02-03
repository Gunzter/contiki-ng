/*
 * Copyright (c) 2013, Institute for Pervasive Computing, ETH Zurich
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
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
 *
 * This file is part of the Contiki operating system.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"
#include "oscore-crypto.h"
#include "cose.h"

#include "dev/crypto.h"

static void printf_hex(const uint8_t *data, unsigned int len)
{
  unsigned int i = 0;
  for(i = 0; i < len; i++) {
    printf("%02x", data[i]);
  }
  printf("\n");
}

static const uint8_t key[16] = { 0xf6, 0xb1, 0x12, 0x19, 0xe1, 0xd1, 0xbc, 0x83, 0xb4, 0x0d, 0x33, 0xa4, 0xf8, 0x03, 0x52, 0x8d };
static const uint8_t iv[13]  = { 0x37, 0xf2, 0x28, 0x6b, 0xfa, 0xc0, 0x43, 0x8f, 0xaa, 0x98, 0x30, 0xcd, 0x07 };
static const uint8_t aad[] = { 0x83, 0x68, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x30, 0x40, 0x4e, 0x85, 0x01, 0x81, 0x0a, 0x46, 0x4b, 0x00, 0x14, 0xd5, 0x2b, 0xe6, 0x41, 0x00, 0x40 };
static const uint8_t plaintext[] = { 0x45 };

PROCESS(oscore_crypto_test, "OSCORE crypto test");
AUTOSTART_PROCESSES(&oscore_crypto_test);

PROCESS_THREAD(oscore_crypto_test, ev, data)
{
  PROCESS_BEGIN();

  crypto_init();

  int ret;

  uint8_t buffer[sizeof(plaintext) + COSE_algorithm_AES_CCM_16_64_128_TAG_LEN];
  memcpy(buffer, plaintext, sizeof(plaintext));

  printf("Encrypting...\n");

  ret = encrypt(COSE_Algorithm_AES_CCM_16_64_128,
    key, sizeof(key),
    iv, sizeof(iv),
    aad, sizeof(aad),
    buffer, sizeof(plaintext));

  printf_hex(buffer, sizeof(buffer));

  printf("Encrypting result = %d\n", ret);
  printf("\n");
  printf("Decrypting...\n");

  ret = decrypt(COSE_Algorithm_AES_CCM_16_64_128,
    key, sizeof(key),
    iv, sizeof(iv),
    aad, sizeof(aad),
    buffer, sizeof(plaintext));

  printf_hex(buffer, sizeof(buffer));

  printf("Decrypting result = %d\n", ret);

  PROCESS_END();
}
