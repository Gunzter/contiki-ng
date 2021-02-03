/*
 * Copyright (c) 2018, SICS, RISE AB
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
 */

/**
 * \file
 *      An implementation of the CBOR Object Signing and Encryption (RFC8152).
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 *
 */


#include "cose.h"
#include "oscore-crypto.h"
#include "string.h"

/* Initiate a new COSE Encrypt0 object. */
void
cose_encrypt0_init(cose_encrypt0_t *ptr)
{
  memset(ptr, 0, sizeof(cose_encrypt0_t));
}

void
cose_encrypt0_set_alg(cose_encrypt0_t *ptr, uint8_t alg)
{
  ptr->alg = alg;
}

void
cose_encrypt0_set_content(cose_encrypt0_t *ptr, uint8_t *buffer, uint16_t size)
{
  ptr->content = buffer;
  ptr->content_len = size;
}

void
cose_encrypt0_set_partial_iv(cose_encrypt0_t *ptr, const uint8_t *buffer, uint8_t size)
{
  if(size > COSE_algorithm_AES_CCM_16_64_128_TAG_LEN){
	  return;
  }
  memcpy(ptr->partial_iv, buffer, size);
  ptr->partial_iv_len = size;
}

/* Return length */
uint8_t
cose_encrypt0_get_partial_iv(cose_encrypt0_t *ptr, const uint8_t **buffer)
{
  *buffer = ptr->partial_iv;
  return ptr->partial_iv_len;
}

void
cose_encrypt0_set_key_id(cose_encrypt0_t *ptr, const uint8_t *buffer, uint8_t size)
{
  ptr->key_id = buffer;
  ptr->key_id_len = size;
}

/* Return length */
uint8_t
cose_encrypt0_get_key_id(cose_encrypt0_t *ptr, const uint8_t **buffer)
{
  *buffer = ptr->key_id;
  return ptr->key_id_len;
}

uint8_t
cose_encrypt0_get_kid_context(cose_encrypt0_t *ptr, const uint8_t **buffer){
  *buffer = ptr->kid_context;
  return ptr->kid_context_len;
}

void
cose_encrypt0_set_kid_context(cose_encrypt0_t *ptr, const uint8_t *buffer, uint8_t size){
  ptr->kid_context = buffer;
  ptr->kid_context_len = size;
} 


void
cose_encrypt0_set_aad(cose_encrypt0_t *ptr, const uint8_t *buffer, uint8_t size)
{
  ptr->aad = buffer;
  ptr->aad_len = size;
}

/* Returns 1 if successfull, 0 if key is of incorrect length. */
bool
cose_encrypt0_set_key(cose_encrypt0_t *ptr, const uint8_t *key, uint8_t key_size)
{
  if(key_size != COSE_algorithm_AES_CCM_16_64_128_KEY_LEN) {
    return false;
  }

  ptr->key = key;
  ptr->key_len = key_size;

  return true;
}

void
cose_encrypt0_set_nonce(cose_encrypt0_t *ptr, const uint8_t *buffer, uint8_t size)
{
  ptr->nonce = buffer;
  ptr->nonce_len = size;
}

int
cose_encrypt0_encrypt(cose_encrypt0_t *ptr)
{
  if(ptr->key == NULL || ptr->key_len != COSE_algorithm_AES_CCM_16_64_128_KEY_LEN) {
    return -1;
  }
  if(ptr->nonce == NULL || ptr->nonce_len != COSE_algorithm_AES_CCM_16_64_128_IV_LEN) {
    return -2;
  }
  if(ptr->aad == NULL || ptr->aad_len == 0) {
    return -3;
  }
  if(ptr->content == NULL ) {
    return -4;
  }

  return encrypt(ptr->alg,
    ptr->key, ptr->key_len,
    ptr->nonce, ptr->nonce_len,
    ptr->aad, ptr->aad_len,
    ptr->content, ptr->content_len);
}

int
cose_encrypt0_decrypt(cose_encrypt0_t *ptr)
{
  if(ptr->key == NULL || ptr->key_len != COSE_algorithm_AES_CCM_16_64_128_KEY_LEN) {
    return -1;
  }
  if(ptr->nonce == NULL || ptr->nonce_len != COSE_algorithm_AES_CCM_16_64_128_IV_LEN) {
    return -2;
  }
  if(ptr->aad == NULL || ptr->aad_len == 0) {
    return -3;
  }
  if(ptr->content == NULL ) {
    return -4;
  }

  return decrypt(ptr->alg,
    ptr->key, ptr->key_len,
    ptr->nonce, ptr->nonce_len,
    ptr->aad, ptr->aad_len,
    ptr->content, ptr->content_len);
}

void cose_sign1_init(cose_sign1_t *ptr){
  memset( ptr, 0, sizeof(cose_sign1_t));
}

void cose_sign1_set_alg(cose_sign1_t *ptr, uint8_t alg, uint8_t param){
  ptr->alg = alg;
  ptr->alg_param = param;
}

void cose_sign1_set_ciphertext(cose_sign1_t *ptr, uint8_t *buffer, int size){
  ptr->ciphertext = buffer;
  ptr->ciphertext_len = size;
}

/* Return length */
int cose_sign1_get_signature(cose_sign1_t *ptr, uint8_t **buffer){
  *buffer = ptr->signature;
  return ptr->signature_len;
}

void cose_sign1_set_signature(cose_sign1_t *ptr, uint8_t *buffer){
  ptr->signature = buffer;
  ptr->signature_len = ES256_SIGNATURE_LEN;
}

void cose_sign1_set_sigstructure(cose_sign1_t *ptr, uint8_t *buffer, int size){
  ptr->sigstructure = buffer;
  ptr->sigstructure_len = size;
}

void cose_sign1_set_public_key(cose_sign1_t *ptr, const uint8_t *buffer){
  ptr->public_key = buffer;
  ptr->public_key_len = ES256_PUBLIC_KEY_LEN;
}

void cose_sign1_set_private_key(cose_sign1_t *ptr, const uint8_t *buffer){
  ptr->private_key = buffer;
  ptr->private_key_len = ES256_PRIVATE_KEY_LEN;
}

int cose_sign1_sign(cose_sign1_t *ptr){
    return oscore_edDSA_sign(ptr->alg, ptr->alg_param, ptr->signature, ptr->ciphertext, ptr->ciphertext_len, ptr->private_key, ptr->public_key);
}

int cose_sign1_verify(cose_sign1_t *ptr){
    return oscore_edDSA_verify(ptr->alg, ptr->alg_param, ptr->signature, ptr->ciphertext, ptr->ciphertext_len, ptr->public_key);
}

size_t cose_curve_public_key_length(COSE_Elliptic_Curves_t curve) {
  switch (curve) {
    case COSE_Elliptic_Curve_P256:
      return 64;

    default:
      return 0;
  }
}

size_t cose_curve_private_key_length(COSE_Elliptic_Curves_t curve) {
  switch (curve) {
    case COSE_Elliptic_Curve_P256:
      return 32;

    default:
      return 0;
  }
}
