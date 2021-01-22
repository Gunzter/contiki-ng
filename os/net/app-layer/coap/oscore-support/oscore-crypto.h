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
 *      An implementation of the Hash Based Key Derivation Function (RFC5869) and wrappers for AES-CCM*.
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 *
 */

#ifndef _CRYPTO_H
#define _CRYPTO_H
#include <inttypes.h>
#include <stdbool.h>

#include "coap.h"

#ifndef HKDF_INFO_MAXLEN
#define HKDF_INFO_MAXLEN 25
#endif /*HKDF_INFO_MAXLEN*/

#ifndef HKDF_OUTPUT_MAXLEN
#define HKDF_OUTPUT_MAXLEN 25
#endif /*HKDF_OUTPUT_MAXLEN*/

/* Plaintext Maxlen and Tag Maxlen is quite generous. */
#define AEAD_PLAINTEXT_MAXLEN COAP_MAX_CHUNK_SIZE
/* Enough for all COSE-AES-CCM algorithms. */
#define AEAD_TAG_MAXLEN 16

#define OSCORE_CRYPTO_DECRYPTION_FAILURE     0
#define OSCORE_CRYPTO_HKDF_INVALID_INFO_LEN -1
#define OSCORE_CRYPTO_HKDF_INVALID_OKM_LEN  -2
#define OSCORE_CRYPTO_UNSUPPORTED_ALGORITHM -5
#define OSCORE_CRYPTO_INVALID_KEY_LEN       -6
#define OSCORE_CRYPTO_INVALID_NONCE_LEN     -7

#ifdef WITH_GROUPCOM
#include "sys/pt.h"

#ifndef SHA256_DIGEST_LEN_BYTES
#define SHA256_DIGEST_LEN_BYTES (256/8)
#endif /*SHA256_DIGEST_LEN_BYTES*/

#ifndef MSGS_TO_SIGN_SIZE
#define MSGS_TO_SIGN_SIZE 5
#endif /*MSGS_TO_SIGN_SIZE*/

#ifndef MSGS_TO_VERIFY_SIZE
#define MSGS_TO_VERIFY_SIZE 5
#endif /*OSCORE_WITH_HW_CRYPTO*/
#endif /*WITH_GROUPCOM*/

/* Returns 0 if failure to encrypt. Ciphertext length, otherwise. Tag-length and ciphertext length is derived from algorithm. No check is done to ensure that ciphertext buffer is of the correct length. */
int encrypt(
	uint8_t alg,
	const uint8_t *key, uint8_t key_len,
	const uint8_t *nonce, uint8_t nonce_len,
	const uint8_t *aad, uint8_t aad_len,
	uint8_t *buffer, uint16_t plaintext_len);

/* Return 0 if if decryption failure. Plaintext length otherwise. Tag-length and plaintext length is derived from algorithm. No check is done to ensure that plaintext buffer is of the correct length. */
int decrypt(
	uint8_t alg,
	const uint8_t *key, uint8_t key_len,
	const uint8_t *nonce, uint8_t nonce_len,
	const uint8_t *aad, uint8_t aad_len,
	uint8_t *buffer, uint16_t ciphertext_len);

/* int hkdf(uint8_t whichSha, const uint8_t *salt, uint8_t salt_len, const uint8_t *ikm,  uint8_t ikm_len, const uint8_t *info, uint8_t info_len, uint8_t *okm, uint8_t   okm_len); */
int hkdf(
	const uint8_t *salt, uint8_t salt_len,
	const uint8_t *ikm, uint8_t ikm_len,
	uint8_t *info, uint8_t info_len,
	uint8_t *okm, uint8_t okm_len);

int
oscore_esDSA_keypair(int8_t alg, int8_t alg_param, uint8_t *private_key, uint8_t *public_key, uint8_t *es256_seed);

/* Return 0 if signing failure. Signatue length otherwise, signature length and key length are derived fron es256 values. No check is done to ensure that buffers are of the correct length. */
int
oscore_edDSA_sign(int8_t alg, int8_t alg_param, uint8_t *signature, uint8_t *ciphertext, uint16_t ciphertext_len, uint8_t *private_key, uint8_t *public_key);

/* Return 0 if signing failure. Signatue length otherwise, signature length and key length are derived fron es256 values. No check is done to ensure that buffers are of the correct length. */
int
oscore_edDSA_verify(int8_t alg, int8_t alg_param, uint8_t *signature, uint8_t *plaintext, uint16_t plaintext_len, uint8_t *public_key);
#ifdef WITH_GROUPCOM
/*Code inspired by Matthew*/
void oscore_crypto_init(void);

bool crypto_fill_random(uint8_t *buffer, size_t size_in_bytes);
//queue items and functions are moved to coap.h

//HW crypto
typedef struct messages_to_verify_entry
{
	struct messages_to_verify_entry * next;
	struct process *process;
	const uint8_t *message;
	uint16_t message_len;
	uint8_t result;
/*#ifdef OSCORE_WITH_HW_CRYPTO
	const
#endif *//*OSCORE_WITH_HW_CRYPTO*/
       	uint8_t *public_key; 
	uint8_t *signature;

} messages_to_verify_entry_t;

bool queue_message_to_verify(struct process *process, uint8_t *signature, uint8_t *message, uint16_t message_len, uint8_t *public_key);
void queue_message_to_verify_done(messages_to_verify_entry_t *item);

typedef struct messages_to_sign_entry
{
	struct messages_to_sign_entry *next;
	struct process *process;
	uint8_t  message[250];
	uint16_t message_len;
	uint8_t *private_key;
	uint8_t *public_key;
	uint8_t result;
	uint8_t *signature;

} messages_to_sign_entry_t;

bool queue_message_to_sign(struct process *process, uint8_t *private_key, uint8_t *public_key, uint8_t *message, uint16_t message_len, uint8_t *signature);
void queue_message_to_sign_done(messages_to_sign_entry_t *item);

extern process_event_t pe_message_signed;
extern process_event_t pe_message_verified;
#endif /*WITH_GROUPCOM*/

#endif /* _CRYPTO_H */
