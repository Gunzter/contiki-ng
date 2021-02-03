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
 *      TODO update the docs
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 *
 */

#include "oscore-crypto.h"
#include "ccm-star.h"
#include <string.h>
#include "cose.h"
#include <stdio.h>
#include "dtls-hmac.h"
#include "assert.h"
//#include "dtls.h"

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "oscore"
#ifdef LOG_CONF_LEVEL_OSCORE
#define LOG_LEVEL LOG_CONF_LEVEL_OSCORE
#else
#define LOG_LEVEL LOG_LEVEL_WARN
#endif

#if LOG_LEVEL == LOG_LEVEL_DBG
#define OSCORE_ENC_DEC_DEBUG
#endif

#ifdef OSCORE_ENC_DEC_DEBUG
static void
printf_hex(const char *name, const uint8_t *data, unsigned int len)
{
  LOG_DBG("%s (len=%u): ", name, len);
  LOG_DBG_BYTES(data, len);
  LOG_DBG_("\n");
}
#endif

#ifdef WITH_GROUPCOM
#include "sys/pt.h"
#include "os/lib/queue.h"
#include "os/lib/memb.h"
#include "random.h"


/*SW/HW crypto libraries*/
#ifdef OSCORE_WITH_HW_CRYPTO

#include "sys/pt-sem.h"
process_event_t oscore_pe_crypto_lock_released;
static struct pt_sem oscore_crypto_processor_mutex;

#ifdef CONTIKI_TARGET_ZOUL
#include "dev/ecc-algorithm.h"
#include "dev/ecc-curve.h"
#include "dev/sha256.h"
#endif /*CONTIKI_TARGET_ZOUL*/

#ifdef CONTIKI_TARGET_SIMPLELINK
#include "ti/drivers/TRNG.h"
#include "ti/drivers/SHA2.h"
#include "ti/drivers/ECDSA.h"
#include "ti/drivers/AESCCM.h"
#include "ti/drivers/cryptoutils/cryptokey/CryptoKeyPlaintext.h"
#include "ti/drivers/cryptoutils/ecc/ECCParams.h"
#endif /*CONTIKI_TARGET_SIMPLELINK*/

#ifdef CONTIKI_TARGET_NATIVE
#error "Cannot run HW crypto on native!"
#endif /*CONTIKI_TARGET_NATIVE*/

#else /*SW crypto*/
#include "uECC.h"
#include "lib/ccm-star.h"

#endif /*OSCORE_WITH_HW_CRYPTO*/


process_event_t oscore_pe_message_signed;
process_event_t oscore_pe_message_verified;

PROCESS(oscore_signer, "oscore_signer");
PROCESS(oscore_verifier, "oscore_verifier");
#else /* not WITH_GROUPCOM */

/*SW/HW crypto libraries*/
#ifdef OSCORE_WITH_HW_CRYPTO
#include "sys/pt-sem.h"
process_event_t oscore_pe_crypto_lock_released;
static struct pt_sem oscore_crypto_processor_mutex;

#ifdef CONTIKI_TARGET_ZOUL
#include "dev/sha256.h"
#endif /*CONTIKI_TARGET_ZOUL*/

#ifdef CONTIKI_TARGET_SIMPLELINK
#include "ti/drivers/SHA2.h"
#include "ti/drivers/AESCCM.h"
#include "ti/drivers/cryptoutils/cryptokey/CryptoKeyPlaintext.h"
#endif /*CONTIKI_TARGET_SIMPLELINK*/

#ifdef CONTIKI_TARGET_NATIVE
#error "Cannot run HW crypto on native!"
#endif /*CONTIKI_TARGET_NATIVE*/

#else /*OSCORE_WITH_HW_CRYPTO*/
#include "lib/ccm-star.h"
#endif /*OSCORE_WITH_HW_CRYPTO*/

#endif /*WITH_GROUPCOM*/
/*Utilities*/
/*---------------------------------------------------------------------------*/
#ifdef OSCORE_WITH_HW_CRYPTO
void
reverse_endianness(uint8_t *a, unsigned int len) {
	uint8_t i, tmp[len];
	memcpy(tmp, a, len);
	for(i = 0; i < len; i++) {
		 a[len - 1 - i] = tmp[i];
	}
}
/*---------------------------------------------------------------------------*/
static inline
uint32_t
uint8x4_to_uint32(const uint8_t *field)
{/*left*/
  return ((uint32_t)field[0] << 24)
         | ((uint32_t)field[1] << 16)
         | ((uint32_t)field[2] << 8)
         | ((uint32_t)field[3]);
}
/*---------------------------------------------------------------------------*/
static void
ec_uint8v_to_uint32v(uint32_t *result, const uint8_t *data, size_t size)
{
  /* `data` is expected to be encoded in big-endian */
  for(int i = (size / sizeof(uint32_t)) - 1; i >= 0; i--) {
    *result = uint8x4_to_uint32(&data[i * sizeof(uint32_t)]);
    result++;
  }
}
/*---------------------------------------------------------------------------*/
static inline void
uint32_to_uint8x4(uint8_t *field, uint32_t data)
{
#ifdef CONTIKI_TARGET_SIMPLELINK
	/*right*/
	field[3] = (uint8_t)((data & 0xFF000000) >> 24);
	field[2] = (uint8_t)((data & 0x00FF0000) >> 16);
	field[1] = (uint8_t)((data & 0x0000FF00) >>  8);
	field[0] = (uint8_t)((data & 0x000000FF)      );
#elif CONTIKI_TARGET_ZOUL
	/*left*/
	field[0] = (uint8_t)((data & 0xFF000000) >> 24);
	field[1] = (uint8_t)((data & 0x00FF0000) >> 16);
	field[2] = (uint8_t)((data & 0x0000FF00) >>  8);
	field[3] = (uint8_t)((data & 0x000000FF)      );
#endif/*CONTIKI_TARGET_SIMPLELINK*/

}
/*---------------------------------------------------------------------------*/
static void
ec_uint32v_to_uint8v(uint8_t *result, const uint32_t *data, size_t size)
{
	for (int i = (size / sizeof(uint32_t)) - 1; i >= 0; i--)
	{
		uint32_to_uint8x4(result, data[i]);
		result += sizeof(uint32_t);
	}
}
/*---------------------------------------------------------------------------*/
void convert_simplelink(uint8_t *a, size_t len) {
	uint8_t i, len_32 = len / sizeof(uint32_t);
	uint32_t a_32[len_32], a_32_rev[len_32];
	ec_uint8v_to_uint32v(a_32, a, len);
	/*reverse endianness within 32-bit words*/
	for(i = 0; i < len_32; i++) {
		a_32_rev[len_32 - 1 - i] = a_32[i];
	}
	ec_uint32v_to_uint8v(a, a_32_rev, len);
}
#endif /*OSCORE_WITH_HW_CRYPTO*/
/*OSCORE crypto functions*/
/*---------------------------------------------------------------------------*/

/* Returns 0 if failure to encrypt. Ciphertext length, otherwise.
   Tag-length and ciphertext length is derived from algorithm. No check is done to ensure
   that ciphertext buffer is of the correct length. */
int
encrypt(uint8_t alg,
        const uint8_t *key, uint8_t key_len,
        const uint8_t *nonce, uint8_t nonce_len,
        const uint8_t *aad, uint8_t aad_len,
        uint8_t *buffer, uint16_t plaintext_len)
{
  if(alg != COSE_Algorithm_AES_CCM_16_64_128) {
    LOG_ERR("Unsupported algorithm %u\n", alg);
    return OSCORE_CRYPTO_UNSUPPORTED_ALGORITHM;
  }

  if(key_len != COSE_algorithm_AES_CCM_16_64_128_KEY_LEN) {
    LOG_ERR("Invalid key length %u != %u\n", key_len, COSE_algorithm_AES_CCM_16_64_128_KEY_LEN);
    return OSCORE_CRYPTO_INVALID_KEY_LEN;
  }

  if(nonce_len != COSE_algorithm_AES_CCM_16_64_128_IV_LEN) {
    LOG_ERR("Invalid nonce length %u != %u\n", nonce_len, COSE_algorithm_AES_CCM_16_64_128_IV_LEN);
    return OSCORE_CRYPTO_INVALID_NONCE_LEN;
  }

  uint8_t* tag_buffer = &buffer[plaintext_len];

#ifdef OSCORE_ENC_DEC_DEBUG
  LOG_DBG("Encrypt:\n");
  printf_hex("Key", key, key_len);
  printf_hex("IV", nonce, nonce_len);
  printf_hex("AAD", aad, aad_len);
  printf_hex("Plaintext", buffer, plaintext_len);
  printf_hex("Tag", tag_buffer, COSE_algorithm_AES_CCM_16_64_128_TAG_LEN);
#endif
  
#ifdef OSCORE_WITH_HW_CRYPTO
#ifdef CONTIKI_TARGET_ZOUL
  cc2538_ccm_star_driver.set_key(key);
  cc2538_ccm_star_driver.aead(nonce, buffer, plaintext_len, aad, aad_len, tag_buffer, COSE_algorithm_AES_CCM_16_64_128_TAG_LEN, 1);
#elif CONTIKI_TARGET_SIMPLELINK 
  AESCCM_Handle handle;
  CryptoKey cryptoKey;
  int_fast16_t encryptionResult;
  uint8_t mac[COSE_algorithm_AES_CCM_16_64_128_TAG_LEN];
  uint8_t output[plaintext_len];

  handle = AESCCM_open(0, NULL);
 
  if (handle == NULL) {
      LOG_ERR("\nCould not open AESCCM handle!\n");
      return -1;
  }

  CryptoKeyPlaintext_initKey(&cryptoKey, key, key_len);
 
  AESCCM_Operation operation;
  AESCCM_Operation_init(&operation);

  operation.key               = &cryptoKey;
  operation.aad               = aad;
  operation.aadLength         = aad_len;
  operation.input             = buffer;
  operation.output            = output;
  operation.inputLength       = plaintext_len;
  operation.nonce             = nonce;
  operation.nonceLength       = nonce_len;
  operation.mac               = mac;
  operation.macLength         = COSE_algorithm_AES_CCM_16_64_128_TAG_LEN;

  encryptionResult = AESCCM_oneStepEncrypt(handle, &operation);

  if (encryptionResult != AESCCM_STATUS_SUCCESS) {
    LOG_ERR("\nAESCCM encryption failed with code: %d\n", encryptionResult);
    return -1;
  }
  memcpy(buffer, output, plaintext_len);
  memcpy(&(buffer[plaintext_len]), mac,  COSE_algorithm_AES_CCM_16_64_128_TAG_LEN);
  AESCCM_close(handle);
#endif /*CONTIKI_TARGET_ZOUL or CONTIKI_TARGET_SIMPLELINK */
#else /* not OSCORE_WITH_HW_CRYPTO  */
  CCM_STAR.set_key(key);
  CCM_STAR.aead(nonce, buffer, plaintext_len, aad, aad_len, tag_buffer, COSE_algorithm_AES_CCM_16_64_128_TAG_LEN, 1);
#endif /* OSCORE_WITH_HW_CRYPTO */

#ifdef OSCORE_ENC_DEC_DEBUG
  printf_hex("Tag'", tag_buffer, COSE_algorithm_AES_CCM_16_64_128_TAG_LEN);
  printf_hex("Ciphertext", buffer, plaintext_len);
#endif

  return plaintext_len + COSE_algorithm_AES_CCM_16_64_128_TAG_LEN;
}
/*---------------------------------------------------------------------------*/
/* Return 0 if if decryption failure. Plaintext length otherwise.
   Tag-length and plaintext length is derived from algorithm. No check is done to ensure
   that plaintext buffer is of the correct length. */
int
decrypt(uint8_t alg,
        const uint8_t *key, uint8_t key_len,
        const uint8_t *nonce, uint8_t nonce_len,
        const uint8_t *aad, uint8_t aad_len,
        uint8_t *buffer, uint16_t ciphertext_len)
{
  if(alg != COSE_Algorithm_AES_CCM_16_64_128) {
    LOG_ERR("Unsupported algorithm %u\n", alg);
    return OSCORE_CRYPTO_UNSUPPORTED_ALGORITHM;
  }

  if(key_len != COSE_algorithm_AES_CCM_16_64_128_KEY_LEN) {
    LOG_ERR("Invalid key length %u != %u\n", key_len, COSE_algorithm_AES_CCM_16_64_128_KEY_LEN);
    return OSCORE_CRYPTO_INVALID_KEY_LEN;
  }

  if(nonce_len != COSE_algorithm_AES_CCM_16_64_128_IV_LEN) {
    LOG_ERR("Invalid nonce length %u != %u\n", nonce_len, COSE_algorithm_AES_CCM_16_64_128_IV_LEN);
    return OSCORE_CRYPTO_INVALID_NONCE_LEN;
  }

  uint8_t tag_buffer[COSE_algorithm_AES_CCM_16_64_128_TAG_LEN];
  uint16_t plaintext_len = ciphertext_len - COSE_algorithm_AES_CCM_16_64_128_TAG_LEN;

#ifdef OSCORE_ENC_DEC_DEBUG
  LOG_DBG("Decrypt:\n");
  printf_hex("Key", key, key_len);
  printf_hex("IV", nonce, nonce_len);
  printf_hex("AAD", aad, aad_len);
  printf_hex("Ciphertext", buffer, plaintext_len);
  printf_hex("Tag", &buffer[plaintext_len], COSE_algorithm_AES_CCM_16_64_128_TAG_LEN);
#endif

#ifdef OSCORE_WITH_HW_CRYPTO
#ifdef CONTIKI_TARGET_ZOUL
  cc2538_ccm_star_driver.set_key(key);
  cc2538_ccm_star_driver.aead(nonce, buffer, plaintext_len, aad, aad_len, tag_buffer, COSE_algorithm_AES_CCM_16_64_128_TAG_LEN, 0);
#elif CONTIKI_TARGET_SIMPLELINK 
  AESCCM_Operation operation;
  AESCCM_Handle handle;
  AESCCM_Params params;
  CryptoKey cryptoKey;
  int_fast16_t decryptionResult;
  uint8_t output[plaintext_len];
  AESCCM_Params_init(&params);

  handle = AESCCM_open(0, &params);
  if (handle == NULL) {
    LOG_ERR("Could not open AESCCM handle!\n");
    return -1; 
  }

  CryptoKeyPlaintext_initKey(&cryptoKey, key, key_len);

  AESCCM_Operation_init(&operation);

  operation.key               = &cryptoKey;
  operation.aad               = aad;
  operation.aadLength         = aad_len;
  operation.input             = buffer;
  operation.output            = output;
  operation.inputLength       = plaintext_len;
  operation.nonce             = nonce;
  operation.nonceLength       = nonce_len;
  operation.mac               = &(buffer[plaintext_len]);
  operation.macLength         = COSE_algorithm_AES_CCM_16_64_128_TAG_LEN;

  decryptionResult = AESCCM_oneStepDecrypt(handle, &operation);

  if (decryptionResult != AESCCM_STATUS_SUCCESS) {
       LOG_ERR("Decryption in HW failed with code %d\n", decryptionResult);
       return 0;
  }
  memcpy(buffer, output, plaintext_len);
  AESCCM_close(handle);
  return plaintext_len;
#endif /*CONTIKI_TARGET_ZOUL or CONTIKI_TARGET_SIMPLELINK */
#else /* not OSCORE_WITH_HW_CRYPTO  */
  CCM_STAR.set_key(key);
  CCM_STAR.aead(nonce, buffer, plaintext_len, aad, aad_len, tag_buffer, COSE_algorithm_AES_CCM_16_64_128_TAG_LEN, 0);
#endif /* OSCORE_WITH_HW_CRYPTO */

#ifdef OSCORE_ENC_DEC_DEBUG
  printf_hex("Tag'", tag_buffer, COSE_algorithm_AES_CCM_16_64_128_TAG_LEN);
  printf_hex("Plaintext", buffer, plaintext_len);
#endif

  if(memcmp(tag_buffer, &(buffer[plaintext_len]), COSE_algorithm_AES_CCM_16_64_128_TAG_LEN) != 0) {
    return OSCORE_CRYPTO_DECRYPTION_FAILURE; /* Decryption failure */
  }
  return plaintext_len;
}
/*---------------------------------------------------------------------------*/
/* only works with key_len <= 64 bytes */
void
hmac_sha256(const uint8_t *key, uint8_t key_len, const uint8_t *data, uint8_t data_len, uint8_t *hmac)
{
  assert(key_len <= 64);

  dtls_hmac_context_t ctx;
  dtls_hmac_init(&ctx, key, key_len);
  dtls_hmac_update(&ctx, data, data_len);
  dtls_hmac_finalize(&ctx, hmac);
}
/*---------------------------------------------------------------------------*/
static void
hkdf_extract(const uint8_t *salt, uint8_t salt_len, const uint8_t *ikm, uint8_t ikm_len, uint8_t *prk_buffer)
{
  uint8_t zeroes[DTLS_SHA256_DIGEST_LENGTH];
  memset(zeroes, 0, sizeof(zeroes));

  if(salt == NULL || salt_len == 0){
    salt = zeroes;
    salt_len = sizeof(zeroes);
  }
  
  hmac_sha256(salt, salt_len, ikm, ikm_len, prk_buffer);
}
/*---------------------------------------------------------------------------*/
static int
hkdf_expand(const uint8_t *prk, const uint8_t *info, uint8_t info_len, uint8_t *okm, uint8_t okm_len)
{
  if(info_len > HKDF_INFO_MAXLEN) {
    return OSCORE_CRYPTO_HKDF_INVALID_INFO_LEN;
  }
  if(okm_len > HKDF_OUTPUT_MAXLEN) {
    return OSCORE_CRYPTO_HKDF_INVALID_OKM_LEN;
  }
  int N = (okm_len + 32 - 1) / 32; /* ceil(okm_len/32) */
  uint8_t aggregate_buffer[32 + HKDF_INFO_MAXLEN + 1];
  uint8_t out_buffer[HKDF_OUTPUT_MAXLEN + 32]; /* 32 extra bytes to fit the last block */
  int i;
  /* Compose T(1) */
  memcpy(aggregate_buffer, info, info_len);
  aggregate_buffer[info_len] = 0x01;
  hmac_sha256(prk, 32, aggregate_buffer, info_len + 1, &(out_buffer[0]));

  /* Compose T(2) -> T(N) */
  memcpy(aggregate_buffer, &(out_buffer[0]), 32);
  for(i = 1; i < N; i++) {
    memcpy(&(aggregate_buffer[32]), info, info_len);
    aggregate_buffer[32 + info_len] = i + 1;
    hmac_sha256(prk, 32, aggregate_buffer, 32 + info_len + 1, &(out_buffer[i * 32]));
    memcpy(aggregate_buffer, &(out_buffer[i * 32]), 32);
  }

  memcpy(okm, out_buffer, okm_len);

  return 0;
}
/*---------------------------------------------------------------------------*/
int
hkdf(
  const uint8_t *salt, uint8_t salt_len,
  const uint8_t *ikm, uint8_t ikm_len,
  const uint8_t *info, uint8_t info_len,
  uint8_t *okm, uint8_t okm_len)
{
  uint8_t prk_buffer[DTLS_SHA256_DIGEST_LENGTH];
  hkdf_extract(salt, salt_len, ikm, ikm_len, prk_buffer);
  return hkdf_expand(prk_buffer, info, info_len, okm, okm_len);
}
/*---------------------------------------------------------------------------*/
#ifdef WITH_GROUPCOM
/*Group OSCORE data structures and protothreads*/
typedef struct {
	struct pt pt;
	struct process *process;
#ifdef OSCORE_WITH_HW_CRYPTO 
#ifdef CONTIKI_TARGET_ZOUL
	ecc_dsa_sign_state_t ecc_sign_state;
#endif /* CONTIKI_TARGET_ZOUL */
#else
	struct pt sign_deterministic_pt;
#endif /* OSCORE_WITH_HW_CRYPTO */
	uint16_t sig_len;

} sign_state_t;

typedef struct {
	struct pt pt;
	struct process *process;
#ifdef OSCORE_WITH_HW_CRYPTO
#ifdef CONTIKI_TARGET_ZOUL
	ecc_dsa_verify_state_t ecc_verify_state;
#endif /* CONTIKI_TARGET_ZOUL */
#else 
	struct pt verify_sw_pt;
#endif /* OSCORE_WITH_HW_CRYPTO */

} verify_state_t;

PT_THREAD(oscore_ecc_sign(sign_state_t *state, const uint8_t *buffer, size_t msg_len, const uint8_t *private_key, const uint8_t *public_key, uint8_t *signature));

PT_THREAD(oscore_ecc_verify(verify_state_t *state, const uint8_t *public_key, const uint8_t *buffer, size_t buffer_len, const uint8_t *signature));
/*---------------------------------------------------------------------------*/
/**
 * \brief Initialise oscore crypto resources (HW engines, processes, etc.).
 *
 */
void
oscore_crypto_init(void)
{
#ifdef OSCORE_WITH_HW_CRYPTO	
#ifdef CONTIKI_TARGET_ZOUL
	crypto_init();
	crypto_disable();
	pka_init();
	pka_disable();
#elif CONTIKI_TARGET_SIMPLELINK
	TRNG_init();
	TRNG_Params trng_params;
	TRNG_Params_init(&trng_params);
	AESCCM_init();
	AESCCM_Params aesccm_params;
	AESCCM_Params_init(&aesccm_params);
	SHA2_init();
	SHA2_Params sha_params;
	SHA2_Params_init(&sha_params);
	sha_params.returnBehavior = SHA2_RETURN_BEHAVIOR_BLOCKING;
	ECDSA_init();
	ECDSA_Params ecdsa_params;
	ECDSA_Params_init(&ecdsa_params);
#endif	/*CONTIKI_TARGET_ZOUL*/
	PT_SEM_INIT(&oscore_crypto_processor_mutex, 1);
	oscore_pe_crypto_lock_released = process_alloc_event();
#endif /*OSCORE_WITH_HW_CRYPTO*/
	oscore_pe_message_signed = process_alloc_event();
	oscore_pe_message_verified = process_alloc_event();
	process_start(&oscore_signer, NULL);
	process_start(&oscore_verifier, NULL);
	LOG_INFO("OSCORE crypto initialised.\n");
}
#ifdef OSCORE_WITH_HW_CRYPTO
#ifdef CONTIKI_TARGET_SIMPLELINK
/*---------------------------------------------------------------------------*/
static uint8_t
sha2_hash(const uint8_t *message, size_t len, uint8_t *hash)
{
	int_fast16_t result;
	/*One-step hash */
	SHA2_Handle handle;
	handle = SHA2_open(0, NULL);
	if(!handle) {
		LOG_ERR("SHA2: could not open handle!\n");
		return -1;
	}

	result = SHA2_hashData(handle, message, len, hash);
	if(result != SHA2_STATUS_SUCCESS) {
		LOG_ERR("SHA2 failed, result: %d", result);
	}
	SHA2_close(handle);
	return (uint8_t) result;
}
#endif /*CONTIKI_TARGET_SIMPLELINK*/
#ifdef CONTIKI_TARGET_ZOUL
/*---------------------------------------------------------------------------*/
bool
oscore_crypto_fill_random(uint8_t *buffer, size_t size_in_bytes)
{
	if(buffer == NULL) {
		return false;
	}

	uint16_t *buffer_u16 = (uint16_t *)buffer;

	for(size_t i = 0; i < size_in_bytes / sizeof(uint16_t); i++) {
		buffer_u16[i] = random_rand();
	}

	if((size_in_bytes % sizeof(uint16_t)) != 0) {
		buffer[size_in_bytes - 1] = (uint8_t)random_rand();
	}

	return true;
}
/*---------------------------------------------------------------------------*/
static uint8_t
sha256_hash(const uint8_t *buffer, size_t len, uint8_t *hash)
{
	sha256_state_t sha256_state;
	uint8_t ret;
	bool enabled = CRYPTO_IS_ENABLED();
	if(!enabled) {
		crypto_enable();
	}
	ret = sha256_init(&sha256_state);
	if(ret != CRYPTO_SUCCESS) {
		LOG_ERR("sha256_init failed with %u\n", ret);
		goto end;
	}
	ret = sha256_process(&sha256_state, buffer, len);
	if(ret != CRYPTO_SUCCESS) {
		LOG_ERR("sha256_process failed with %u\n", ret);
		goto end;
	}
	ret = sha256_done(&sha256_state, hash);
	if(ret != CRYPTO_SUCCESS) {
		LOG_ERR("sha256_done failed with %u\n", ret);
		goto end;
	}
end:
	if(enabled) {
		crypto_disable();
	}
	return ret;
}
#endif /*CONTIKI_TARGET_ZOUL*/
#endif /*OSCORE_WITH_HW_CRYPTO*/
/*---------------------------------------------------------------------------*/
/* Return 0 if key pair generation failure. Key lengths are derived fron ed25519 values. No check is done to ensure that buffers are of the correct length. */
int
oscore_edDSA_keypair(int8_t alg, int8_t alg_param, uint8_t *private_key, uint8_t *public_key, uint8_t *es256_seed)
{
   if(alg != COSE_Algorithm_ES256 || alg_param != COSE_Elliptic_Curve_P256)  {
       return 0;
    }
 /*   es256_create_keypair(public_key, private_key, es256_seed);*/
  return 1;
}
/*---------------------------------------------------------------------------*/
/* For ECDSA-Deterministic - SW crypto only*/
#define SHA256_BLOCK_LENGTH  64
#define SHA256_DIGEST_LENGTH 32
#ifndef OSCORE_WITH_HW_CRYPTO

typedef struct SHA256_HashContext {
    uECC_HashContext uECC;
    dtls_sha256_ctx ctx;
} SHA256_HashContext;

static void init_SHA256(uECC_HashContext *base) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    dtls_sha256_init(&context->ctx);
}

static void update_SHA256(uECC_HashContext *base,
                          const uint8_t *message,
                          unsigned message_size) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    dtls_sha256_update(&context->ctx, message, message_size);
}

static void finish_SHA256(uECC_HashContext *base, uint8_t *hash_result) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    dtls_sha256_final(hash_result, &context->ctx);
}

PT_THREAD(oscore_ecc_sign_deterministic(sign_state_t *state, uint8_t *private_key, uint8_t *message_hash, uECC_HashContext *hash_context, uint8_t *signature))
{
	PT_BEGIN(&state->sign_deterministic_pt);
	uint8_t res = -1;
	res = uECC_sign_deterministic(private_key, message_hash, hash_context, signature);
	if(res != 1) {
		LOG_ERR("Deterministic sign in SW failed with code %d!\n", res);
		PT_EXIT(&state->sign_deterministic_pt);
	}
	PT_END(&state->sign_deterministic_pt);
}

PT_THREAD(oscore_ecc_verify_sw(verify_state_t *state, const uint8_t *public_key, const uint8_t *message_hash, const uint8_t *signature))
{
	PT_BEGIN(&state->verify_sw_pt);
	uint8_t res = -1;
        res = uECC_verify(public_key, message_hash, signature);
	if(res != 1) {
		LOG_ERR("Deterministic verify in SW failed with code %d!\n", res);
		PT_EXIT(&state->verify_sw_pt);
	}
	PT_END(&state->verify_sw_pt);
}
#endif /*OSCORE_WITH_HW_CRYPTO*/

PT_THREAD(oscore_ecc_sign(sign_state_t *state, const uint8_t *buffer, size_t msg_len, const uint8_t *private_key, const uint8_t *public_key, uint8_t *signature))
{
	PT_BEGIN(&state->pt);
	uint8_t message_hash[SHA256_DIGEST_LENGTH];/*==SHA56_DIGEST_LEN_BYTES*/
#ifdef OSCORE_WITH_HW_CRYPTO
	uint8_t sha_ret;
	PT_SEM_WAIT(&state->pt, &oscore_crypto_processor_mutex);
#endif /* OSCORE_WITH_HW_CRYPTO */
	state->sig_len = 0;
#ifndef OSCORE_WITH_HW_CRYPTO /*SW crypto is used */
	dtls_sha256_ctx msg_hash_ctx;
	dtls_sha256_init(&msg_hash_ctx);
	dtls_sha256_update(&msg_hash_ctx, buffer, msg_len);
	dtls_sha256_final(message_hash, &msg_hash_ctx);

	uint8_t tmp[ES256_PRIVATE_KEY_LEN + ES256_PRIVATE_KEY_LEN + ES256_SIGNATURE_LEN];
	SHA256_HashContext ctx = {{&init_SHA256, &update_SHA256, &finish_SHA256, 64, 32, tmp}};
 	PT_SPAWN(&state->pt, &state->sign_deterministic_pt, ecc_sign_deterministic(state, private_key, message_hash, &ctx.uECC, signature));

	state->sig_len = ES256_SIGNATURE_LEN;

#else /* HW crypto is used */
#ifdef CONTIKI_TARGET_SIMPLELINK
	uint8_t priv_key[ES256_PRIVATE_KEY_LEN];
	uint8_t hash[SHA256_DIGEST_LENGTH];
	uint8_t r[32] = {0};
	uint8_t s[32] = {0};
	/*uint8_t k[32] =  		       {0xAE, 0x50, 0xEE, 0xFA, 0x27, 0xB4, 0xDB, 0x14,
						0x9F, 0xE1, 0xFB, 0x04, 0xF2, 0x4B, 0x50, 0x58,
						0x91, 0xE3, 0xAC, 0x4D, 0x2A, 0x5D, 0x43, 0xAA,
						0xCA, 0xC8, 0x7F, 0x79, 0x52, 0x7E, 0x1A, 0x7A};*/
	uint8_t k[32] = {0}; /*The number will be created by TRNG*/
	TRNG_Handle trngHandle;
	CryptoKey myPrivateKey;
	CryptoKey pmsnKey;
	ECDSA_Handle ecdsaHandle;
	ECDSA_OperationSign operationSign;
	int_fast16_t trngResult, operationResult;

	sha_ret= sha2_hash((const uint8_t *) buffer, msg_len, message_hash);
	if(sha_ret != SHA2_STATUS_SUCCESS) {
		LOG_ERR("SHA2 failed! Code: %u", sha_ret);
		PT_EXIT(&state->pt);
	}

	trngHandle = TRNG_open(0, NULL);
	if(!trngHandle) {
		LOG_ERR("Failed to open TRNG handle!\n");
		PT_EXIT(&state->pt);
	}

	CryptoKeyPlaintext_initBlankKey(&pmsnKey, k, ECCParams_NISTP256.length);
	trngResult = TRNG_generateEntropy(trngHandle, &pmsnKey);

	if(trngResult != TRNG_STATUS_SUCCESS) {
		LOG_ERR("TRNG failed with code: %d", trngResult);
		PT_EXIT(&state->pt);
	}

	TRNG_close(trngHandle);

	ecdsaHandle = ECDSA_open(0, NULL);
	if(!ecdsaHandle) {
		LOG_ERR("\nFailed to open ecdsaHandle!!!!\n");
		PT_EXIT(&state->pt);
	}
	memcpy(priv_key, private_key, ES256_PRIVATE_KEY_LEN);
	memcpy(hash, message_hash, SHA256_DIGEST_LENGTH);
	/*Re-format the inputs according to the requirements of simplelink crypto-processor*/
	convert_simplelink(priv_key, ES256_PRIVATE_KEY_LEN);
	convert_simplelink(hash, SHA256_DIGEST_LENGTH);

	CryptoKeyPlaintext_initKey(&myPrivateKey, priv_key, ES256_PRIVATE_KEY_LEN);
	//CryptoKeyPlaintext_initKey(&pmsnKey, k, sizeof(k));

	ECDSA_OperationSign_init(&operationSign);
	operationSign.curve = &ECCParams_NISTP256;
	operationSign.myPrivateKey = &myPrivateKey;
	operationSign.pmsn = &pmsnKey;
	operationSign.hash = hash;
	operationSign.r = r;
	operationSign.s = s;

	operationResult = ECDSA_sign(ecdsaHandle, &operationSign);

	if(operationResult != ECDSA_STATUS_SUCCESS) {
		LOG_ERR("Sign failed with the following code: %d", operationResult);
		PT_EXIT(&state->pt);
	}
	/*reverse all bytes of r and s*/
	reverse_endianness(r, ES256_PRIVATE_KEY_LEN);
	reverse_endianness(s, ES256_PRIVATE_KEY_LEN);
	memcpy(signature, r, ES256_PRIVATE_KEY_LEN);
	memcpy(signature + ES256_PRIVATE_KEY_LEN, s, ES256_PRIVATE_KEY_LEN);

	state->sig_len = ES256_SIGNATURE_LEN;
	ECDSA_close(ecdsaHandle);
	PT_SEM_SIGNAL(&state->pt, &crypto_processor_mutex);
#endif /*CONTIKI_TARGET_SIMPLELINK */
#ifdef CONTIKI_TARGET_ZOUL
	sha_ret = sha256_hash(buffer, msg_len, message_hash);
	if(sha_ret != CRYPTO_SUCCESS) {
		LOG_ERR("sha256_hash failed with %u\n", sha_ret);
		state->ecc_sign_state.result = sha_ret;
		PT_SEM_SIGNAL(&state->pt, &oscore_crypto_processor_mutex);
		PT_EXIT(&state->pt);
	}

	ec_uint8v_to_uint32v(state->ecc_sign_state.hash, message_hash, sizeof(message_hash));

	state->ecc_sign_state.process = state->process;
	state->ecc_sign_state.curve_info = &nist_p_256;
	ec_uint8v_to_uint32v(state->ecc_sign_state.secret, private_key, ES256_PRIVATE_KEY_LEN);

	oscore_crypto_fill_random((uint8_t *) state->ecc_sign_state.k_e, ES256_PRIVATE_KEY_LEN);

	pka_enable();
	PT_SPAWN(&state->pt, &state->ecc_sign_state.pt, ecc_dsa_sign(&state->ecc_sign_state));
	pka_disable();

	PT_SEM_SIGNAL(&state->pt, &oscore_crypto_processor_mutex);

	if(state->ecc_sign_state.result != PKA_STATUS_SUCCESS)	{
		LOG_ERR("Failed to sign message with %d\n", state->ecc_sign_state.result);
		PT_EXIT(&state->pt);
	} 
	ec_uint32v_to_uint8v(signature, state->ecc_sign_state.point_r.x, ES256_PRIVATE_KEY_LEN);
	ec_uint32v_to_uint8v(signature + ES256_PRIVATE_KEY_LEN, state->ecc_sign_state.signature_s, ES256_PRIVATE_KEY_LEN);
	state->sig_len = ES256_SIGNATURE_LEN;
	
	PT_SEM_SIGNAL(&state->pt, &oscore_crypto_processor_mutex);
#endif /*CONTIKI_TARGET_ZOUL*/
#endif /*OSCORE_WITH_HW_CRYPTO*/
	PT_END(&state->pt);
}

PT_THREAD(oscore_ecc_verify(verify_state_t *state, const uint8_t *public_key, const uint8_t *buffer, size_t buffer_len, const uint8_t *signature))
{
	PT_BEGIN(&state->pt);
#ifdef OSCORE_WITH_HW_CRYPTO
	PT_SEM_WAIT(&state->pt, &oscore_crypto_processor_mutex);
#endif /*OSCORE_WITH_HW_CRYPTO*/
	uint8_t message_hash[SHA256_DIGEST_LENGTH];
#ifndef OSCORE_WITH_HW_CRYPTO
	dtls_sha256_ctx msg_hash_ctx;
	dtls_sha256_init(&msg_hash_ctx);
	dtls_sha256_update(&msg_hash_ctx, buffer, buffer_len);
	dtls_sha256_final(message_hash, &msg_hash_ctx);
	PT_SPAWN(&state->pt, &state->verify_sw_pt, ecc_verify_sw(state, public_key, message_hash, signature));
#else 
	uint8_t sha_ret;
#ifdef CONTIKI_TARGET_SIMPLELINK
	CryptoKey theirPublicKey;
	ECDSA_Handle ecdsaHandle;
	int_fast16_t operationResult;
	ECDSA_OperationVerify operationVerify;
	uint8_t pub_x[ES256_PRIVATE_KEY_LEN];
       	uint8_t pub_y[ES256_PRIVATE_KEY_LEN];
	uint8_t pub_key[ES256_PUBLIC_KEY_LEN];
       	uint8_t hash[SHA256_DIGEST_LENGTH];
	uint8_t sig_r[ES256_PRIVATE_KEY_LEN];
	uint8_t sig_s[ES256_PRIVATE_KEY_LEN];	
	sha_ret = sha2_hash(buffer, buffer_len, message_hash);
	if(sha_ret != SHA2_STATUS_SUCCESS) {
		LOG_ERR("Sha2 failed with the code: %u!\n", sha_ret);
		PT_EXIT(&state->pt);
	}

	ecdsaHandle = ECDSA_open(0, NULL);

	if(!ecdsaHandle) {
		LOG_ERR("Could not open ECDSA handle!\n");
		PT_EXIT(&state->pt);
	}

	memcpy(pub_x, public_key, 				ES256_PRIVATE_KEY_LEN);	
	memcpy(pub_y, public_key + ES256_PRIVATE_KEY_LEN, 	ES256_PRIVATE_KEY_LEN);
	memcpy(hash, message_hash, 				SHA256_DIGEST_LENGTH);
	memcpy(sig_r, signature, 				ES256_PRIVATE_KEY_LEN);
	memcpy(sig_s, signature + ES256_PRIVATE_KEY_LEN, 	ES256_PRIVATE_KEY_LEN);
	/*Re-format the inputs according to the requirements of simplelink crypto-processor*/
	convert_simplelink(pub_x, ES256_PRIVATE_KEY_LEN);
	convert_simplelink(pub_y, ES256_PRIVATE_KEY_LEN);
	convert_simplelink(hash, SHA256_DIGEST_LENGTH);
	convert_simplelink(sig_r, ES256_PRIVATE_KEY_LEN);
	convert_simplelink(sig_s, ES256_PRIVATE_KEY_LEN);

	memcpy(pub_key, pub_x, 		ES256_PRIVATE_KEY_LEN);
	memcpy(&(pub_key[32]), pub_y, 	ES256_PRIVATE_KEY_LEN);

	CryptoKeyPlaintext_initKey(&theirPublicKey, pub_key, ES256_PUBLIC_KEY_LEN);

	ECDSA_OperationVerify_init(&operationVerify);

	operationVerify.curve = &ECCParams_NISTP256;
	operationVerify.theirPublicKey = &theirPublicKey;
	operationVerify.hash = hash;
	operationVerify.r = sig_r;
	operationVerify.s = sig_s;
	operationResult = ECDSA_verify(ecdsaHandle, &operationVerify);

	PT_SEM_SIGNAL(&state->pt, &crypto_processor_mutex);

	if(operationResult != ECDSA_STATUS_SUCCESS) {
		LOG_ERR("Verify failed with the following code: %d\n", operationResult);
		PT_EXIT(&state->pt);
	} else {
		LOG_DBG("Verify in Simplelink HW succeded!\n");
	}

	ECDSA_close(ecdsaHandle);
#endif /*CONTIKI_TARGET_SIMPLELINK*/
#ifdef CONTIKI_TARGET_ZOUL
	const uint8_t *sig_r = signature;
	const uint8_t *sig_s = signature + ES256_PRIVATE_KEY_LEN;
	ec_uint8v_to_uint32v(state->ecc_verify_state.signature_r, sig_r, ES256_PRIVATE_KEY_LEN);
	ec_uint8v_to_uint32v(state->ecc_verify_state.signature_s, sig_s, ES256_PRIVATE_KEY_LEN);

	sha_ret = sha256_hash(buffer, buffer_len, message_hash);
	if(sha_ret != CRYPTO_SUCCESS) {
		LOG_ERR("sha256_hash failed with %u\n", sha_ret);
		state->ecc_verify_state.result = sha_ret;
		PT_SEM_SIGNAL(&state->pt, &oscore_crypto_processor_mutex);
		PT_EXIT(&state->pt);
	}

	ec_uint8v_to_uint32v(state->ecc_verify_state.hash, message_hash, sizeof(message_hash));

	state->ecc_verify_state.process = state->process;
	state->ecc_verify_state.curve_info = &nist_p_256;
	ec_uint8v_to_uint32v(state->ecc_verify_state.public.x, public_key, 32);
	ec_uint8v_to_uint32v(state->ecc_verify_state.public.y, &public_key[32], 32);

	pka_enable();
	PT_SPAWN(&state->pt, &state->ecc_verify_state.pt, ecc_dsa_verify(&state->ecc_verify_state));
	pka_disable();

	PT_SEM_SIGNAL(&state->pt, &oscore_crypto_processor_mutex);

	if(state->ecc_verify_state.result != PKA_STATUS_SUCCESS) {
		LOG_ERR("Failed to verify message with %d\n", state->ecc_verify_state.result);
		PT_EXIT(&state->pt);
	}
#endif /*CONTIKI_TARGET_ZOUL*/
#endif /*OSCORE_WITH_HW_CRYPTO*/
	PT_END(&state->pt);
}	

QUEUE(oscore_messages_to_sign);
MEMB(oscore_messages_to_sign_memb, oscore_messages_to_sign_entry_t, MSGS_TO_SIGN_SIZE);

QUEUE(oscore_messages_to_verify);
MEMB(oscore_messages_to_verify_memb, oscore_messages_to_verify_entry_t, MSGS_TO_VERIFY_SIZE);
/*---------------------------------------------------------------------------*/
bool
oscore_queue_message_to_sign(struct process *process, const uint8_t *private_key, const uint8_t *public_key, const uint8_t *message, uint16_t message_len, uint8_t *signature)
{
	oscore_messages_to_sign_entry_t *item = memb_alloc(&oscore_messages_to_sign_memb);
	if(!item) {
		LOG_ERR("queue_message_to_sign: out of memory\n");
		return false;
	}
	item->process = process;
	item->private_key = private_key;
	item->public_key = public_key;
	memcpy(item->message, message, message_len);
	item->message_len = message_len;
	item->signature = signature;
	
	queue_enqueue(oscore_messages_to_sign, item);

	process_post_synch(&oscore_signer, PROCESS_EVENT_CONTINUE, NULL);

	return true;
}

/*---------------------------------------------------------------------------*/
void
oscore_queue_message_to_sign_done(oscore_messages_to_sign_entry_t *item)
{
	memb_free(&oscore_messages_to_sign_memb, item);
}

PROCESS_THREAD(oscore_signer, ev, data)
{
	PROCESS_BEGIN();

	queue_init(oscore_messages_to_sign);
	memb_init(&oscore_messages_to_sign_memb);

	LOG_INFO("Process signer started!\n");
	while(1) {
		PROCESS_YIELD_UNTIL(!queue_is_empty(oscore_messages_to_sign));
		while(!queue_is_empty(oscore_messages_to_sign)){
			static oscore_messages_to_sign_entry_t *item;
			item = (oscore_messages_to_sign_entry_t *) queue_dequeue(oscore_messages_to_sign);
			static sign_state_t state;
			state.process = &oscore_signer;
			PROCESS_PT_SPAWN(&state.pt, oscore_ecc_sign(&state, item->message, item->message_len, item->private_key, item->public_key, item->signature));
#if defined OSCORE_WITH_HW_CRYPTO && defined CONTIKI_TARGET_ZOUL
			item->result = state.ecc_sign_state.result;
#endif /* OSCORE_WITH_HW_CRYPTO && CONTIKI_TARGET_ZOUL */
 			if(process_post(PROCESS_BROADCAST, oscore_pe_message_signed, item) != PROCESS_ERR_OK){ 
				LOG_ERR("Failed to post pe_message_signed to %s\n", item->process->name);
			} else {
				oscore_queue_message_to_sign_done(item);
			}
		}
#ifdef OSCORE_WITH_HW_CRYPTO
		process_post(PROCESS_BROADCAST, oscore_pe_crypto_lock_released, NULL);
#endif /* OSCORE_WITH_HW_CRYPTO */
	}

	PROCESS_END();
}
/*---------------------------------------------------------------------------*/
bool
oscore_queue_message_to_verify(struct process *process, const uint8_t *signature, const uint8_t *message, uint16_t message_len, const uint8_t *public_key)
{
	oscore_messages_to_verify_entry_t *item = memb_alloc(&oscore_messages_to_verify_memb);
	if(!item) {
		LOG_ERR("queue_message_to_verify: out of memory\n");
		return false;
	}
	item->process = process;
	item->signature = signature;
	item->message = message;
	item->message_len = message_len;
	item->public_key = public_key;

	queue_enqueue(oscore_messages_to_verify, item);

	process_post_synch(&oscore_verifier, PROCESS_EVENT_CONTINUE, NULL);

	return true;
}

/*---------------------------------------------------------------------------*/
void
oscore_queue_message_to_verify_done(oscore_messages_to_verify_entry_t *item)
{
	memb_free(&oscore_messages_to_verify_memb, item);
}

PROCESS_THREAD(oscore_verifier, ev, data)
{
	PROCESS_BEGIN();

	queue_init(oscore_messages_to_verify);
	memb_init(&oscore_messages_to_verify_memb);

	LOG_INFO("Process verifier started!\n");
	while(1) {
		PROCESS_YIELD_UNTIL(!queue_is_empty(oscore_messages_to_verify));

		while(!queue_is_empty(oscore_messages_to_verify)) {
			static oscore_messages_to_verify_entry_t *item;
			item = (oscore_messages_to_verify_entry_t *) queue_dequeue(oscore_messages_to_verify);
			static verify_state_t state;
			state.process = &oscore_verifier;
			PROCESS_PT_SPAWN(&state.pt, oscore_ecc_verify(&state, item->public_key, item->message, item->message_len, item->signature));
#ifdef OSCORE_WITH_HW_CRYPTO
#ifdef CONTIKI_TARGET_ZOUL
			item->result = state.ecc_verify_state.result;
#endif/*CONTIKI_TARGET_ZOUL*/
#endif/*OSCORE_WITH_HW_CRYPTO*/
			static uint8_t verify_result;
		        verify_result = item->result;
			if(process_post(PROCESS_BROADCAST, oscore_pe_message_verified, &verify_result) != PROCESS_ERR_OK) {
				LOG_ERR("Failed to post pe_message_verified to %s\n", item->process->name);
			} else {
				oscore_queue_message_to_verify_done(item);
			}
		}
#ifdef OSCORE_WITH_HW_CRYPTO
		process_post(PROCESS_BROADCAST, oscore_pe_crypto_lock_released, NULL);
#endif/*OSCORE_WITH_HW_CRYPTO*/
	}
	PROCESS_END();
}
/*---------------------------------------------------------------------------*/
int
oscore_edDSA_sign(int8_t alg, int8_t alg_param, uint8_t *signature, uint8_t *ciphertext, uint16_t ciphertext_len, const uint8_t *private_key, const uint8_t *public_key)
{
  if(alg != COSE_Algorithm_ES256 || alg_param != COSE_Elliptic_Curve_P256)  {
    return 0;
  }
  
  if(!oscore_queue_message_to_sign(PROCESS_CURRENT(), private_key, public_key, ciphertext, ciphertext_len, signature)) {
	  LOG_ERR("Could not queue the message to sign!\n");
	  return 0;
  }
  return 1;
}
/*---------------------------------------------------------------------------*/
/* Return 0 if signing failure. Signatue length otherwise, signature length and key length are derived fron ed25519 values. No check is done to ensure that buffers are of the correct length. */
int
oscore_edDSA_verify(int8_t alg, int8_t alg_param, uint8_t *signature, uint8_t *plaintext, uint16_t plaintext_len, const uint8_t *public_key)
{
  if(alg != COSE_Algorithm_ES256 || alg_param != COSE_Elliptic_Curve_P256)  {
    return 0;
  }

  if(!oscore_queue_message_to_verify(PROCESS_CURRENT(), signature, plaintext, plaintext_len, public_key))
  {
	  LOG_ERR("Could not queue message to verify\n");
	  return 0;
  }
  return 1;
}
#endif /*WITH_GROUPCOM*/
