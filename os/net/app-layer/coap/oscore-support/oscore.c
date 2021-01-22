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
 *      An implementation of the Object Security for Constrained RESTful Enviornments (Internet-Draft-15) .
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 *
 */




#include "oscore.h"
#include "cbor.h"
#include "coap.h"
#include "stdio.h"
#include "inttypes.h"
#include "assert.h"

#ifdef WITH_GROUPCOM
#include "oscore-crypto.h"
#endif

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "oscore"
#ifdef LOG_CONF_LEVEL_OSCORE
#define LOG_LEVEL LOG_CONF_LEVEL_OSCORE
#else
#define LOG_LEVEL LOG_LEVEL_WARN
#endif

/* Sets Alg, Partial IV Key ID and Key in COSE. */
static void
oscore_populate_cose(coap_message_t *pkt, cose_encrypt0_t *cose, oscore_ctx_t *ctx, bool sending);

/* Creates and sets External AAD */
static size_t
oscore_prepare_aad(coap_message_t *coap_pkt, cose_encrypt0_t *cose, uint8_t *buffer, bool sending);

static void
printf_hex_detailed(const char* name, const uint8_t *data, size_t len)
{
  LOG_DBG("%s (len=%zu): ", name, len);
  LOG_DBG_BYTES(data, len);
  LOG_DBG_("\n");
}

static bool
coap_is_request(const coap_message_t *coap_pkt)
{
  return coap_pkt->code >= COAP_GET && coap_pkt->code <= COAP_DELETE;
}
bool
oscore_protected_request(const coap_message_t *request)
{
  return request != NULL && coap_is_option(request, COAP_OPTION_OSCORE);
}
void
oscore_protect_resource(coap_resource_t *resource)
{
  resource->oscore_protected = 1;
}
bool oscore_is_resource_protected(const coap_resource_t *resource)
{
  return resource->oscore_protected;
}
static uint8_t
u64tob(uint64_t value, uint8_t *buffer)
{
  memset(buffer, 0, 8);
  uint8_t length = 0;
  for(int i = 0; i < 8; i++){
    uint8_t temp = (value >> (8*i)) & 0xFF;

    if(temp != 0){
      length = i+1;
    }
  }

  for (int i = 0; i < length; i++){
    buffer[length - i - 1] = (value >> (8*i)) & 0xFF;
  }  
  return length == 0 ? 1 : length;

}
static uint64_t
btou64(uint8_t *bytes, size_t len)
{
  uint8_t buffer[8];
  memset(buffer, 0, sizeof(buffer)); /* function variables are not initializated to anything */
  int offset = 8 - len;
  uint64_t num;

  memcpy((uint8_t *)(buffer + offset), bytes, len);

  num =
    (uint64_t)buffer[0] << 56 |
    (uint64_t)buffer[1] << 48 |
    (uint64_t)buffer[2] << 40 |
    (uint64_t)buffer[3] << 32 |
    (uint64_t)buffer[4] << 24 |
    (uint64_t)buffer[5] << 16 |
    (uint64_t)buffer[6] << 8 |
    (uint64_t)buffer[7];

  return num;
}
static int
oscore_encode_option_value(uint8_t *option_buffer, cose_encrypt0_t *cose, bool include_partial_iv)
{
  uint8_t offset = 1;
  if(cose->partial_iv_len > 5){
	  return 0;
  }
  option_buffer[0] = 0;
  if(cose->partial_iv_len > 0 && cose->partial_iv != NULL && include_partial_iv) {
    option_buffer[0] |= (0x07 & cose->partial_iv_len);
    memcpy(&(option_buffer[offset]), cose->partial_iv, cose->partial_iv_len);
    offset += cose->partial_iv_len;
  }
#ifdef WITH_GROUPCOM
  //Always set the 4th LSB to 1 and set kid context = Gid. kid = rid.
  //TODO right now hardcoded to only respond the Java client!
  uint8_t kid[1] = { 0x52 }; //values taken from Java client and group-oscore-server.c
  uint8_t gid[3] = { 0x44, 0x61, 0x6c };
  uint8_t gid_len = 3, kid_len = 1;
  //add kid_context = group id
  option_buffer[0] |= 0x10;
  option_buffer[offset] = gid_len; 
  offset++;
  memcpy(&(option_buffer[offset]), gid, gid_len);
  offset += gid_len;
  //add kid
  option_buffer[0] |= 0x08;
  memcpy(&(option_buffer[offset]), kid, kid_len);
  offset += kid_len;
#else
  if(cose->kid_context_len > 0 && cose->kid_context != NULL) {
    option_buffer[0] |= 0x10;
    option_buffer[offset] = cose->kid_context_len;
    offset++;
    memcpy(&(option_buffer[offset]), cose->kid_context, cose->kid_context_len);
    offset += cose->kid_context_len;
  }

  if(cose->key_id_len > 0 && cose->key_id != NULL) {
    option_buffer[0] |= 0x08;
    memcpy(&(option_buffer[offset]), cose->key_id, cose->key_id_len);
    offset += cose->key_id_len;
  }
#endif
  LOG_DBG("OSCORE encoded option value, len %d, full [",offset);
  LOG_DBG_BYTES(option_buffer, offset);
  LOG_DBG_("]\n");

  if(offset == 1 && option_buffer[0] == 0) { /* If option_value is 0x00 it should be empty. */
	  return 0;
  }
  return offset;
}

coap_status_t
oscore_decode_option_value(uint8_t *option_value, int option_len, cose_encrypt0_t *cose)
{
  if(option_len == 0){
    return NO_ERROR;
  } else if( option_len > 255 || option_len < 0 || (option_value[0] & 0x06) == 6 || (option_value[0] & 0x07) == 7 || (option_value[0] & 0xE0) != 0) {
    return BAD_OPTION_4_02;
  }
#ifdef WITH_GROUPCOM
  /*h and k flags MUST be 1 in group OSCORE. h MUST be 1 only for requests. //TODO exclude h if client behaviour considered.*/  
  if ( (option_value[0] & 0x18) == 0) {
    return BAD_OPTION_4_02;
  }
#endif
  
  uint8_t partial_iv_len = (option_value[0] & 0x07);
  uint8_t offset = 1;
  if(partial_iv_len != 0) {    
    if( offset + partial_iv_len > option_len) {
      return BAD_OPTION_4_02;
    }

    cose_encrypt0_set_partial_iv(cose, &(option_value[offset]), partial_iv_len);
    offset += partial_iv_len;
  }
  
  /* If h-flag is set KID-Context field is present. */
  if((option_value[0] & 0x10) != 0) {
    uint8_t kid_context_len = option_value[offset];
    offset++;
    if (offset + kid_context_len > option_len) {
      return BAD_OPTION_4_02;
    }

    cose_encrypt0_set_kid_context(cose, &(option_value[offset]), kid_context_len);
    offset += kid_context_len;
  }
  /* IF k-flag is set Key ID field is present. */
  if((option_value[0] & 0x08) != 0) {
    int kid_len = option_len - offset;
    if (kid_len <= 0) {
      return BAD_OPTION_4_02;
    }
    cose_encrypt0_set_key_id(cose, &(option_value[offset]), kid_len);
  }
  return NO_ERROR;
}
/* Decodes a OSCORE message and passes it on to the COAP engine. */
coap_status_t
oscore_decode_message(coap_message_t *coap_pkt)
{
  cose_encrypt0_t cose[1];
  oscore_ctx_t *ctx = NULL;
  uint8_t aad_buffer[35];
  uint8_t nonce_buffer[COSE_algorithm_AES_CCM_16_64_128_IV_LEN];
  uint8_t seq_buffer[8];
  cose_encrypt0_init(cose);
#ifdef WITH_GROUPCOM
  cose_sign1_t sign[1];
  cose_sign1_init(sign);
#endif /*WITH_GROUPCOM*/

  printf_hex_detailed("object_security", coap_pkt->object_security, coap_pkt->object_security_len);

  /* Options are discarded later when they are overwritten. This should be improved */
  coap_status_t ret = oscore_decode_option_value(coap_pkt->object_security, coap_pkt->object_security_len, cose);

  if(ret != NO_ERROR){
	  LOG_ERR("OSCORE option value could not be parsed.\n");
	  coap_error_message = "OSCORE option could not be parsed.";
	  return ret;
  }

  if(coap_is_request(coap_pkt)) {
#ifdef WITH_GROUPCOM
    uint8_t *group_id; /*used to extract gid from OSCORE option*/
#endif
    const uint8_t *key_id;
    uint8_t key_id_len = cose_encrypt0_get_key_id(cose, &key_id);
    ctx = oscore_find_ctx_by_rid(key_id, key_id_len);
    if(ctx == NULL) {
      LOG_ERR("OSCORE Security Context not found (rid = '");
      LOG_ERR_BYTES(key_id, key_id_len);
      LOG_ERR_("' len=%u).\n", key_id_len);
      coap_error_message = "Security context not found";
      return OSCORE_MISSING_CONTEXT; /* Will transform into UNAUTHORIZED_4_01 later */
    }
#ifdef WITH_GROUPCOM
    uint8_t gid_len = cose_encrypt0_get_kid_context(cose, &group_id);
    if(gid_len == 0) {
      LOG_DBG_("Gid length is 0.\n");
      return UNAUTHORIZED_4_01;
    } 
    else if (*(ctx->gid) != *(group_id)) {
      LOG_DBG_("Received gid does not match.\n");    
      return UNAUTHORIZED_4_01;
    }
    else {
       LOG_DBG("Group-ID, len %d, full [",gid_len);
       LOG_DBG_BYTES(group_id, gid_len);
       LOG_DBG_("]\n");
    }
#endif
    /*4 Verify the ‘Partial IV’ parameter using the Replay Window, as described in Section 7.4. */
    if(!oscore_validate_sender_seq(&ctx->recipient_context, cose)) {
      LOG_WARN("OSCORE Replayed or old message\n");
      coap_error_message = "Replay detected";
      return UNAUTHORIZED_4_01;
    }
    cose_encrypt0_set_key(cose, ctx->recipient_context.recipient_key, COSE_algorithm_AES_CCM_16_64_128_KEY_LEN);
  } else { /* Message is a response */
    uint64_t seq;
    ctx = oscore_get_contex_from_exchange(coap_pkt->token, coap_pkt->token_len, &seq);
    oscore_remove_exchange(coap_pkt->token, coap_pkt->token_len);
    if(ctx == NULL) {
      LOG_ERR("OSCORE Security Context not found (token = '");
      LOG_ERR_BYTES(coap_pkt->token, coap_pkt->token_len);
      LOG_ERR_("' len=%u).\n", coap_pkt->token_len);
      coap_error_message = "Security context not found";
      return OSCORE_MISSING_CONTEXT; /* Will transform into UNAUTHORIZED_4_01 later */
    }
    /* If message contains a partial IV, the received is used. */
    if(cose->partial_iv_len == 0){
      LOG_DBG("cose->partial_iv_len == 0 (%"PRIu64")\n", seq);
      uint8_t seq_len = u64tob(seq, seq_buffer);
      cose_encrypt0_set_partial_iv(cose, seq_buffer, seq_len);
    } else {
      LOG_DBG("cose->partial_iv_len == %"PRIu16" (%"PRIu64")\n", cose->partial_iv_len, seq);
    }
  }

  oscore_populate_cose(coap_pkt, cose, ctx, false);
  coap_pkt->security_context = ctx;

  size_t aad_len = oscore_prepare_aad(coap_pkt, cose, aad_buffer, false);
  cose_encrypt0_set_aad(cose, aad_buffer, aad_len);
  cose_encrypt0_set_alg(cose, ctx->alg);
  
  oscore_generate_nonce(cose, coap_pkt, nonce_buffer, sizeof(nonce_buffer));
  cose_encrypt0_set_nonce(cose, nonce_buffer, sizeof(nonce_buffer));
  
uint16_t encrypt_len = coap_pkt->payload_len;
#ifdef WITH_GROUPCOM
  if (ctx->mode == OSCORE_GROUP){
    encrypt_len = coap_pkt->payload_len - ES256_SIGNATURE_LEN;
  }
#endif /* WITH_GROUPCOM */
  uint8_t tmp_buffer[encrypt_len];
  memcpy(tmp_buffer, coap_pkt->payload, encrypt_len); 
  cose_encrypt0_set_content(cose, coap_pkt->payload, encrypt_len);
  int res = cose_encrypt0_decrypt(cose);
  if(res <= 0) {
    LOG_ERR("OSCORE Decryption Failure, result code: %d\n", res);
    if(coap_is_request(coap_pkt)) {
      oscore_roll_back_seq(&ctx->recipient_context);
      coap_error_message = "Decryption failure";
      return BAD_REQUEST_4_00;
    } else {
      coap_error_message = "Decryption failure";
      return OSCORE_DECRYPTION_ERROR;
    }  
  }
#ifdef WITH_GROUPCOM
  if (ctx->mode == OSCORE_GROUP){
  /* verify signature     */
     uint8_t *signature_ptr = coap_pkt->payload + encrypt_len;//address of the signature (after the ciphertext)
     uint8_t sig_buffer[aad_len + encrypt_len + 24];
     //TODO optimize so we dont have to do this twice
     aad_len = oscore_prepare_int(ctx, cose, coap_pkt->object_security, coap_pkt->object_security_len,aad_buffer);
 
     oscore_populate_sign(coap_is_request(coap_pkt), sign, ctx);
     size_t sig_len = oscore_prepare_sig_structure(sig_buffer, 
                  aad_buffer, aad_len, tmp_buffer, encrypt_len);
     cose_sign1_set_signature(sign, signature_ptr);
     cose_sign1_set_ciphertext(sign, sig_buffer, sig_len);
     cose_sign1_verify(sign);//we do not care about the response; the thing will be in progress
  } 
#endif /* WITH_GROUPCOM */


  return oscore_parser(coap_pkt, cose->content, res, ROLE_CONFIDENTIAL);
}

static void
oscore_populate_cose(coap_message_t *pkt, cose_encrypt0_t *cose, oscore_ctx_t *ctx, bool sending)
{
  cose_encrypt0_set_alg(cose, ctx->alg);

  uint8_t partial_iv_buffer[8];
  uint8_t partial_iv_len;

#ifdef WITH_GROUPCOM
    if(sending){//recent_seq is the one that actually gets updated
      partial_iv_len = u64tob(ctx->recipient_context.recent_seq, partial_iv_buffer);
      cose_encrypt0_set_partial_iv(cose, partial_iv_buffer, partial_iv_len);
      cose_encrypt0_set_key_id(cose, ctx->sender_context.sender_id, ctx->sender_context.sender_id_len);
      cose_encrypt0_set_key(cose, ctx->sender_context.sender_key, COSE_algorithm_AES_CCM_16_64_128_KEY_LEN);
  } else {
  
    cose_encrypt0_set_key_id(cose, ctx->recipient_context.recipient_id, ctx->recipient_context.recipient_id_len);
    cose_encrypt0_set_key(cose, ctx->recipient_context.recipient_key, COSE_algorithm_AES_CCM_16_64_128_KEY_LEN);
  }
#else
  if(coap_is_request(pkt)) {
    if(sending){
      cose->partial_iv_len = u64tob(ctx->sender_context.seq, cose->partial_iv);
      cose_encrypt0_set_key_id(cose, ctx->sender_context.sender_id, ctx->sender_context.sender_id_len);
      cose_encrypt0_set_key(cose, ctx->sender_context.sender_key, COSE_algorithm_AES_CCM_16_64_128_KEY_LEN);
    } else { /* receiving */
      assert(cose->partial_iv_len > 0); /* Partial IV set by decode option value. */
      assert(cose->key_id != NULL); /* Key ID set by decode option value. */
      cose_encrypt0_set_key(cose, ctx->recipient_context.recipient_key, COSE_algorithm_AES_CCM_16_64_128_KEY_LEN);
    }
  } else { /* coap is response */
    if(sending){
      cose->partial_iv_len = u64tob(ctx->recipient_context.recent_seq, cose->partial_iv);
      cose_encrypt0_set_key_id(cose, ctx->recipient_context.recipient_id, ctx->recipient_context.recipient_id_len);
      cose_encrypt0_set_key(cose, ctx->sender_context.sender_key, COSE_algorithm_AES_CCM_16_64_128_KEY_LEN);
    } else { /* receiving */
      assert(cose->partial_iv_len > 0); /* Partial IV set when getting seq from exchange. */
      cose_encrypt0_set_key_id(cose, ctx->sender_context.sender_id, ctx->sender_context.sender_id_len);
      cose_encrypt0_set_key(cose, ctx->recipient_context.recipient_key, COSE_algorithm_AES_CCM_16_64_128_KEY_LEN);
    }
  }
#endif /* WITH_GROUPCOM */
}

/* Global buffers since oscore_prepare_message() return before message is sent. */
#ifdef WITH_GROUPCOM
uint8_t content_buffer[COAP_MAX_CHUNK_SIZE + COSE_algorithm_AES_CCM_16_64_128_TAG_LEN + ES256_SIGNATURE_LEN];
uint8_t sign_encoded_buffer[100]; //TODO come up with a better way to size buffer
uint8_t option_value_buffer[15];
#endif /* WITH_GROUPCOM */

/* Prepares a new OSCORE message, returns the size of the message. */
size_t
oscore_prepare_message(coap_message_t *coap_pkt, uint8_t *buffer)
{
  cose_encrypt0_t cose[1];
  cose_encrypt0_init(cose);
#ifdef WITH_GROUPCOM
  cose_sign1_t sign[1];
  cose_sign1_init(sign);
#endif /*WITH_GROUPCOM*/

#ifndef WITH_GROUPCOM
  uint8_t option_value_buffer[15]; /* When using Group-OSCORE this has to be global. */
  uint8_t content_buffer[COAP_MAX_CHUNK_SIZE + COSE_algorithm_AES_CCM_16_64_128_TAG_LEN];
#endif /* not WITH_GROUPCOM */
  uint8_t aad_buffer[35];
  uint8_t nonce_buffer[COSE_algorithm_AES_CCM_16_64_128_IV_LEN];

  /*  1 Retrieve the Sender Context associated with the target resource. */
  oscore_ctx_t *ctx = coap_pkt->security_context;
  if(ctx == NULL) {
    LOG_ERR("No context in OSCORE!\n");
    return PACKET_SERIALIZATION_ERROR;
  }
  oscore_populate_cose(coap_pkt, cose, coap_pkt->security_context, true);

  /* 2 Compose the AAD and the plaintext, as described in Sections 5.3 and 5.4.*/
  size_t plaintext_len = oscore_serializer(coap_pkt, content_buffer, ROLE_CONFIDENTIAL);
  if(plaintext_len > COAP_MAX_CHUNK_SIZE){
    LOG_ERR("OSCORE Message to large to process.\n");
    return PACKET_SERIALIZATION_ERROR;
  }

  cose_encrypt0_set_content(cose, content_buffer, plaintext_len);
  
  size_t aad_len = oscore_prepare_aad(coap_pkt, cose, aad_buffer, true);
  cose_encrypt0_set_aad(cose, aad_buffer, aad_len);
 /*3 Compute the AEAD nonce as described in Section 5.2*/ 
  oscore_generate_nonce(cose, coap_pkt, nonce_buffer, COSE_algorithm_AES_CCM_16_64_128_IV_LEN);
  cose_encrypt0_set_nonce(cose, nonce_buffer, COSE_algorithm_AES_CCM_16_64_128_IV_LEN);
  
  if(coap_is_request(coap_pkt)) {
    if(!oscore_set_exchange(coap_pkt->token, coap_pkt->token_len, ctx->sender_context.seq, ctx)) {
      LOG_ERR("OSCORE Could not store exchange.\n");
      return PACKET_SERIALIZATION_ERROR;
    }
    oscore_increment_sender_seq(ctx);
  }
  /*4 Encrypt the COSE object using the Sender Key*/
  /*Groupcomm 4.2: The payload of the OSCORE messages SHALL encode the ciphertext of the COSE object
   * concatenated with the value of the CounterSignature0 of the COSE object as in Appendix A.2 of RFC8152
   * according to the Counter Signature Algorithm and Counter Signature Parameters in the Security Context.*/

  int ciphertext_len = cose_encrypt0_encrypt(cose);
  if(ciphertext_len < 0){
    LOG_ERR("OSCORE internal error %d.\n", ciphertext_len);
    return PACKET_SERIALIZATION_ERROR;
  }
  
  // Partial IV shall NOT be included in responses if not a request
#ifdef WITH_GROUPCOM
  const bool include_partial_iv = true;
#else
  const bool include_partial_iv = coap_is_request(coap_pkt);
#endif
  const uint8_t option_value_len = oscore_encode_option_value(option_value_buffer, cose, include_partial_iv);
  
  coap_set_header_object_security(coap_pkt, option_value_buffer, option_value_len);

#ifdef WITH_GROUPCOM
  int total_len = ciphertext_len + ES256_SIGNATURE_LEN;

  //set the keys and algorithms
  oscore_populate_sign(coap_is_request(coap_pkt), sign, ctx);

  //When we are sending responses the Key-ID in the Signature AAD shall be the REQUEST Key ID.
  if(!coap_is_request(coap_pkt)){ 
    cose_encrypt0_set_key_id(cose, ctx->recipient_context.recipient_id, ctx->recipient_context.recipient_id_len);
  }
  //prepare external_aad structure with algs, params, etc. to later populate the sig_structure
  
  aad_len = oscore_prepare_int(ctx, cose, coap_pkt->object_security, coap_pkt->object_security_len,aad_buffer);
   
  size_t sign_encoded_len = oscore_prepare_sig_structure(sign_encoded_buffer, 
               aad_buffer, aad_len, cose->content, ciphertext_len); 
  memset(&(content_buffer[ciphertext_len]), 0xAA, 64);
//printf("SIGNATURE SHOULD GO HERE %p \n", &(content_buffer[ciphertext_len]));
  cose_sign1_set_signature(sign, &(content_buffer[ciphertext_len]));
  cose_sign1_set_ciphertext(sign, sign_encoded_buffer, sign_encoded_len);
  /* Queue message to sign */
  cose_sign1_sign(sign); //don't care about the result, it will be in progress
  
  coap_set_payload(coap_pkt, content_buffer, total_len);
#else
  coap_set_payload(coap_pkt, content_buffer, ciphertext_len);
#endif /* WITH_GROUPCOM */

  
  /* Overwrite the CoAP code. */
  if(coap_is_request(coap_pkt)) {
    coap_pkt->code = COAP_POST;
  } else {
    coap_pkt->code = CHANGED_2_04;
  }
  oscore_clear_options(coap_pkt);
#ifdef WITH_GROUPCOM
  return 0;
#else
  uint8_t serialized_len = oscore_serializer(coap_pkt, buffer, ROLE_COAP);

  return serialized_len;
#endif
}

/* Creates and sets External AAD */
size_t
oscore_prepare_aad(coap_message_t *coap_pkt, cose_encrypt0_t *cose, uint8_t *buffer, bool sending)
{
  uint8_t external_aad_buffer[25];
  uint8_t *external_aad_ptr = external_aad_buffer;
  uint8_t external_aad_len = 0;
  /* Serialize the External AAD*/
  external_aad_len += cbor_put_array(&external_aad_ptr, 5);
  external_aad_len += cbor_put_unsigned(&external_aad_ptr, 1); /* Version, always for this version of the draft 1 */

#ifdef WITH_GROUPCOM
  if(coap_pkt->security_context->mode == OSCORE_GROUP){
    external_aad_len += cbor_put_array(&external_aad_ptr, 4); /* Algoritms array */
    external_aad_len += cbor_put_unsigned(&external_aad_ptr, coap_pkt->security_context->alg); 
    external_aad_len += cbor_put_negative(&external_aad_ptr, -(coap_pkt->security_context->counter_signature_algorithm)); 
    external_aad_len += cbor_put_unsigned(&external_aad_ptr, (coap_pkt->security_context->counter_signature_parameters)); 
    external_aad_len += cbor_put_array(&external_aad_ptr, 2); /* Countersign Key Parameters array */
    external_aad_len += cbor_put_unsigned(&external_aad_ptr, 26); /*ECDSA_256 Hard coded */ 
    external_aad_len += cbor_put_unsigned(&external_aad_ptr, 1); /*ECDSA_256 Hard coded */ 
  } else {
    external_aad_len += cbor_put_array(&external_aad_ptr, 1); /* Algoritms array */
    external_aad_len += cbor_put_unsigned(&external_aad_ptr, coap_pkt->security_context->alg); /* Algorithm */
  }
#else 
  external_aad_len += cbor_put_array(&external_aad_ptr, 1); /* Algoritms array */
  external_aad_len += cbor_put_unsigned(&external_aad_ptr, coap_pkt->security_context->alg); /* Algorithm */
#endif /*"WITH_GROUPCOM */

  /*When sending responses. */
  if(coap_is_request(coap_pkt)) {
    external_aad_len += cbor_put_bytes(&external_aad_ptr, cose->key_id, cose->key_id_len);
  } else {
    if (sending) {
      external_aad_len += cbor_put_bytes(&external_aad_ptr,
      coap_pkt->security_context->recipient_context.recipient_id,
      coap_pkt->security_context->recipient_context.recipient_id_len);
    } else {
      external_aad_len += cbor_put_bytes(&external_aad_ptr,
        coap_pkt->security_context->sender_context.sender_id,
        coap_pkt->security_context->sender_context.sender_id_len);
    }
  }
  external_aad_len += cbor_put_bytes(&external_aad_ptr, cose->partial_iv, cose->partial_iv_len);  
  external_aad_len += cbor_put_bytes(&external_aad_ptr, NULL, 0); /* Put integrety protected option, at present there are none. */

  assert(external_aad_len <= sizeof(external_aad_buffer));

  uint8_t ret = 0;
  const char* encrypt0 = "Encrypt0";
  /* Begin creating the AAD */
  ret += cbor_put_array(&buffer, 3);
  ret += cbor_put_text(&buffer, encrypt0, strlen(encrypt0));
  ret += cbor_put_bytes(&buffer, NULL, 0);
  ret += cbor_put_bytes(&buffer, external_aad_buffer, external_aad_len);  

  return ret;
}
/* Creates Nonce */
void
oscore_generate_nonce(cose_encrypt0_t *ptr, coap_message_t *coap_pkt, uint8_t *buffer, uint8_t size)
{
  printf_hex_detailed("key_id", ptr->key_id, ptr->key_id_len);
  printf_hex_detailed("partial_iv", ptr->partial_iv, ptr->partial_iv_len);
  printf_hex_detailed("common_iv", coap_pkt->security_context->common_iv, CONTEXT_INIT_VECT_LEN);

  memset(buffer, 0, size);
  buffer[0] = (uint8_t)(ptr->key_id_len);
  memcpy(&(buffer[((size - 5) - ptr->key_id_len)]), ptr->key_id, ptr->key_id_len);
  memcpy(&(buffer[size - ptr->partial_iv_len]), ptr->partial_iv, ptr->partial_iv_len);
  int i;
  for(i = 0; i < size; i++) {
    buffer[i] ^= (uint8_t)coap_pkt->security_context->common_iv[i];
  }

  printf_hex_detailed("result", buffer, size);
}
/*Remove all protected options */
void
oscore_clear_options(coap_message_t *coap_pkt)
{
  coap_pkt->options[COAP_OPTION_IF_MATCH / COAP_OPTION_MAP_SIZE] &= ~(1 << (COAP_OPTION_IF_MATCH % COAP_OPTION_MAP_SIZE));
  /* URI-Host should be unprotected */
  coap_pkt->options[COAP_OPTION_ETAG / COAP_OPTION_MAP_SIZE] &= ~(1 << (COAP_OPTION_ETAG % COAP_OPTION_MAP_SIZE));
  coap_pkt->options[COAP_OPTION_IF_NONE_MATCH / COAP_OPTION_MAP_SIZE] &= ~(1 << (COAP_OPTION_IF_NONE_MATCH % COAP_OPTION_MAP_SIZE));
  /* Observe should be duplicated */
  coap_pkt->options[COAP_OPTION_LOCATION_PATH / COAP_OPTION_MAP_SIZE] &= ~(1 << (COAP_OPTION_LOCATION_PATH % COAP_OPTION_MAP_SIZE));
  coap_pkt->options[COAP_OPTION_URI_PATH / COAP_OPTION_MAP_SIZE] &= ~(1 << (COAP_OPTION_URI_PATH % COAP_OPTION_MAP_SIZE));
  coap_pkt->options[COAP_OPTION_CONTENT_FORMAT / COAP_OPTION_MAP_SIZE] &= ~(1 << (COAP_OPTION_CONTENT_FORMAT % COAP_OPTION_MAP_SIZE));
  /* Max-Age shall me duplicated */
  coap_pkt->options[COAP_OPTION_URI_QUERY / COAP_OPTION_MAP_SIZE] &= ~(1 << (COAP_OPTION_URI_QUERY % COAP_OPTION_MAP_SIZE));
  coap_pkt->options[COAP_OPTION_ACCEPT / COAP_OPTION_MAP_SIZE] &= ~(1 << (COAP_OPTION_ACCEPT % COAP_OPTION_MAP_SIZE));
  coap_pkt->options[COAP_OPTION_LOCATION_QUERY / COAP_OPTION_MAP_SIZE] &= ~(1 << (COAP_OPTION_LOCATION_QUERY % COAP_OPTION_MAP_SIZE));
  /* Block2 should be duplicated */
  /* Block1 should be duplicated */
  /* Size2 should be duplicated */
  /* Proxy-URI should be unprotected */
  /* Proxy-Scheme should be unprotected */
  /* Size1 should be duplicated */
}
/*Return 1 if OK, Error code otherwise */
bool
oscore_validate_sender_seq(oscore_recipient_ctx_t *ctx, cose_encrypt0_t *cose)
{
  int64_t incomming_seq = btou64(cose->partial_iv, cose->partial_iv_len);

  LOG_DBG("Incomming SEQ %" PRIi64 "\n", incomming_seq);

  ctx->rollback_largest_seq = ctx->largest_seq;
  ctx->rollback_sliding_window = ctx->sliding_window;

   /* Special case since we do not use unisgned int for seq */
 /* if(!ctx->initialized) {
      ctx->initialized = 1;
      int shift = incomming_seq - ctx->largest_seq;
      ctx->sliding_window = ctx->sliding_window << shift;
      ctx->sliding_window = ctx->sliding_window | 1;
      ctx->largest_seq = incomming_seq;
      ctx->recent_seq = incomming_seq;
      return 1;
  }
  */
   if(incomming_seq >= OSCORE_SEQ_MAX) {
    LOG_WARN("OSCORE Replay protection, SEQ larger than SEQ_MAX.\n");
    return false;
  }

  if(incomming_seq > ctx->largest_seq) {
    /* Update the replay window */
    int shift = incomming_seq - ctx->largest_seq;
    ctx->sliding_window = ctx->sliding_window << shift;
    ctx->sliding_window = ctx->sliding_window | 1;
    ctx->largest_seq = incomming_seq;
  } else if(incomming_seq == ctx->largest_seq) {
      LOG_WARN("OSCORE Replay protection, replayed SEQ.\n");
      return false;
  } else { /* seq < recipient_seq */
    if(incomming_seq + ctx->replay_window_size < ctx->largest_seq) {
      LOG_WARN("OSCORE Replay protection, SEQ outside of replay window.\n");
      return false;
    }
    /* seq+replay_window_size > recipient_seq */
    int shift = ctx->largest_seq - incomming_seq;
    uint32_t pattern = 1 << shift;
    uint32_t verifier = ctx->sliding_window & pattern;
    verifier = verifier >> shift;
    if(verifier == 1) {
	      LOG_WARN("OSCORE Replay protection, replayed SEQ.\n");
      return false;
    }
    ctx->sliding_window = ctx->sliding_window | pattern;
  }
  ctx->recent_seq = incomming_seq;
  return true;
}
/* Return 0 if SEQ MAX, return 1 if OK */
bool
oscore_increment_sender_seq(oscore_ctx_t *ctx)
{
  LOG_DBG("Incrementing seq to %"PRIu64"\n", ctx->sender_context.seq + 1);

  ctx->sender_context.seq++;
  return ctx->sender_context.seq < OSCORE_SEQ_MAX;
}
/* Restore the sequence number and replay-window to the previous state. This is to be used when decryption fail. */
void
oscore_roll_back_seq(oscore_recipient_ctx_t *ctx)
{
  LOG_DBG("Rolling back seq (window %"PRIu32" = %"PRIi32") (seq %"PRIi64" = %"PRIi64")\n",
    ctx->sliding_window, ctx->rollback_sliding_window,
    ctx->largest_seq, ctx->rollback_largest_seq);

  ctx->sliding_window = ctx->rollback_sliding_window;
  ctx->largest_seq = ctx->rollback_largest_seq;
}

void
oscore_init(void)
{
  oscore_ctx_store_init();

  /* Initialize the security_context storage and the protected resource storage. */
  oscore_exchange_store_init();

#ifdef WITH_GROUPCOM
  oscore_crypto_init();
#endif

  /* Initialize the security_context storage, the token - seq association storrage and the URI - security_context association storage. */
  oscore_ep_ctx_store_init();
}

#ifdef WITH_GROUPCOM
/* Sets alg and keys in COSE SIGN  */
void
oscore_populate_sign(uint8_t coap_is_request, cose_sign1_t *sign, oscore_ctx_t *ctx)
{
  cose_sign1_set_alg(sign, ctx->counter_signature_algorithm,
                     ctx->counter_signature_parameters);
  if (coap_is_request){
    cose_sign1_set_private_key(sign, ctx->recipient_context.private_key); 
    cose_sign1_set_public_key(sign, ctx->recipient_context.public_key);
  } else {
    cose_sign1_set_private_key(sign, ctx->sender_context.private_key); 
    cose_sign1_set_public_key(sign, ctx->sender_context.public_key);
  }
}
//
// oscore_prepare_sig_structure
// creates and sets structure to be signed
size_t
oscore_prepare_sig_structure(uint8_t *sig_ptr,
uint8_t *aad_buffer, uint8_t aad_len,
uint8_t *text, uint8_t text_len)
{
  uint8_t sig_len = 0;
  char countersig0[] = "CounterSignature0";
  sig_len += cbor_put_array(&sig_ptr, 5);
  sig_len += cbor_put_text(&sig_ptr, countersig0, strlen(countersig0));
  sig_len += cbor_put_bytes(&sig_ptr, NULL, 0);
  sig_len += cbor_put_bytes(&sig_ptr, NULL, 0);
  sig_len += cbor_put_bytes(&sig_ptr, 
                  aad_buffer, aad_len); 
  sig_len += cbor_put_bytes(&sig_ptr, text, text_len); 
  return sig_len;
}

size_t
oscore_prepare_int(oscore_ctx_t *ctx, cose_encrypt0_t *cose,     uint8_t *oscore_option, size_t oscore_option_len, uint8_t *external_aad_ptr)
{
  size_t external_aad_len = 0;
  if ((oscore_option_len > 0) && (oscore_option != NULL)){
    external_aad_len += cbor_put_array(&external_aad_ptr, 6);
  }else{
    external_aad_len += cbor_put_array(&external_aad_ptr, 5);
  }
  external_aad_len += cbor_put_unsigned(&external_aad_ptr, 1);
  /* Version, always "1" for this version of the draft */
  if (ctx->mode == OSCORE_SINGLE){
 /* Algoritms array with one item*/
    external_aad_len += cbor_put_array(&external_aad_ptr, 1); 
  /* Encryption Algorithm   */
    external_aad_len += 
           cbor_put_unsigned(&external_aad_ptr, (ctx->alg));
  } else {  /* ctx-> mode == OSCORE_GROUP */
  /* Algoritms array with 4 items */
     external_aad_len += cbor_put_array(&external_aad_ptr, 4);
  /* Encryption Algorithm   */
     external_aad_len += cbor_put_unsigned(&external_aad_ptr, (ctx->alg));     
  /* signature Algorithm */
     external_aad_len += cbor_put_negative(&external_aad_ptr, 
                             -(ctx->counter_signature_algorithm) );
     external_aad_len += cbor_put_unsigned(&external_aad_ptr, 
                             ctx->counter_signature_parameters);
  /* Signature algorithm array */
     external_aad_len += cbor_put_array(&external_aad_ptr, 2);
     external_aad_len += cbor_put_unsigned(&external_aad_ptr, 26); 
     external_aad_len += cbor_put_unsigned(&external_aad_ptr, 1);
/* fill in correct 1 and 6  */
  }
  //Request Key ID should go here
  external_aad_len += cbor_put_bytes(&external_aad_ptr, cose->key_id, cose->key_id_len);
  external_aad_len += cbor_put_bytes(&external_aad_ptr, cose->partial_iv, cose->partial_iv_len);
  external_aad_len += cbor_put_bytes(&external_aad_ptr, NULL, 0); 
if(oscore_option != NULL && oscore_option_len > 0){
  external_aad_len += cbor_put_bytes(&external_aad_ptr, oscore_option, oscore_option_len);
}
  /* Put integrity protected option, at present there are none. */
  return external_aad_len;
}

#endif /*WITH_GROUPCOM*/
