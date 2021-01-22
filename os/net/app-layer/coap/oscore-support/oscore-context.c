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


#include "oscore-context.h"
#include <stddef.h>
#include "lib/memb.h"
#include "lib/list.h"
#include "cbor.h"
#include <string.h>
#include "oscore-crypto.h"
#include "oscore.h"
#include "coap-log.h"

#include <stdio.h>

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "oscore"
#ifdef LOG_CONF_LEVEL_OSCORE
#define LOG_LEVEL LOG_CONF_LEVEL_OSCORE
#else
#define LOG_LEVEL LOG_LEVEL_WARN
#endif

MEMB(exchange_memb, oscore_exchange_t, TOKEN_SEQ_NUM);
MEMB(ep_ctx_memb, ep_ctx_t, EP_CTX_NUM);

LIST(common_context_list);
LIST(exchange_list);
LIST(ep_ctx_list);

void
oscore_ctx_store_init(void)
{
  list_init(common_context_list);
}

static uint8_t
compose_info(
  uint8_t *buffer, uint8_t buffer_len,
  uint8_t alg,
  const uint8_t *id, uint8_t id_len,
  const uint8_t *id_context, uint8_t id_context_len,
  uint8_t out_len)
{
  uint8_t ret = 0;

  // TODO: Needs bounds checking on buffer_len

  ret += cbor_put_array(&buffer, 5);
  ret += cbor_put_bytes(&buffer, id, id_len);
  if(id_context != NULL && id_context_len > 0){
  	ret += cbor_put_bytes(&buffer, id_context, id_context_len);
  } else {
	ret += cbor_put_nil(&buffer); 
  }
  ret += cbor_put_unsigned(&buffer, alg);
  char *text;
  uint8_t text_len;
  if(out_len != 16) {
    text = "IV";
    text_len = 2;
  } else {
    text = "Key";
    text_len = 3;
  }

  ret += cbor_put_text(&buffer, text, text_len);
  ret += cbor_put_unsigned(&buffer, out_len);
  return ret;
}

static bool
bytes_equal(const uint8_t *a_ptr, uint8_t a_len, const uint8_t *b_ptr, uint8_t b_len)
{
  if(a_len != b_len) {
    return false;
  }
  return memcmp(a_ptr, b_ptr, a_len) == 0;
}

#ifdef WITH_GROUPCOM
void
oscore_derive_ctx(oscore_ctx_t *common_ctx,
  const uint8_t *master_secret, uint8_t master_secret_len,
  const uint8_t *master_salt, uint8_t master_salt_len,
  uint8_t alg,
  const uint8_t *sid, uint8_t sid_len,
  const uint8_t *rid, uint8_t rid_len,
  const uint8_t *id_context, uint8_t id_context_len,
  uint8_t replay_window,
  const uint8_t *gid)
#else
void
oscore_derive_ctx(oscore_ctx_t *common_ctx,
  const uint8_t *master_secret, uint8_t master_secret_len,
  const uint8_t *master_salt, uint8_t master_salt_len,
  uint8_t alg,
  const uint8_t *sid, uint8_t sid_len,
  const uint8_t *rid, uint8_t rid_len,
  const uint8_t *id_context, uint8_t id_context_len,
  uint8_t replay_window)
#endif
{
  uint8_t info_buffer[15];
  uint8_t info_len;

  /* sender_ key */
  info_len = compose_info(info_buffer, sizeof(info_buffer), alg, sid, sid_len, id_context, id_context_len, CONTEXT_KEY_LEN);
  hkdf(master_salt, master_salt_len, master_secret, master_secret_len, info_buffer, info_len, common_ctx->sender_context.sender_key, CONTEXT_KEY_LEN);

  /* Receiver key */
  info_len = compose_info(info_buffer, sizeof(info_buffer), alg, rid, rid_len, id_context, id_context_len, CONTEXT_KEY_LEN);
  hkdf(master_salt, master_salt_len, master_secret, master_secret_len, info_buffer, info_len, common_ctx->recipient_context.recipient_key, CONTEXT_KEY_LEN);

  /* common IV */
  info_len = compose_info(info_buffer, sizeof(info_buffer), alg, NULL, 0, id_context, id_context_len, CONTEXT_INIT_VECT_LEN);
  hkdf(master_salt, master_salt_len, master_secret, master_secret_len, info_buffer, info_len, common_ctx->common_iv, CONTEXT_INIT_VECT_LEN);

  common_ctx->master_secret = master_secret;
  common_ctx->master_secret_len = master_secret_len;
  common_ctx->master_salt = master_salt;
  common_ctx->master_salt_len = master_salt_len;
  common_ctx->alg = alg;
  common_ctx->id_context = id_context;
  common_ctx->id_context_len = id_context_len;
#ifdef WITH_GROUPCOM 
  common_ctx->gid = gid;
#endif

  common_ctx->sender_context.sender_id = sid;
  common_ctx->sender_context.sender_id_len = sid_len;
  common_ctx->sender_context.seq = 0;

  common_ctx->recipient_context.recipient_id = rid;
  common_ctx->recipient_context.recipient_id_len = rid_len;
  common_ctx->recipient_context.largest_seq = -1;
  common_ctx->recipient_context.recent_seq = 0;
  common_ctx->recipient_context.replay_window_size = replay_window;
  common_ctx->recipient_context.rollback_largest_seq = 0;
  common_ctx->recipient_context.sliding_window = 0;
  common_ctx->recipient_context.rollback_sliding_window = -1;
  common_ctx->recipient_context.initialized = 0;

  list_add(common_context_list, common_ctx);
}

void
oscore_free_ctx(oscore_ctx_t *ctx)
{
  list_remove(common_context_list, ctx); 
  memset(ctx, 0, sizeof(*ctx));
}

oscore_ctx_t *
oscore_find_ctx_by_rid(const uint8_t *rid, uint8_t rid_len)
{
  oscore_ctx_t *ptr = NULL;
  for(ptr = list_head(common_context_list); ptr != NULL; ptr = list_item_next(ptr)){
    if(bytes_equal(ptr->recipient_context.recipient_id, ptr->recipient_context.recipient_id_len, rid, rid_len) ){
      return ptr;
    }
  }
  return NULL;
} 

/* Token <=> SEQ association */
void
oscore_exchange_store_init(void)
{
  memb_init(&exchange_memb);
  list_init(exchange_list);
}

static oscore_exchange_t*
oscore_get_exchange(const uint8_t *token, uint8_t token_len)
{
  for(oscore_exchange_t *ptr = list_head(exchange_list); ptr != NULL; ptr = list_item_next(ptr)) {
    if(bytes_equal(ptr->token, ptr->token_len, token, token_len)) {
      return ptr;
    }
  }
  return NULL;
}


oscore_ctx_t*
oscore_get_contex_from_exchange(const uint8_t *token, uint8_t token_len, uint64_t *seq)
{
  oscore_exchange_t *ptr = oscore_get_exchange(token, token_len);
  if (ptr) {
    *seq = ptr->seq;
    return ptr->context;
  } else {
    *seq = 0;
    return NULL;
  }
}

bool
oscore_set_exchange(const uint8_t *token, uint8_t token_len, uint64_t seq, oscore_ctx_t *context)
{
  oscore_exchange_t *new_exchange = memb_alloc(&exchange_memb);
  if(new_exchange == NULL){
    LOG_ERR("oscore_set_exchange: out of memory\n");
    return false;
  }

  memcpy(new_exchange->token, token, token_len);
  new_exchange->token_len = token_len;
  new_exchange->seq = seq;
  new_exchange->context = context;

  list_add(exchange_list, new_exchange);
  return true;
}

void
oscore_remove_exchange(const uint8_t *token, uint8_t token_len)
{
  oscore_exchange_t *ptr = oscore_get_exchange(token, token_len);
  if (ptr) {
    list_remove(exchange_list, ptr);
    memb_free(&exchange_memb, ptr);
  }
}
/* URI <=> RID association */
void
oscore_ep_ctx_store_init(void)
{
  memb_init(&ep_ctx_memb);
  list_init(ep_ctx_list);
}

static int
_strcmp(const char *a, const char *b){
  if(a == NULL && b != NULL){
    return -1;
  } else if (a != NULL && b == NULL) {
    return 1;
  } else if (a == NULL && b == NULL) {
    return 0;
  }
  return strcmp(a,b);
}

static ep_ctx_t *
oscore_ep_ctx_find(coap_endpoint_t *ep, const char *uri)
{
  for(ep_ctx_t *ptr = list_head(ep_ctx_list); ptr != NULL; ptr = list_item_next(ptr)) {
    if((coap_endpoint_cmp(ep, ptr->ep) && (_strcmp(uri, ptr->uri) == 0))) {
      return ptr;
    }
  }
  return NULL;
}

bool
oscore_ep_ctx_set_association(coap_endpoint_t *ep, const char *uri, oscore_ctx_t *ctx)
{
  ep_ctx_t *new_ep_ctx;

  new_ep_ctx = oscore_ep_ctx_find(ep, uri);
  if (new_ep_ctx) {
    LOG_INFO("oscore_ep_ctx_set_association: updating existing context 0x%" PRIXPTR " -> 0x%" PRIXPTR "\n",
      (uintptr_t)new_ep_ctx->ctx, (uintptr_t)ctx);
    new_ep_ctx->ctx = ctx;
    return true;
  }

  new_ep_ctx = memb_alloc(&ep_ctx_memb);
  if(new_ep_ctx == NULL) {
    return false;
  }
  new_ep_ctx->ep = ep;
  new_ep_ctx->uri = uri;
  new_ep_ctx->ctx = ctx;
  list_add(ep_ctx_list, new_ep_ctx);
 
  return true;
}

oscore_ctx_t *
oscore_get_context_from_ep(coap_endpoint_t *ep, const char *uri)
{
  ep_ctx_t *ptr = oscore_ep_ctx_find(ep, uri);
  if (ptr) {
    return ptr->ctx;
  }
  return NULL;
}

void oscore_remove_ep_ctx(coap_endpoint_t *ep, const char *uri)
{
  ep_ctx_t *ptr = oscore_ep_ctx_find(ep, uri);
  if (ptr) {
    list_remove(ep_ctx_list, ptr);
    memb_free(&ep_ctx_memb, ptr);
  }
}

#ifdef WITH_GROUPCOM
void
oscore_add_group_keys(oscore_ctx_t *ctx,  
   uint8_t *snd_public_key, 
   uint8_t *snd_private_key,
   uint8_t *rcv_public_key, 
   uint8_t *rcv_private_key,
   int8_t counter_signature_algorithm,
   int8_t counter_signature_parameters)
{
    ctx->counter_signature_algorithm = 
                            counter_signature_algorithm;
    ctx->counter_signature_parameters = 
                            counter_signature_parameters; 
    ctx->mode = OSCORE_GROUP;

    ctx->sender_context.private_key_len    = 0;
    ctx->sender_context.public_key_len     = 0;
    ctx->recipient_context.private_key_len = 0;
    ctx->recipient_context.public_key_len  = 0;

    if (snd_private_key != NULL){
      memcpy(ctx->sender_context.private_key, snd_private_key,  
                                        ES256_PRIVATE_KEY_LEN);
      ctx->sender_context.private_key_len = 
                                         ES256_PRIVATE_KEY_LEN;
    }
    if (snd_public_key != NULL){
      memcpy(ctx->sender_context.public_key, snd_public_key,  
                                        ES256_PUBLIC_KEY_LEN);
      ctx->sender_context.public_key_len = 
                                          ES256_PUBLIC_KEY_LEN;
    }
    if (rcv_private_key != NULL){
      memcpy(ctx->recipient_context.private_key,
                      rcv_private_key, ES256_PRIVATE_KEY_LEN);
      ctx->recipient_context.private_key_len = 
                                         ES256_PRIVATE_KEY_LEN;
    }
    if (rcv_public_key != NULL){
      memcpy(ctx->recipient_context.public_key, rcv_public_key,  
                                        ES256_PUBLIC_KEY_LEN); 
      ctx->recipient_context.public_key_len = 
                                          ES256_PUBLIC_KEY_LEN;
    } 
    /*if (coap_get_log_level() >= LOG_INFO){ 
      int key_len= 0;
      key_len = ctx->sender_context.private_key_len;
      if (key_len > 0) {
        fprintf(stderr,"sender private key:\n");
        for (int qq = 0; qq <key_len; qq++)
             fprintf(stderr,"%02x",
                     ctx->sender_context.private_key[qq]);
        fprintf(stderr,"\n");
      }
      key_len = ctx->sender_context.public_key_len;
      if (key_len > 0) {
        fprintf(stderr,"sender public key:\n");
        for (int qq = 0; qq <key_len; qq++)
             fprintf(stderr,"%02x",
                     ctx->sender_context.public_key[qq]);
        fprintf(stderr,"\n");
      }
      key_len = ctx->recipient_context.private_key_len;
      if (key_len > 0) {
        fprintf(stderr,"recipient private key:\n");
        for (int qq = 0; qq <key_len; qq++)
             fprintf(stderr,"%02x",
                     ctx->recipient_context.private_key[qq]);
        fprintf(stderr,"\n");
      }
      key_len = ctx->recipient_context.public_key_len;
      if (key_len > 0) {
        fprintf(stderr,"recipient public key:\n");
        for (int qq = 0; qq <key_len; qq++)
             fprintf(stderr,"%02x",
                     ctx->recipient_context.public_key[qq]);
        fprintf(stderr,"\n");
      }
    } */ 
}
#endif /* WITH_GROUPCOM */
