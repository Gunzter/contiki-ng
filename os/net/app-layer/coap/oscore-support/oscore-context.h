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

#ifndef _OSCORE_CONTEXT_H
#define _OSCORE_CONTEXT_H

#include <inttypes.h>

#include "coap-constants.h"
#include "coap-endpoint.h"
#include "cose.h"

#include "sliding-window.h"

#include "sliding-window.h"

#define CONTEXT_KEY_LEN 16
#define CONTEXT_INIT_VECT_LEN 13
#define CONTEXT_SEQ_LEN sizeof(uint64_t)

#ifndef TOKEN_SEQ_NUM
#define TOKEN_SEQ_NUM 30
#endif

typedef struct oscore_sender_ctx {
  uint8_t sender_key[CONTEXT_KEY_LEN];
  uint64_t seq;
  const uint8_t *sender_id;
  uint8_t sender_id_len;

#ifdef WITH_GROUPCOM
  const uint8_t *public_key;
  const uint8_t *private_key;
  COSE_Elliptic_Curves_t curve;
#endif /* WITH_GROUPCOM */

} oscore_sender_ctx_t;

typedef struct oscore_recipient_ctx {
  uint8_t recipient_key[CONTEXT_KEY_LEN];
  const uint8_t *recipient_id;
  uint8_t recipient_id_len;

#ifdef WITH_GROUPCOM
  const uint8_t *public_key;
  COSE_Elliptic_Curves_t curve;
  //struct oscore_recipient_ctx *next_recipient; /* This field allows recipient chaining */
#endif /* WITH_GROUPCOM */

  oscore_sliding_window_t sliding_window;
} oscore_recipient_ctx_t;

typedef struct oscore_ctx {
  struct oscore_ctx *next;
  const uint8_t *master_secret;
  uint8_t common_iv[CONTEXT_INIT_VECT_LEN];
  uint8_t master_secret_len;
  uint8_t alg;

#ifdef WITH_GROUPCOM
  const uint8_t *gid;
  oscore_recipient_ctx_t *recipient_chain;
  int8_t counter_signature_algorithm;
  int8_t counter_signature_parameters;
  uint8_t mode;   /* OSCORE_SINGLE or OSCORE_GROUP  */
#endif /* WITH_GROUPCOM */

  oscore_sender_ctx_t sender_context;
  oscore_recipient_ctx_t recipient_context;
} oscore_ctx_t;

typedef struct oscore_exchange {
  struct oscore_exchange *next;
  oscore_ctx_t *context;
  uint64_t seq;
  uint8_t token[COAP_TOKEN_LEN];
  uint8_t token_len;
} oscore_exchange_t;

void oscore_ctx_store_init(void);

#ifdef WITH_GROUPCOM
void
oscore_add_group_keys(oscore_ctx_t *ctx,  
   const uint8_t *snd_public_key,
   const uint8_t *snd_private_key,
   const uint8_t *rcv_public_key,
   COSE_ECDSA_Algorithms_t counter_signature_algorithm,
   COSE_Elliptic_Curves_t counter_signature_parameters);

oscore_recipient_ctx_t *
oscore_add_recipient(oscore_ctx_t *ctx, 
        uint8_t *rid, uint8_t rid_len);

void oscore_derive_ctx(oscore_ctx_t *common_ctx,
  const uint8_t *master_secret, uint8_t master_secret_len,
  const uint8_t *master_salt, uint8_t master_salt_len,
  uint8_t alg,
  const uint8_t *sid, uint8_t sid_len,
  const uint8_t *rid, uint8_t rid_len,
  const uint8_t *id_context, uint8_t id_context_len,
  const uint8_t *gid);
#else
void oscore_derive_ctx(oscore_ctx_t *common_ctx,
  const uint8_t *master_secret, uint8_t master_secret_len,
  const uint8_t *master_salt, uint8_t master_salt_len,
  uint8_t alg,
  const uint8_t *sid, uint8_t sid_len,
  const uint8_t *rid, uint8_t rid_len,
  const uint8_t *id_context, uint8_t id_context_len);
#endif

void oscore_free_ctx(oscore_ctx_t *ctx);

oscore_ctx_t *oscore_find_ctx_by_rid(const uint8_t *rid, uint8_t rid_len);

/* Token <=> SEQ association */
void oscore_exchange_store_init(void);
bool oscore_set_exchange(const uint8_t *token, uint8_t token_len, uint64_t seq, oscore_ctx_t *context);
oscore_exchange_t* oscore_get_exchange(const uint8_t *token, uint8_t token_len);
void oscore_remove_exchange(const uint8_t *token, uint8_t token_len);

#endif /* _OSCORE_CONTEXT_H */
