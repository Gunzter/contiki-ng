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

#include "oscore-association.h"

#ifdef OSCORE_EP_CTX_ASSOCIATION

typedef struct ep_ctx {
  struct ep_ctx *next;
  coap_endpoint_t *ep;
  const char *uri;
  oscore_ctx_t *ctx;
} ep_ctx_t;

MEMB(ep_ctx_memb, ep_ctx_t, EP_CTX_NUM);
LIST(ep_ctx_list);

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
    LOG_ERR("oscore_ep_ctx_set_association: out of memory\n");
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

#endif
