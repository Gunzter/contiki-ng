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
 *      An implementation of the Object Security for Constrained RESTful Enviornments (Internet-Draft-15).
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 *
 */


#ifndef _OSCORE_H
#define _OSCORE_H

#include "coap.h"
#include "cose.h"
#include "oscore-context.h"
#include "coap-engine.h"

#include <stdbool.h>
#include <stdint.h>

#define OSCORE_SINGLE 0
#define OSCORE_GROUP 1

/*
 * The maximum length of Sender ID in
 * bytes equals the length of the AEAD nonce minus 6
 * https://tools.ietf.org/html/rfc8613#section-3.3
 */
#define OSCORE_SENDER_ID_MAX_LEN(NONE_LENGTH) (NONE_LENGTH - 6)
#define OSCORE_SENDER_ID_MAX_SUPPORTED_LEN OSCORE_SENDER_ID_MAX_LEN(COSE_LARGEST_IV_LENGTH)

size_t oscore_serializer(coap_message_t *coap_pkt, uint8_t *buffer, uint8_t role);
coap_status_t oscore_parser(coap_message_t *coap_pkt, uint8_t *data, uint16_t data_len, uint8_t role);

/* Decodes a OSCORE message and passes it on to the COAP engine. */
coap_status_t oscore_decode_message(coap_message_t *coap_pkt);

/*Decodes the OSCORE option value and places decoded values into the provided code structure */
coap_status_t oscore_decode_option_value(uint8_t *option_value, int option_len, cose_encrypt0_t *cose);

/* Prepares a new OSCORE message, returns the size of the message. */
size_t oscore_prepare_message(coap_message_t *coap_pkt, uint8_t *buffer);

/* Creates Nonce */
void oscore_generate_nonce(const cose_encrypt0_t *ptr, const coap_message_t *coap_pkt, uint8_t *buffer, uint8_t size);

/* Remove all protected options */
void oscore_clear_options(coap_message_t *ptr);

/* Return 0 if SEQ MAX, return 1 if OK */
bool oscore_increment_sender_seq(oscore_ctx_t *ctx);

/* Mark a resource as protected by OSCORE, incoming COAP requests to that resource will be rejected. */
void oscore_protect_resource(coap_resource_t *resource);
bool oscore_is_resource_protected(const coap_resource_t *resource);

/* Retuns 1 if the resource is protected by OSCORE, 0 otherwise. */
bool oscore_is_request_protected(const coap_message_t *request);

/* Initialize the context storage and the protected resource storage. */
/* Initialize the context storage, the token - seq association storrage and the URI - context association storage. */
void oscore_init(void);

#endif /* _OSCORE_H */
