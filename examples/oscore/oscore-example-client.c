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
 *      OSCORE client example.
 * \author
 *      Martin Gunnarsson <martin.gunnarsson@ri.se>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"
#include "contiki-net.h"
#include "coap-engine.h"
#include "coap-blocking-api.h"
#if PLATFORM_SUPPORTS_BUTTON_HAL
#include "dev/button-hal.h"
#else
#include "dev/button-sensor.h"
#endif

#ifdef WITH_OSCORE
#include "oscore.h"
/* Key material, sender-ID and receiver-ID used for deriving an OSCORE-Security-Context. Note that Sender-ID and Receiver-ID is 
 * mirrored in the Client and Server. */
uint8_t master_secret[35] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23};
uint8_t salt[8] = {0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40}; 
uint8_t sender_id[] = { 0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74 };
uint8_t receiver_id[] = { 0x73, 0x65, 0x72, 0x76, 0x65, 0x72 };
#endif /* WITH_OSCORE */

/* Log configuration */
#include "coap-log.h"
#define LOG_MODULE "client"
#define LOG_LEVEL  LOG_LEVEL_COAP

#define TOGGLE_INTERVAL 10

/* FIXME: This server address is hard-coded for Cooja and link-local for unconnected border router. */
//#define SERVER_EP "coap://[fe80::212:7402:0002:0202]"
//#define SERVER_EP "coap://[fe80::202:0002:0002:0002]"
#define SERVER_EP "coap://[aaaa::1]"

PROCESS(er_example_client, "OSCORE Example Client");
AUTOSTART_PROCESSES(&er_example_client);

static struct etimer et;

/* Example URIs that can be queried. */
#define NUMBER_OF_URLS 4
/* leading and ending slashes only for demo purposes, get cropped automatically when setting the Uri-Path */
char *service_urls[NUMBER_OF_URLS] =
{ ".well-known/core", "test/hello", "battery/", "error/in//path" };
#if PLATFORM_HAS_BUTTON
static int uri_switch = 0;
#endif

/* This function is will be passed to COAP_BLOCKING_REQUEST() to handle responses. */
void
client_chunk_handler(coap_message_t *response)
{
  const uint8_t *chunk;

  int len = coap_get_payload(response, &chunk);
  printf("response: \n");
  printf("|%.*s", len, (char *)chunk);
}

PROCESS_THREAD(er_example_client, ev, data)
{
  PROCESS_BEGIN();

  static coap_message_t request[1];      /* This way the packet can be treated as pointer as usual. */
  static coap_endpoint_t server_ep;

  coap_endpoint_parse(SERVER_EP, strlen(SERVER_EP), &server_ep);

  #ifdef WITH_OSCORE
  /*Derive an OSCORE-Security-Context. */
  static oscore_ctx_t context;
  oscore_derive_ctx(&context, master_secret, 35, NULL, 0, 10, sender_id, 6, receiver_id, 6, NULL, 0);

  /* Set the association between a remote URL and a security contect. When sending a message the specified context will be used to 
   * protect the message. Note that this can be done on a resource-by-resource basis. Thus any requests to .well-known/core will not 
   * be OSCORE protected.*/  
  oscore_ep_ctx_set_association(&server_ep, service_urls[1], &context);
  oscore_ep_ctx_set_association(&server_ep, service_urls[2], &context);

  #endif /* WITH_OSCORE */

  etimer_set(&et, TOGGLE_INTERVAL * CLOCK_SECOND);
  
 #if PLATFORM_HAS_BUTTON
#if !PLATFORM_SUPPORTS_BUTTON_HAL
  SENSORS_ACTIVATE(button_sensor);
#endif
  LOG_INFO("Press a button to request %s\n", service_urls[uri_switch]);
#endif /* PLATFORM_HAS_BUTTON */

  while(1) {
    PROCESS_YIELD();

    if(etimer_expired(&et)) {
      LOG_DBG("--Toggle timer--\n");

      /* prepare request, TID is set by COAP_BLOCKING_REQUEST() */
      coap_init_message(request, COAP_TYPE_CON, COAP_POST, 0);
      coap_set_header_uri_path(request, service_urls[1]);

      const char msg[] = "Toggle!";

      coap_set_payload(request, (uint8_t *)msg, sizeof(msg) - 1);

      LOG_INFO_COAP_EP(&server_ep);
      LOG_INFO_("\n");

      COAP_BLOCKING_REQUEST(&server_ep, request, client_chunk_handler);

      printf("\n--Done--\n");

      etimer_reset(&et);

#if PLATFORM_HAS_BUTTON
#if PLATFORM_SUPPORTS_BUTTON_HAL
    } else if(ev == button_hal_release_event) {
#else
    } else if(ev == sensors_event && data == &button_sensor) {
#endif

      /* send a request to notify the end of the process */

      coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
      coap_set_header_uri_path(request, service_urls[uri_switch]);

      printf("--Requesting %s--\n", service_urls[uri_switch]);

      LOG_INFO_COAP_EP(&server_ep);
      LOG_INFO_("\n");

      COAP_BLOCKING_REQUEST(&server_ep, request,
                            client_chunk_handler);

      printf("\n--Done--\n");

      uri_switch = (uri_switch + 1) % NUMBER_OF_URLS;
#endif /* PLATFORM_HAS_BUTTON */
    }
  }

  PROCESS_END();
}
 
