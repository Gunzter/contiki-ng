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

/**
 * \file
 *      OSCORE interops server, tests specified according to https://raw.githubusercontent.com/EricssonResearch/OSCOAP/master/test-spec5.md .
 * \author
 *      Martin Gunnarsson <martin.gunnarsson@ri.se>
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"
#include "contiki-net.h"
#include "coap.h"
#include "coap-transactions.h"
#include "coap-separate.h"
#include "coap-engine.h"
#include "oscore.h"

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define PRINTF(...)
#endif

/*
 * Resources to be activated need to be imported through the extern keyword.
 * The build system automatically compiles the resources in the corresponding
 * sub-directory.
 */
extern coap_resource_t
  res_hello,
  res_hello1,
  res_hello2,
  res_hello3,
  res_hello6,
  res_hello7,
  res_test;

uint8_t master_secret[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
uint8_t salt[8] = {0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40};
uint8_t *receiver_id = NULL;
uint8_t sender_id[1] = { 0x01};
//uint8_t id_context[8] = {0x37, 0xcb, 0xf3, 0x21, 0x00, 0x17, 0xa2, 0xd3};

PROCESS(plugtest_server, "OSCORE interops server");
AUTOSTART_PROCESSES(&plugtest_server);

PROCESS_THREAD(plugtest_server, ev, data)
{
  PROCESS_BEGIN();

  PROCESS_PAUSE();

  PRINTF("OSCORE Plugtests Server\n");

  static oscore_ctx_t context;
  oscore_derive_ctx(&context, master_secret, 16, salt, 8, 10, sender_id, 1, receiver_id, 0, NULL, 0);
  //oscore_derive_ctx(&context, master_secret, 16, salt, 8, 10, sender_id, 1, receiver_id, 0, id_context, 8);

  uint8_t *key_id = NULL;
  oscore_ctx_t *ctx;
  ctx = oscore_find_ctx_by_rid(key_id, 0);
  if(ctx == NULL){
    printf("CONTEXT NOT FOUND\n");
  }else {
    printf("context FOUND!\n");
  }

  /* Activate the application-specific resources. */
  coap_activate_resource(&res_hello, "oscore/hello/coap");
  coap_activate_resource(&res_hello1, "oscore/hello/1");
  coap_activate_resource(&res_hello2, "oscore/hello/2");
  coap_activate_resource(&res_hello3, "oscore/hello/3");
  coap_activate_resource(&res_hello6, "oscore/hello/6");
  coap_activate_resource(&res_hello7, "oscore/hello/7");
  coap_activate_resource(&res_test,   "oscore/test");
  
  oscore_protect_resource(&res_hello1);
  oscore_protect_resource(&res_hello2);
  oscore_protect_resource(&res_hello3);
  oscore_protect_resource(&res_hello6);
  oscore_protect_resource(&res_hello7);
  oscore_protect_resource(&res_test);
  /* Define application-specific events here. */
  while(1) {
    PROCESS_WAIT_EVENT();
  }                             /* while (1) */

  PROCESS_END();
}
