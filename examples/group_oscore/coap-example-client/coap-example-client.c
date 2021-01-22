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
 *      Erbium (Er) CoAP client example.
 * \author
 *      Matthias Kovatsch <kovatsch@inf.ethz.ch>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"
#include "contiki-net.h"
#include "coap-engine.h"
#include "coap-callback-api.h"

#include "ipv6/simple-udp.h"
#include "net/ipv6/multicast/uip-mcast6.h"


/* Log configuration */
#include "coap-log.h"
#define LOG_MODULE "App"
#define LOG_LEVEL  LOG_LEVEL_APP

/* FIXME: This server address is hard-coded for Cooja and link-local for unconnected border router. */
//#define SERVER_EP "coap://[ff1e::89:abcd]"

#define TOGGLE_INTERVAL 10

PROCESS(er_example_client, "Erbium Example Client");
AUTOSTART_PROCESSES(&er_example_client);

static struct etimer et;
static struct uip_udp_conn *conn = NULL;

char *service_urls[] =
{"/test/hello", "/test/mcastq", "/test/hello", "/test/mcast"};

/* This function is will be passed to COAP_BLOCKING_REQUEST() to handle responses. */
void
client_chunk_handler(coap_message_t *response)
{
  const uint8_t *chunk;

  int len = coap_get_payload(response, &chunk);

  printf("|%.*s", len, (char *)chunk);
}

/*This function will be called when the response arrives or the timeout expires*/
void my_callback_f(coap_callback_request_state_t *callback_state)
{
  printf("Callback called!\n");
  return;
}

PROCESS_THREAD(er_example_client, ev, data)
{
//  static coap_endpoint_t server_ep;
  PROCESS_BEGIN();
   
//  static coap_message_t request[1];      /* This way the packet can be treated as pointer as usual. */
//   coap_endpoint_parse(SERVER_EP, strlen(SERVER_EP), &server_ep);

  static uip_ipaddr_t udp_addr;
//  char *ip_str = "[ff02::1]";
  //char *ip_str = "[ff1e::89:abcd]";
  //char *ip_str = "[fd00::212:4b00:14b5:d8fb]";
  //uiplib_ipaddrconv(ip_str, &udp_addr); 
  //uip_ip6addr(&udp_addr, 0xFD00,0,0,0,0x212,0x4b00,0x14b5,0xd8fb);
  uip_ip6addr(&udp_addr, 0xFF1E,0,0,0,0,0,0x89,0xABCD);
  printf("udp_addr\n");
  uiplib_ipaddr_print(&udp_addr);
  printf("\n");

  printf("Multicast Engine: '%s'\n", UIP_MCAST6.name);



  conn = udp_new(NULL, 0, NULL);
  if(conn == NULL){
	printf("Could not allocate conn\n");
  }

  static uint8_t payload[24] = {0xFF}; 
  
  uip_udp_packet_sendto(conn, payload, 15, &udp_addr, UIP_HTONS(5684)); 
  printf("sent?\n");
  etimer_set(&et, TOGGLE_INTERVAL * CLOCK_SECOND);

  while(1) {
    PROCESS_YIELD();

    if(etimer_expired(&et)) {
      printf("--Toggle timer--\n");

      /* prepare a non-blocking, NON confirmable request */
      //coap_init_message(request, COAP_TYPE_NON, COAP_GET, 0);
      //coap_set_header_uri_path(request, service_urls[0]);

      uip_udp_packet_sendto(conn, payload, 15, &udp_addr, UIP_HTONS(5684)); 
      printf("sent?\n");
      
      etimer_reset(&et);
    }
  }

  PROCESS_END();
}
