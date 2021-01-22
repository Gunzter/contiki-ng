//TODO add copyright statement

#include <stdio.h>

#include "contiki.h"
#include "contiki-net.h"
#include "contiki-lib.h"
#include "lib/assert.h"

#include "oscore-test-vectors.h"
#include "unit-test/unit-test.h"
#include "oscore.h" 
#include "oscore-context.h" 
#include "coap-endpoint.h"

PROCESS(test_process, "6top protocol APIs test");
AUTOSTART_PROCESSES(&test_process);

static void
test_setup(void)
{
  oscore_init_client();
}

UNIT_TEST_REGISTER(test_client_context_derivation,
                   "context_derivation()");
UNIT_TEST(test_client_context_derivation)
{

  UNIT_TEST_BEGIN();
  oscore_ctx_t *ctx  = oscore_derive_ctx(master_secret, master_secret_len, master_salt, master_salt_len, 10, sender_id, sender_id_len, recipient_id, recipient_id_len, NULL, 0, OSCORE_DEFAULT_REPLAY_WINDOW);
  UNIT_TEST_ASSERT(ctx != NULL);
  UNIT_TEST_ASSERT(memcmp(ctx->common_iv, client_common_iv, CONTEXT_INIT_VECT_LEN) == 0);
  UNIT_TEST_ASSERT(memcmp(ctx->sender_context->sender_key, client_sender_key,CONTEXT_KEY_LEN) == 0);
  UNIT_TEST_ASSERT(memcmp(ctx->recipient_context->recipient_key, client_recipient_key,CONTEXT_KEY_LEN) == 0);
  
  UNIT_TEST_ASSERT(ctx->sender_context->sender_id_len == 0);
  UNIT_TEST_ASSERT(ctx->recipient_context->recipient_id_len == 1);
 
  oscore_free_ctx(ctx);
 
  ctx = oscore_derive_ctx(master_secret_2, master_secret_2_len, NULL, 0, 10, sender_id_2, sender_id_2_len, recipient_id, recipient_id_len, NULL, 0, OSCORE_DEFAULT_REPLAY_WINDOW);
  UNIT_TEST_ASSERT(ctx != NULL);
  
  UNIT_TEST_ASSERT(memcmp(ctx->common_iv, client_common_iv_no_salt, CONTEXT_INIT_VECT_LEN) == 0);
  UNIT_TEST_ASSERT(memcmp(ctx->sender_context->sender_key, client_sender_key_no_salt, CONTEXT_KEY_LEN) == 0);
  UNIT_TEST_ASSERT(memcmp(ctx->recipient_context->recipient_key, client_recipient_key_no_salt, CONTEXT_KEY_LEN) == 0);
  
  UNIT_TEST_ASSERT(ctx->sender_context->sender_id_len == 1);
  UNIT_TEST_ASSERT(ctx->recipient_context->recipient_id_len == 1);
 

  UNIT_TEST_END();
}

UNIT_TEST_REGISTER(test_get_context, "get_context()");
UNIT_TEST(test_get_context){
  UNIT_TEST_BEGIN();
  
  oscore_ctx_t *ctx = NULL;
  ctx = oscore_find_ctx_by_rid(recipient_id, recipient_id_len);
  UNIT_TEST_ASSERT(ctx != NULL);
  UNIT_TEST_ASSERT(memcmp(recipient_id, ctx->recipient_context->recipient_id, recipient_id_len) == 0);

  UNIT_TEST_END();
}


UNIT_TEST_REGISTER(test_exchange_storage, "test_exchange_storage()");
UNIT_TEST(test_exchange_storage){
  UNIT_TEST_BEGIN();
  uint8_t token_1[4] = { 0xAA, 0xAB, 0xAC, 0xAD };
  uint8_t token_2[5] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
  uint8_t token_3[1] = { 0x00 };
  uint64_t seq_1 = 5;
  uint64_t seq_2 = 9999;
  uint64_t seq_3 = 1;
  oscore_ctx_t ctx_1[1];
  oscore_ctx_t ctx_2[1];
  oscore_ctx_t ctx_3[1];

  UNIT_TEST_ASSERT(TOKEN_SEQ_NUM == 2);  

  int ret = oscore_set_exchange(token_1, 4, seq_1, ctx_1);
  UNIT_TEST_ASSERT(ret == 1);
  
  ret = oscore_set_exchange(token_2, 5, seq_2, ctx_2);
  UNIT_TEST_ASSERT(ret == 1);
  
  uint64_t seq_1_ptr; 
  oscore_ctx_t *ctx_ptr_1 = oscore_get_contex_from_exchange(token_1, 4, &seq_1_ptr);
  UNIT_TEST_ASSERT(ctx_ptr_1 == ctx_1);

  uint64_t seq_2_ptr; 
  oscore_ctx_t *ctx_ptr_2 = oscore_get_contex_from_exchange(token_2, 5, &seq_2_ptr);
  UNIT_TEST_ASSERT(ctx_ptr_2 == ctx_2);
   
    /* Test to fetch non-existing exchange. */
  oscore_remove_exchange(token_1, 4);
  ctx_ptr_1 = oscore_get_contex_from_exchange(token_1, 4, &seq_1_ptr);
  UNIT_TEST_ASSERT(ctx_ptr_1 == NULL);
  UNIT_TEST_ASSERT(seq_1_ptr == 0); 
 
  ret = oscore_set_exchange(token_3,1, seq_3, ctx_3); 
  UNIT_TEST_ASSERT(ret == 1);

  uint64_t seq_3_ptr;
  oscore_ctx_t *ctx_ptr_3 = oscore_get_contex_from_exchange(token_3, 1, &seq_3_ptr);
  UNIT_TEST_ASSERT( ctx_ptr_3 == ctx_3);
 
  ctx_ptr_2 = oscore_get_contex_from_exchange(token_2, 5, &seq_2_ptr);
  UNIT_TEST_ASSERT(ctx_ptr_2 == ctx_2);
  

  oscore_remove_exchange(token_1, 4);
  oscore_remove_exchange(token_2, 5);
  oscore_remove_exchange(token_3, 1);

  ctx_ptr_1 = oscore_get_contex_from_exchange(token_1, 4, &seq_1_ptr);
  UNIT_TEST_ASSERT( ctx_ptr_1 == 0);
  ctx_ptr_2 = oscore_get_contex_from_exchange(token_2, 5, &seq_2_ptr);
  UNIT_TEST_ASSERT( ctx_ptr_2 == 0);
  ctx_ptr_3 = oscore_get_contex_from_exchange(token_3, 1, &seq_3_ptr);
  UNIT_TEST_ASSERT( ctx_ptr_3 == 0);

  UNIT_TEST_END();
}


UNIT_TEST_REGISTER(test_endpoint_uri_context, "test_endpoint_uri_context()");
UNIT_TEST(test_endpoint_uri_context){
  UNIT_TEST_BEGIN();
  char* ip_1 = "coap://[fe80::202:0000:0000:0001]"; 
  char* ip_2 = "coap://[fe80::202:0000:0000:0002]"; 
  char* ip_3 = "coap://[fe80::202:0000:0000:0003]"; 
  char* uri_1 = "test/hello";
  char* uri_2 = "test/";
  char* uri_3 = "/not/found";
  coap_endpoint_t ep_1;
  coap_endpoint_t ep_2;
  coap_endpoint_t ep_3;
  /* Static stored contexts, the contents of the context are not important here. */
  oscore_ctx_t ctx_1[1];
  oscore_ctx_t ctx_2[1];
  oscore_ctx_t ctx_3[1];
  
  UNIT_TEST_ASSERT(EP_CTX_NUM == 2); 
  
  coap_endpoint_parse(ip_1, strlen(ip_1), &ep_1); 
  coap_endpoint_parse(ip_2, strlen(ip_2), &ep_2); 
  coap_endpoint_parse(ip_3, strlen(ip_3), &ep_3); 
  oscore_ep_ctx_store_init();

  int ret = oscore_ep_ctx_set_association(&ep_1, uri_1, ctx_1);  
  UNIT_TEST_ASSERT(ret == 1);
  ret = oscore_ep_ctx_set_association(&ep_2, uri_2, ctx_2);  
  UNIT_TEST_ASSERT(ret == 1);
 
  char* uri_1_fetch = "test/hello";
  char* uri_2_fetch = "test/";
  char* uri_3_fetch = "/not/found";
 
  oscore_ctx_t *ctx_ptr = oscore_get_context_from_ep(&ep_1, uri_1);
  UNIT_TEST_ASSERT( ctx_ptr == ctx_1 ); 
  ctx_ptr = oscore_get_context_from_ep(&ep_2, uri_2_fetch);
  UNIT_TEST_ASSERT( ctx_ptr == ctx_2);

  /* Test to add to full ep-ctx database. Oldest entry is removed to make room for a new.*/ 
  ret = oscore_ep_ctx_set_association(&ep_3, uri_3, ctx_3);  
  UNIT_TEST_ASSERT(ret == 1);

  ctx_ptr = oscore_get_context_from_ep(&ep_2, uri_2_fetch);
  UNIT_TEST_ASSERT( ctx_ptr == ctx_2);

  ctx_ptr = oscore_get_context_from_ep(&ep_3, uri_3_fetch);
  UNIT_TEST_ASSERT( ctx_ptr == ctx_3);

  oscore_remove_ep_ctx(&ep_1, uri_1);
  oscore_remove_ep_ctx(&ep_2, uri_2);
  oscore_remove_ep_ctx(&ep_3, uri_3);

  ctx_ptr = oscore_get_context_from_ep(&ep_1, uri_1_fetch);
  UNIT_TEST_ASSERT( ctx_ptr == NULL);
  ctx_ptr = oscore_get_context_from_ep(&ep_2, uri_2_fetch);
  UNIT_TEST_ASSERT( ctx_ptr == NULL);
  ctx_ptr = oscore_get_context_from_ep(&ep_3, uri_3_fetch);
  UNIT_TEST_ASSERT( ctx_ptr == NULL);


  UNIT_TEST_END();
}

PROCESS_THREAD(test_process, ev, data)
{

  PROCESS_BEGIN();
  test_setup();
  printf("Run unit-test\n");
  printf("---\n");
  UNIT_TEST_RUN(test_client_context_derivation);
  UNIT_TEST_RUN(test_get_context);
  UNIT_TEST_RUN(test_exchange_storage);
  UNIT_TEST_RUN(test_endpoint_uri_context);
  printf("=check-me= DONE\n");
  PROCESS_END();
}


