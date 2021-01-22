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
#include "cose.h"

PROCESS(test_process, "6top protocol APIs test");
AUTOSTART_PROCESSES(&test_process);

static void
test_setup(void)
{
  oscore_init_client();
}

UNIT_TEST_REGISTER(test_validate_sender_seq,
                   "validate_sender_seq()");
UNIT_TEST(test_validate_sender_seq)
{

  UNIT_TEST_BEGIN();
  cose_encrypt0_t cose[1];
  uint8_t seq_0[1] = { 0x00 };
  uint8_t seq_1[1] = { 0x01 };
  uint8_t seq_3[1] = { 0x03 };
  uint8_t seq_5[1] = { 0x05 };
  uint8_t seq_8[1] = { 0x08 };
  uint8_t seq_50[1] = { 0x32 };
  uint8_t seq_60[1] = { 0x3C };
  uint8_t seq_under_max[8] = { 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE }; /* ((1 << 40) - 2)*/
  uint8_t seq_max[8] = { 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }; /* ((1 << 40) - 1)*/
  uint8_t seq_over_max[8] = { 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 }; /* ((1 << 40)) */
  

  oscore_ctx_t *ctx  = oscore_derive_ctx(master_secret, master_secret_len, master_salt, master_salt_len, 10, sender_id, sender_id_len, recipient_id, recipient_id_len, NULL, 0, OSCORE_DEFAULT_REPLAY_WINDOW);
  UNIT_TEST_ASSERT(ctx != NULL);

  oscore_recipient_ctx_t *r_ctx = ctx->recipient_context;
  
  cose_encrypt0_set_partial_iv(cose, seq_0, sizeof(seq_0));  
   
  uint8_t ret = oscore_validate_sender_seq(r_ctx, cose);
  UNIT_TEST_ASSERT(ret == 1);

  /* Test seq 1. */
  cose_encrypt0_set_partial_iv(cose, seq_1, sizeof(seq_1));  
  ret = oscore_validate_sender_seq(r_ctx, cose);
  UNIT_TEST_ASSERT(ret == 1);

  /* Test seq 1 again (replay). */
  cose_encrypt0_set_partial_iv(cose, seq_1, sizeof(seq_1));  
  ret = oscore_validate_sender_seq(r_ctx, cose);
  UNIT_TEST_ASSERT(ret != 1);

  
  /* Test seq 5, then seq 3. Test replay window. */
  cose_encrypt0_set_partial_iv(cose, seq_5, sizeof(seq_5));  
  ret = oscore_validate_sender_seq(r_ctx, cose);
  UNIT_TEST_ASSERT(ret == 1);

  cose_encrypt0_set_partial_iv(cose, seq_3, sizeof(seq_3));  
  ret = oscore_validate_sender_seq(r_ctx, cose);
  UNIT_TEST_ASSERT(ret == 1);

  /* Test seq 60, 50 (within replay window), then seq 8, outside replay window -> reject seq. */
  cose_encrypt0_set_partial_iv(cose, seq_60, sizeof(seq_60));  
  ret = oscore_validate_sender_seq(r_ctx, cose);
  UNIT_TEST_ASSERT(ret == 1);

  cose_encrypt0_set_partial_iv(cose, seq_50, sizeof(seq_50));  
  ret = oscore_validate_sender_seq(r_ctx, cose);
  UNIT_TEST_ASSERT(ret == 1);

  cose_encrypt0_set_partial_iv(cose, seq_8, sizeof(seq_8));  
  ret = oscore_validate_sender_seq(r_ctx, cose);
  UNIT_TEST_ASSERT(ret != 1);

  cose_encrypt0_set_partial_iv(cose, seq_under_max, sizeof(seq_max));  
  ret = oscore_validate_sender_seq(r_ctx, cose);
  UNIT_TEST_ASSERT(ret == 1);

  cose_encrypt0_set_partial_iv(cose, seq_max, sizeof(seq_max));  
  ret = oscore_validate_sender_seq(r_ctx, cose);
  UNIT_TEST_ASSERT(ret != 1);
  
  cose_encrypt0_set_partial_iv(cose, seq_over_max, sizeof(seq_over_max));  
  ret = oscore_validate_sender_seq(r_ctx, cose);
  UNIT_TEST_ASSERT(ret != 1);

  oscore_free_ctx(ctx);

  UNIT_TEST_END();
}

UNIT_TEST_REGISTER(test_rollback_seq,
                   "rollback_seq()");
UNIT_TEST(test_rollback_seq)
{

  UNIT_TEST_BEGIN();
  cose_encrypt0_t cose[1];
  uint8_t seq_0[1] = { 0x00 };
  uint8_t seq_1[1] = { 0x01 };
  uint8_t seq_2[1] = { 0x0F };
  uint8_t seq_3[1] = { 0x12 };

  oscore_ctx_t *ctx  = oscore_derive_ctx(master_secret, master_secret_len, master_salt, master_salt_len, 10, sender_id, sender_id_len, recipient_id, recipient_id_len, NULL, 0, OSCORE_DEFAULT_REPLAY_WINDOW);
  UNIT_TEST_ASSERT(ctx != NULL);

  oscore_recipient_ctx_t *r_ctx = ctx->recipient_context;
  
  /* Set seq 0. */
  cose_encrypt0_set_partial_iv(cose, seq_0, sizeof(seq_0));  
  uint8_t ret = oscore_validate_sender_seq(r_ctx, cose);
  UNIT_TEST_ASSERT(ret == 1);

  /* Set seq 1. */
  cose_encrypt0_set_partial_iv(cose, seq_1, sizeof(seq_1));  
  ret = oscore_validate_sender_seq(r_ctx, cose);
  UNIT_TEST_ASSERT(ret == 1);

  /* Set seq 2. */
  cose_encrypt0_set_partial_iv(cose, seq_2, sizeof(seq_2));  
  ret = oscore_validate_sender_seq(r_ctx, cose);
  UNIT_TEST_ASSERT(ret == 1);

  /* Save parameters to test after rollback. */
  uint32_t sliding_window = r_ctx->sliding_window; 
  uint64_t last_seq = r_ctx->largest_seq;

  /* Set seq 3. */
  cose_encrypt0_set_partial_iv(cose, seq_3, sizeof(seq_3));  
  ret = oscore_validate_sender_seq(r_ctx, cose);
  UNIT_TEST_ASSERT(ret == 1);

  /* Roll back seq. */
  oscore_roll_back_seq(r_ctx);
  UNIT_TEST_ASSERT(sliding_window == r_ctx->sliding_window); 
  UNIT_TEST_ASSERT( last_seq == r_ctx->largest_seq);

  UNIT_TEST_END();
}


UNIT_TEST_REGISTER(test_parse_option,
                   "parse_option()");
UNIT_TEST(test_parse_option)
{

  UNIT_TEST_BEGIN();
  cose_encrypt0_t cose[1];
  cose_encrypt0_init(cose);
  cose_encrypt0_t cose_zero[1];
  cose_encrypt0_init(cose_zero);
   //sixth to eight byte should be zero -> malformed

  int ret = 0;
  uint8_t o_0[1] = { 0x00 };
  uint8_t o_1[1] = { 0x06 };
  uint8_t o_2[1] = { 0x07 };
  uint8_t o_3[1] = { 0xE0 };
  uint8_t o_4[5] = { 0x04, 0x01, 0x02, 0x03, 0x04 }; //only partial IV len 4
  uint8_t o_5[5] = { 0x08, 0xA1, 0xA2, 0xA3, 0xA4 }; //only Kid len 4
  uint8_t o_6[6] = { 0x10, 0x04, 0xB1, 0xB2, 0xB3, 0xB4 }; //kid-context with len 4
  uint8_t o_7[1] = { 0x05 }; //Non-existing Partial IV, but length = 5;
  uint8_t o_8[2] = { 0x10, 0xFF }; //Kid-context flag and length, but no kid-context
  uint8_t o_9[1] = { 0x08 }; //Key-ID flag set, but no Key-id
  uint8_t o_10[19] = { 0x1D, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0x05, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7 };

  uint8_t piv[4] = { 0x01, 0x02, 0x03, 0x04};
  uint8_t kid[4] = { 0xA1, 0xA2, 0xA3, 0xA4};
  uint8_t piv2[5] = { 0xF1, 0xF2, 0xF3, 0xF4, 0xF5 };
  uint8_t kid2[7] = { 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7};
  uint8_t kid_context[4] = { 0xB1, 0xB2, 0xB3, 0xB4 };
  uint8_t kid_context2[5] = { 0xC1, 0xC2, 0xC3, 0xC4, 0xC5 };
   //only kid context
  //lengths does not fit?
  //other malformed stuff

  /*  Assert that len < 255 */
  ret = oscore_decode_option_value(o_0, 256, cose);
  UNIT_TEST_ASSERT( ret == BAD_OPTION_4_02);  

  /* Assert that values n = 7 & n = 6 are reserved */
  ret = oscore_decode_option_value(o_1, sizeof(o_1), cose);
  UNIT_TEST_ASSERT( ret == BAD_OPTION_4_02);

  ret = oscore_decode_option_value(o_2, sizeof(o_2), cose);
  UNIT_TEST_ASSERT( ret == BAD_OPTION_4_02);

  /* Assert that bits six to eight are set to 0 */
  ret = oscore_decode_option_value(o_3, sizeof(o_3), cose);
  UNIT_TEST_ASSERT( ret == BAD_OPTION_4_02);

  ret = oscore_decode_option_value(o_4, sizeof(o_4), cose);
  UNIT_TEST_ASSERT( ret == 0);
  UNIT_TEST_ASSERT(memcmp(cose->partial_iv, piv, cose->partial_iv_len) == 0);

  cose_encrypt0_init(cose);
  ret = oscore_decode_option_value(o_5, sizeof(o_5), cose);
  UNIT_TEST_ASSERT( ret == 0);
  UNIT_TEST_ASSERT(memcmp(cose->key_id, kid, cose->key_id_len) == 0);

  cose_encrypt0_init(cose);
  ret = oscore_decode_option_value(o_6, sizeof(o_6), cose);
  UNIT_TEST_ASSERT( ret == 0);
  UNIT_TEST_ASSERT(memcmp(cose->kid_context, kid_context, cose->kid_context_len) == 0);

  cose_encrypt0_init(cose);
  ret = oscore_decode_option_value(o_7, sizeof(o_7), cose);
  UNIT_TEST_ASSERT( ret == BAD_OPTION_4_02);
  UNIT_TEST_ASSERT(memcmp((char*)cose, (char*)cose_zero, sizeof(cose)) == 0);

  cose_encrypt0_init(cose);
  ret = oscore_decode_option_value(o_8, sizeof(o_8), cose);
  UNIT_TEST_ASSERT( ret == BAD_OPTION_4_02);
  UNIT_TEST_ASSERT(memcmp((char*)cose, (char*)cose_zero, sizeof(cose)) == 0);

  cose_encrypt0_init(cose);
  ret = oscore_decode_option_value(o_8, sizeof(o_8), cose);
  UNIT_TEST_ASSERT( ret == BAD_OPTION_4_02); 
  UNIT_TEST_ASSERT(memcmp((char*)cose, (char*)cose_zero, sizeof(cose)) == 0);

  cose_encrypt0_init(cose);
  ret = oscore_decode_option_value(o_9, sizeof(o_9), cose);
  UNIT_TEST_ASSERT( ret == BAD_OPTION_4_02); 
  UNIT_TEST_ASSERT(memcmp((char*)cose, (char*)cose_zero, sizeof(cose)) == 0);

  cose_encrypt0_init(cose);
  ret = oscore_decode_option_value(o_10, sizeof(o_10), cose);
  UNIT_TEST_ASSERT( ret == 0); 
  UNIT_TEST_ASSERT(memcmp(cose->kid_context, kid_context2, cose->kid_context_len) == 0);
  UNIT_TEST_ASSERT(memcmp(cose->key_id, kid2, cose->key_id_len) == 0);
  UNIT_TEST_ASSERT(memcmp(cose->partial_iv, piv2, cose->partial_iv_len) == 0);

  UNIT_TEST_END();
}

PROCESS_THREAD(test_process, ev, data)
{

  PROCESS_BEGIN();
  test_setup();
  printf("Run unit-test\n");
  printf("---\n");
  UNIT_TEST_RUN(test_validate_sender_seq);
  UNIT_TEST_RUN(test_rollback_seq);
  UNIT_TEST_RUN(test_parse_option);
  printf("=check-me= DONE\n");
  PROCESS_END();
}


