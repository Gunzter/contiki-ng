//TODO add copyright statement

#include <stdio.h>

#include "contiki.h"
#include "contiki-net.h"
#include "contiki-lib.h"
#include "lib/assert.h"

#include "hkdf-test-vectors.h"
#include "unit-test/unit-test.h"
#include "oscore-crypto.h"

PROCESS(test_process, "6top protocol APIs test");
AUTOSTART_PROCESSES(&test_process);

uint8_t OKM_buffer[100];

static void
test_setup(void)
{
  memset(OKM_buffer, 0, 100);
}

UNIT_TEST_REGISTER(test_hkdf_a1,
                   "test_HKDF_SHA-256_A1()");
UNIT_TEST(test_hkdf_a1)
{

  UNIT_TEST_BEGIN();
  test_setup();
  printf("HKDF_INFO_MAXLEN %d\n",HKDF_INFO_MAXLEN);
  printf("HKDF_OUTPUT_MAXLEN %d\n",HKDF_OUTPUT_MAXLEN);


  hkdf(salt_1, 13, IKM_1, 22, info_1, 10, OKM_buffer, L_1);
  UNIT_TEST_ASSERT(memcmp(OKM_1, OKM_buffer, L_1) == 0 );
  UNIT_TEST_END();
}

UNIT_TEST_REGISTER(test_hkdf_a2,
                   "test_HKDF_SHA-256_A2()");
UNIT_TEST(test_hkdf_a2)
{

  UNIT_TEST_BEGIN();
  test_setup();
  
  hkdf(salt_2, 80, IKM_2, 80, info_2, 80, OKM_buffer, L_2);
  UNIT_TEST_ASSERT(memcmp(OKM_2, OKM_buffer, L_2) == 0 );
  UNIT_TEST_END();
}

UNIT_TEST_REGISTER(test_hkdf_a3,
                   "test_HKDF_SHA-256_A3()");
UNIT_TEST(test_hkdf_a3)
{

  UNIT_TEST_BEGIN();
  test_setup();
  
  hkdf(salt_3, 0, IKM_3, 22, info_3, 0, OKM_buffer, L_3);
  UNIT_TEST_ASSERT(memcmp(OKM_3, OKM_buffer, L_3) == 0 );
  UNIT_TEST_END();
}

PROCESS_THREAD(test_process, ev, data)
{

  PROCESS_BEGIN();
  test_setup();
  printf("Run unit-test\n");
  printf("---\n");
  UNIT_TEST_RUN(test_hkdf_a1);
  UNIT_TEST_RUN(test_hkdf_a2);
  UNIT_TEST_RUN(test_hkdf_a3);
  printf("=check-me= DONE\n");
  PROCESS_END();
}


