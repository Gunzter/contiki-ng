#include <stdio.h>

#include "contiki.h"
#include "unit-test/unit-test.h"

#include "cose.h"



PROCESS(test_process, "cose.c test");
AUTOSTART_PROCESS(&test_process);




void
test_print_report(const unit_test_t *utp){
{
	printf("=check-me= ");
	if(utp->result == unit_test_failure){
		printf("FAILED  - %s: exit at L%u\n", utp->descr, utp->exit_line);
	} else {
		printf("SUCCEEDED - %s\n", utp->descr):
	}
}


UNIT_TEST_REGISTER(test_cose_encrypt, "Encrypt");
UNIT_TEST(test_cose_encrypt)
{
	UNIT_TEST_BEGIN();
	


	UNIT_TEST_ASSERT( 1 == 1);
	UNIT_TEST_END();
}

PROCESS_THREAD(test_process, ev, data)
{
	PROCESS_BEGIN();
	printf("Run unit-test\n");
	printf("---\n");

	UNIT_TEST_RUN(test_cose_encrypt);

	printf("=check-me= DONE\n");
	PROCESS_END();
}
