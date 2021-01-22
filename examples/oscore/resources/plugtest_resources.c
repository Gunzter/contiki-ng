#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "coap-engine.h"
#include "oscore.h"
#include <assert.h>
#include "plugtest_resources.h"

//static coap_observee_t *obs;

char *urls[8] = { "/oscore/hello/coap", "/oscore/hello/1", "/oscore/hello/2", "/oscore/hello/3", "/oscore/observe", "/oscore/hello/6", "/oscore/hello/7", "/oscore/test"};
uint8_t rid[] = { 0x73, 0x65, 0x72, 0x76, 0x65, 0x72 };

void test0_a(coap_message_t* request){
  printf("\n\nTest 0a: Starting!\n");
  coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
  coap_set_header_uri_path(request, urls[0]);

  printf("Test 0a: Sending!\n");
}

void test0_a_handler(void* response){
  printf("Test 0a: Receiving Response!\n");
//return;
  const uint8_t *response_payload;
  const char desired[] = "Hello World!";
  int len = coap_get_payload(response, &response_payload);
  int res = strncmp( desired, (char*)response_payload, strlen(desired));
  if(res == 0){
    printf("Test 0a: PASSED!\n");
  }else {
    printf("Test 0a: FAILED!\n");
    printf("\t Expected result: \"Hello World!\" but was: ");
    printf("%.*s\n", len, response_payload);
    failed_tests++;
  }
}

void test1_a(coap_message_t* request){
  printf("\n\nTest 1a: Starting!\n");
  coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
  coap_set_header_uri_path(request, urls[1]);
  coap_set_oscore(request);
 
  printf("Test 1a: Sending!\n");
}

void test1_a_handler(void* response){
  printf("Test 1a: Receiving Response!\n");

  const uint8_t *response_payload;
  const char desired[] = "Hello World!";
  int len = coap_get_payload(response, &response_payload);
  int res = strncmp( desired, (char*)response_payload, strlen(desired));

  if(res == 0){
    printf("Test 1a: PASSED!\n");
  }else {
    printf("Test 1a: FAILED!\n");
    printf("\t Expected result: \"Hello World!\" but was: ");
    printf("%.*s\n", len, response_payload);
    failed_tests++;
  }
} 

void test2_a(coap_message_t* request){
  printf("\n\nTest 2a: Starting!\n");
  coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
  coap_set_header_uri_path(request, urls[2]);
  coap_set_oscore(request);
 
  const char *uri_query = "first=1";
  coap_set_header_uri_query(request, uri_query);
  printf("Test 2a: Sending!\n");
}

void test2_a_handler(void* response){
  printf("Test 2a: Receiving Response!\n");

  const uint8_t *response_payload;
  const char desired[] = "Hello World!";
  const uint8_t desired_etag = 0x2b;
  int len = coap_get_payload(response, &response_payload);
  int res = strncmp( desired, (char*)response_payload, strlen(desired));
  const uint8_t *etag;

  int etag_len = coap_get_header_etag(response, &etag);
  if((etag_len != 1)){
    res++;
  }

  unsigned int content = 15;
  coap_get_header_content_format(response, &content);
  if(content != 0){
    res++;
  }
  
  res += memcmp(etag, &desired_etag, 1);

  if(res == 0){
    printf("Test 2a: PASSED!\n");
  }else {
    printf("Test 2a: FAILED!\n");
    printf("\t Expected result: \"Hello World!\" but was: ");
    printf("%.*s\n", len, response_payload);
    printf("Expected etag: \"0x2b\" or \"43\" but was %02x or %d, length %d\n", etag[0], etag[0], etag_len);
    failed_tests++;
  }
} 

void test3_a(coap_message_t* request){
  printf("\n\nTest 3a: Starting!\n");
  coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
  coap_set_header_uri_path(request, urls[3]);
  coap_set_header_accept(request, 0);

  coap_set_oscore(request);

  printf("Test 3a: Sending!\n");
}

void test3_a_handler(void* response){
  printf("Test 3a: Receiving Response!\n");

  const uint8_t *response_payload;
  const char desired[] = "Hello World!";
  int len = coap_get_payload(response, &response_payload);
  int res = strncmp( desired, (char*)response_payload, strlen(desired));
  
  uint32_t age = 0;
  coap_get_header_max_age(response, &age);
  if(age != 0x05){
    res++;
  }

  unsigned int content = 15;
  coap_get_header_content_format(response, &content);
  if(content != 0){
    res++;
  }

  if(res == 0){
    printf("Test 3a: PASSED!\n");
  }else {
    printf("Test 3a: FAILED!\n");
    printf("\t Expected result: \"Hello World!\" but was: ");
    printf("Expected restult: Max Age \"5\", was %" PRIu32", Content Format \"0\", was %d\n", age, content);
    printf("%.*s\n", len, response_payload);
    failed_tests++;
  }
}



void test4_a(coap_message_t* request){
  printf("\n\nTest 4a: Starting!\n");
  coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
  coap_set_header_uri_path(request, urls[3]);
  coap_set_oscore(request);
  coap_set_header_accept(request, 0);
  printf("Test 4a: Sending!\n");
}

void test4_a_handler(void* response){
  printf("Test 4a: Receiving Response!\n");
  int res = 0;
  uint32_t max_age = 0;
  unsigned int content_format = 155; //0 is the desired result
  coap_get_header_max_age(response, &max_age);
  coap_get_header_content_format(response, &content_format);

  if(((coap_message_t*)response)->code != CONTENT_2_05){
	  res++;
  }
  if(max_age != 5){
	  res++;
  }
  if(content_format != 0){
	  res++;
  }

  if(res == 0){
    printf("Test 4: PASSED!\n");
  }else {
    printf("Test 4a: FAILED!\n");
    printf("\t Result was: \n");
    printf("Max-Age %" PRIu32 ", Content-Format %d\n", max_age, content_format);
    printf("Code = %d\n", ((coap_message_t*)response)->code);
    failed_tests++;
  }
} 

static uint8_t payload[1] = { 0x4a };

void test8_a(coap_message_t* request){
  printf("\n\nTest 8a: Starting!\n");
  coap_init_message(request, COAP_TYPE_CON, COAP_POST, 0);
  coap_set_header_uri_path(request, urls[5]);
  coap_set_oscore(request);
  coap_set_header_content_format(request, 0);
  coap_set_payload(request, payload, 1);

  printf("Test 8a: Sending!\n");
}

void test8_a_handler(void* response){
  printf("Test 8a: Receiving Response!\n");
  int res = 0;

  if(((coap_message_t*)response)->code != CHANGED_2_04){
    res++;
  }
  const uint8_t *payload;
  int len = coap_get_payload(response, &payload);
  if( len != 1 || *payload != 0x4a){
	  res++;
  }
  unsigned int content_format = 155;
  coap_get_header_content_format(response, &content_format);
  if(content_format != 0){
	  res++;
  }

  if(res == 0){
    printf("Test 8: PASSED!\n");
  }else {
    printf("Test 8a: FAILED!\n");

    failed_tests++;
  }
}

static uint8_t payload_9a[1] = { 0x7a };
const uint8_t if_match_9a[1] = { 0x7b };
void test9_a(coap_message_t* request){
  printf("\n\nTest 9a: Starting!\n");
  coap_init_message(request, COAP_TYPE_CON, COAP_PUT, 0);
  coap_set_header_uri_path(request, urls[6]);
  coap_set_oscore(request);
  coap_set_header_content_format(request, 0);
  coap_set_header_if_match(request, if_match_9a, 1);
  coap_set_payload(request, payload_9a, 1);

  printf("Test 9a: Sending!\n");
}

void test9_a_handler(void* response){
  printf("Test 9a: Receiving Response!\n");
  int res = 0;

  if(((coap_message_t*)response)->code != CHANGED_2_04){
    res++;
  }

  if(res == 0){
    printf("Test 9: PASSED!\n");
  }else {
    printf("Test 9a: FAILED!\n");
    printf("\t Expected result: 204 Changed.\n");

    failed_tests++;
  }
} 

static uint8_t payload_10a[1] = { 0x8a };
void test10_a(coap_message_t* request){
  printf("\n\nTest 10a: Starting!\n");
  coap_init_message(request, COAP_TYPE_CON, COAP_PUT, 0);
  coap_set_header_uri_path(request, urls[6]);
  coap_set_oscore(request);
  coap_set_header_content_format(request, 0);
  coap_set_header_if_none_match(request);
  coap_set_payload(request, payload_10a, 1);

  printf("Test 10a: Sending!\n");
}

void test10_a_handler(void* response){
  printf("Test 10a: Receiving Response!\n");
  int res = 0;

  if(((coap_message_t*)response)->code != PRECONDITION_FAILED_4_12){
    res++;
  }

  if(res == 0){
    printf("Test 10: PASSED!\n");
  }else {
    printf("Test 10a: FAILED!\n");
    printf("\t Expected result: 4.12 Precondition Failed.\n");
    printf("message code: %d\n", ((coap_message_t*)response)->code );
    failed_tests++;
  }
} 

void test11_a(coap_message_t* request){
  printf("\n\nTest 11a: Starting!\n");
  coap_init_message(request, COAP_TYPE_CON, COAP_DELETE, 0);
  coap_set_header_uri_path(request, urls[7]);

  coap_set_oscore(request);

  printf("Test 11a: Sending!\n");
}

void test11_a_handler(void* response){
  printf("Test 11a: Receiving Response!\n");
  int res = 0;

  if(((coap_message_t*)response)->code != DELETED_2_02){
    res++;
  }

  if(res == 0){
    printf("Test 11: PASSED!\n");
  }else {
    printf("Test 11a: FAILED!\n");
    printf("\t Expected result: 2.02 Deleted.\n");

    failed_tests++;
  }
}
 
uint8_t false_sender_id[] = { 0x63, 0x6C, 0x69, 0x65, 0x6E, 0x75 };
uint8_t false_sender_id_len = 6;
uint8_t *real_sender_id = NULL;
uint8_t real_sender_id_len = 0;
uint64_t real_sender_seq = 0;
uint8_t false_sender_key[] = {0x21, 0x64, 0x42, 0xda, 0x60, 0x3c, 0x51, 0x59, 0x2d, 0xf4, 0xc3, 0xd0, 0xcd, 0x1c, 0x0d, 0x48 };
uint8_t real_sender_key[] = { 0xf0, 0x91, 0x0e, 0xd7, 0x29, 0x5e, 0x6a, 0xd4, 0xb5, 0x4f, 0xc7, 0x93, 0x15, 0x43, 0x02, 0xff };

uint8_t false_recipient_key[] =  {0xd1, 0xcb, 0x37, 0x10, 0x37, 0x15, 0x34, 0xa1, 0xca, 0x22, 0x4e, 0x19, 0xeb, 0x96, 0xe9, 0x6d };
uint8_t real_recipient_key[] =  {0xff, 0xb1, 0x4e, 0x09, 0x3c, 0x94, 0xc9, 0xca, 0xc9, 0x47, 0x16, 0x48, 0xb4, 0xf9, 0x87, 0x10};


static oscore_ctx_t* security_context;
void test12_a(coap_message_t* request){
  printf("\n\nTest 12a: Starting!\n");
  coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
  coap_set_header_uri_path(request, urls[1]);

  coap_set_oscore(request);
  uint8_t id[1] = { 0x01 };
  security_context = oscore_find_ctx_by_rid(id, 1);
  if( security_context == NULL ){
	  printf("COULD NOT FIND CONTEXT!\n");
  }

  security_context->sender_context.sender_id = false_sender_id;
  security_context->sender_context.sender_id_len = false_sender_id_len;
  printf("Test 12a: Sending!\n");
}

void test12_a_handler(void* response){
  printf("Test 12a: Receiving Response!\n");
  int res = 0;

  if(((coap_message_t*)response)->code != UNAUTHORIZED_4_01){
    res++;
  }

  if(res == 0){
    printf("Test 12: PASSED!\n");
  }else {
    printf("Test 12a: FAILED!\n");
    printf("\t Expected result: 4.01 Unauthorized\n");

    failed_tests++;
  }

  security_context->sender_context.sender_id = real_sender_id;
  security_context->sender_context.sender_id_len = real_sender_id_len;
} 

void test13_a(coap_message_t* request){
  printf("\n\nTest 13a: Starting!\n");
  coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
  coap_set_header_uri_path(request, urls[1]);

  coap_set_oscore(request);
  
  memcpy(security_context->sender_context.sender_key, false_sender_key, 16);
  printf("Test 13a: Sending!\n");
}

void test13_a_handler(void* response){
  printf("Test 13a: Receiving Response!\n");
  int res = 0;

  if(((coap_message_t*)response)->code != BAD_REQUEST_4_00){
    res++;
  }

  if(res == 0){
    printf("Test 13: PASSED!\n");
  }else {
    printf("Test 13a: FAILED!\n");
    printf("\t Expected result: 4.00 Bad Request\n");

    failed_tests++;
  }
  memcpy(security_context->sender_context.sender_key, real_sender_key, 16);
}

void test14_a(coap_message_t* request){
  printf("\n\nTest 14a: Starting!\n");
  coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
  coap_set_header_uri_path(request, urls[1]);

  coap_set_oscore(request);
  
  memcpy(security_context->recipient_context.recipient_key, false_recipient_key, 16);
  printf("Test 14a: Sending!\n");
}

void test14_a_handler(void* response){
  printf("Test 14a: Receiving Response!\n");
  int res = 0;

  if(((coap_message_t*)response)->code != OSCORE_DECRYPTION_ERROR){
    res++;
  }

  if(res == 0){
    printf("Test 14: PASSED!\n");
  }else {
    printf("Test 14a: FAILED!\n");
    printf("\t Expected result: Decryption Error\n");
    printf("Got : %d\n", ((coap_message_t*)response)->code);
    failed_tests++;
  }
  memcpy(security_context->recipient_context.recipient_key, real_recipient_key, 16);
}

void test15_a(coap_message_t* request){
  printf("\n\nTest 15a: Starting!\n");
  coap_init_message(request, COAP_TYPE_CON, COAP_POST, 0);
  coap_set_header_uri_path(request, urls[1]);

  coap_set_oscore(request);
  
  real_sender_seq = security_context->sender_context.seq;
  security_context->sender_context.seq = 1;
  printf("Test 15a: Sending!\n");
}

void test15_a_handler(void* response){
  printf("Test 15a: Receiving Response!\n");
  int res = 0;

  if(((coap_message_t*)response)->code != UNAUTHORIZED_4_01){
    res++;
  }

  if(res == 0){
    printf("Test 15: PASSED!\n");
  }else {
    printf("Test 15a: FAILED!\n");
    printf("\t Expected result: 4.01 Unauthorized, was %d\n", ((coap_message_t*)response)->code);

    failed_tests++;
  }
  security_context->sender_context.seq = real_sender_seq;
}

void test16_a(coap_message_t* request){
  printf("\n\nTest 16a: Starting!\n");
  coap_init_message(request, COAP_TYPE_CON, COAP_POST, 0);
  coap_set_header_uri_path(request, urls[0]);

  coap_set_oscore(request);
  
  printf("Test 16a: Sending!\n");
}

void test16_a_handler(void* response){
  printf("Test 16a: Receiving Response!\n");
  int res = 0;

  if(((coap_message_t*)response)->code != BAD_OPTION_4_02){
    res++;
  }

  if(res == 0){
    printf("Test 16: PASSED!\n");
  }else {
    printf("Test 16a: FAILED!\n");
    printf("\t Expected result: 4.02 Bad Option, was %d\n", ((coap_message_t*)response)->code);

    failed_tests++;
  }
}

