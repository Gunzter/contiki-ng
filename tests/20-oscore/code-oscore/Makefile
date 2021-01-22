all:


MAKE_WITH_OSCORE = 1

MODULES += os/services/unit-test
MODULES += os/net/app-layer/coap
CFLAGS += -DHKDF_INFO_MAXLEN=95 -DHKDF_OUTPUT_MAXLEN=95

PROJECT_SOURCEFILES += common.c

CONTIKI = ../../..
include $(CONTIKI)/Makefile.include
