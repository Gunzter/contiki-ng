CONTIKI_PROJECT = oscore-test-server
all: $(CONTIKI_PROJECT)

# Do not try to build on Sky because of code size limitation
PLATFORMS_EXCLUDE = sky z1

# Include the CoAP implementation
MODULES += os/net/app-layer/coap


#If no SERVER is defined use Server 1
ifeq ($(strip $(SERVER)),)
CFLAGS += -DSERVER=1
else
CFLAGS += -DSERVER=$(SERVER)
endif

#If no TEST is defined do not use any
ifdef $(TEST)
CFLAGS += -DTEST=$(TEST)
endif

MAKE_WITH_OSCORE = 1
MAKE_WITH_HW_CRYPTO = 1

# Include CoAP resources
MODULES_REL += ./resources

#dissable Werror for now
WERROR=0

CONTIKI=../../..
include $(CONTIKI)/Makefile.include
