all: oscore-example-server oscore-example-client oscore-plugtest-server oscore-plugtest-client
# use target "oscore-plugtest-server" explicitly when required

CONTIKI=../..

MAKE_WITH_OSCORE = 1
WERROR = 1
CFLAGS += -DCOOJA_MTARCH_STACKSIZE=4096
#CFLAGS += -Wvla

# build RESTful resources
include $(CONTIKI)/Makefile.identify-target
ifeq ($(TARGET),native)
	MODULES_REL += ./resources-plugtest
endif
MODULES_REL += ./resources
MODULES_REL += ../coap/coap-example-server/resources
MODULES_REL += $(TARGET)

CONTIKI_TARGET_SOURCEFILES += plugtest_resources.c

# Include the CoAP implementation
MODULES += os/net/app-layer/coap

include $(CONTIKI)/Makefile.include

# border router rules
$(CONTIKI)/tools/tunslip6:	$(CONTIKI)/tools/tunslip6.c
	(cd $(CONTIKI)/tools && $(MAKE) tunslip6)

connect-router:	$(CONTIKI)/tools/tunslip6
	sudo $(CONTIKI)/tools/tunslip6 fd00::1/64

connect-router-cooja:	$(CONTIKI)/tools/tunslip6
	sudo $(CONTIKI)/tools/tunslip6 -a 127.0.0.1 -p 60001 fd00::1/64

connect-router-native:	$(CONTIKI)/examples/rpl-border-router/border-router.native
	sudo $(CONTIKI)/examples/rpl-border-router/border-router.native -a 127.0.0.1 -p 60001 fd00::1/64

connect-native:
	sudo ip address add fdfd::1/64 dev tun0
