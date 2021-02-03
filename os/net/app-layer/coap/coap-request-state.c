#include "coap-request-state.h"
#include "cc.h"

static const char* coap_request_status_to_string_table[] = {
    "RESPONSE",
    "MORE",
    "FINISHED",
    "TIMEOUT",
    "BLOCK_ERROR"
};

const char*
coap_request_status_to_string(coap_request_status_t status)
{
    if (status >= 0 && status < CC_ARRAY_SIZE(coap_request_status_to_string_table))
    {
        return coap_request_status_to_string_table[status];
    }
    else
    {
        return "UNKNOWN";
    }
}
