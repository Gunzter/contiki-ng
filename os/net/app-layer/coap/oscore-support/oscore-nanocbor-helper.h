#pragma once

#include "nanocbor/nanocbor.h"

#include "cc.h"

#define NANOCBOR_CHECK(expr) \
    do { \
        const int result = (expr); \
        if (result < 0) \
        { \
            LOG_ERR("Failed '" CC_STRINGIFY(expr) "' at " __FILE__ ":" CC_STRINGIFY(__LINE__) " (result=%d)\n", result); \
            return result; \
        } \
    } while (0)
