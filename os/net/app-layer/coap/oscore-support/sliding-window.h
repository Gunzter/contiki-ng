#ifndef _OSCORE_SLIDING_WINDOW_H
#define _OSCORE_SLIDING_WINDOW_H

#include <stdint.h>
#include <stdbool.h>
#include <limits.h>

#include "cc.h"

#define OSCORE_SEQ_MAX (((uint64_t)1 << 40) - 1)

#define OSCORE_INVALID_SEQ UINT64_MAX

typedef struct {
    uint32_t sliding_window;
    uint32_t rollback_sliding_window;

    uint64_t largest_seq;
    uint64_t rollback_largest_seq;

    uint64_t recent_seq;

} oscore_sliding_window_t;

/* The maximum replay window size is defined by the number of bits in the sliding_window field */
#define OSCORE_MAX_REPLAY_WINDOW_SIZE (CC_FIELD_SIZEOF(oscore_sliding_window_t, sliding_window) * CHAR_BIT)

/* Default the replay window size to the maximum size */
#ifndef OSCORE_DEFAULT_REPLAY_WINDOW
#define OSCORE_DEFAULT_REPLAY_WINDOW OSCORE_MAX_REPLAY_WINDOW_SIZE
#endif

_Static_assert(OSCORE_DEFAULT_REPLAY_WINDOW >= 1, "OSCORE Replay window too small");
_Static_assert(OSCORE_DEFAULT_REPLAY_WINDOW <= OSCORE_MAX_REPLAY_WINDOW_SIZE, "OSCORE Replay window too large");

void oscore_sliding_window_init(oscore_sliding_window_t* window);

/* Restore the sequence number and replay-window to the previous state. This is to be used when decryption fails. */
void oscore_sliding_window_rollback(oscore_sliding_window_t* window);

/* Check that incoming_seq is a valid sequence number that has not been seen before */
bool oscore_sliding_window_validate(oscore_sliding_window_t* window, uint64_t incoming_seq);

/* Check if seq has been seen before */
bool oscore_sliding_window_test(const oscore_sliding_window_t* w, uint64_t seq);

/* Set that seq has been seen */
void oscore_sliding_window_set(oscore_sliding_window_t* w, uint64_t seq);

/* Check if the sliding window is at a point where it could contain seq */
bool oscore_sliding_window_contains(const oscore_sliding_window_t* w, uint64_t seq);

#endif /* _OSCORE_SLIDING_WINDOW_H */
