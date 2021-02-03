#include "sliding-window.h"

#include "assert.h"

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "oscore"
#ifdef LOG_CONF_LEVEL_OSCORE
#define LOG_LEVEL LOG_CONF_LEVEL_OSCORE
#else
#define LOG_LEVEL LOG_LEVEL_WARN
#endif

void oscore_sliding_window_init(oscore_sliding_window_t* w)
{
    w->largest_seq = OSCORE_INVALID_SEQ;
    w->rollback_largest_seq = w->largest_seq;
    
    w->sliding_window = 0;
    w->rollback_sliding_window = w->sliding_window;

    w->recent_seq = OSCORE_INVALID_SEQ;
}

void oscore_sliding_window_rollback(oscore_sliding_window_t* w)
{
    LOG_DBG("Rolling back seq (window %"PRIu32" = %"PRIu32") (seq %"PRIu64" = %"PRIu64")\n",
    w->sliding_window, w->rollback_sliding_window,
    w->largest_seq, w->rollback_largest_seq);

    w->sliding_window = w->rollback_sliding_window;
    w->largest_seq = w->rollback_largest_seq;
}

bool oscore_sliding_window_test(const oscore_sliding_window_t* w, uint64_t seq)
{
    /* Check that seq is within the sliding window */
    if (w->largest_seq == OSCORE_INVALID_SEQ)
    {
        /* no sliding window yet */
        return false;
    }
    if (seq > w->largest_seq)
    {
        /* too big */
        return false;
    }
    if (seq + OSCORE_DEFAULT_REPLAY_WINDOW < w->largest_seq)
    {
        /* too small */
        return false;
    }

    const int64_t shift = w->largest_seq - seq;

    return (w->sliding_window & (1 << shift)) != 0;
}

void oscore_sliding_window_set(oscore_sliding_window_t* w, uint64_t seq)
{
    if (w->largest_seq == OSCORE_INVALID_SEQ) {
        /* Set the 0th bit */
        w->sliding_window = (1 << 0);

        w->largest_seq = seq;
    }
    else if (seq > w->largest_seq) {
        const int64_t shift = seq - w->largest_seq;

        /* Move the window along so the 0th bit is this new seq */
        w->sliding_window <<= shift;

        /* Set the 0th bit */
        w->sliding_window |= (1 << 0);

        w->largest_seq = seq;

    } else {
        assert(oscore_sliding_window_contains(w, seq));

        const int64_t shift = w->largest_seq - seq;

        assert(shift >= 0);
        assert(shift < OSCORE_DEFAULT_REPLAY_WINDOW);

        w->sliding_window |= (1 << shift);
    }
}

bool oscore_sliding_window_contains(const oscore_sliding_window_t* w, uint64_t seq)
{
    /* Seq needs to be in the range (largest_seq - OSCORE_DEFAULT_REPLAY_WINDOW : largest_seq] */
    return w->largest_seq != OSCORE_INVALID_SEQ &&

        seq <= w->largest_seq &&

        /* Rearranged to prevent underflow */
        seq + OSCORE_DEFAULT_REPLAY_WINDOW > w->largest_seq;
}

bool oscore_sliding_window_validate(oscore_sliding_window_t* w, uint64_t incoming_seq)
{
    LOG_DBG("incoming SEQ %" PRIu64 "\n", incoming_seq);

    /* Save the current state for potential rollback */
    w->rollback_largest_seq = w->largest_seq;
    w->rollback_sliding_window = w->sliding_window;

    if(incoming_seq >= OSCORE_SEQ_MAX) {
        LOG_WARN("Replay protection, SEQ %" PRIu64 " larger than SEQ_MAX %" PRIu64 ".\n",
          incoming_seq, OSCORE_SEQ_MAX);
        return false;
    }

    if(incoming_seq > w->largest_seq || w->largest_seq == OSCORE_INVALID_SEQ) {
        oscore_sliding_window_set(w, incoming_seq);

    } else if(incoming_seq == w->largest_seq) {
        LOG_WARN("Replay protection, replayed SEQ incoming_seq (%" PRIu64 ") == w->largest_seq (%" PRIu64 ").\n",
            incoming_seq, w->largest_seq);
        return false;

    } else { /* seq < recipient_seq */
        if(!oscore_sliding_window_contains(w, incoming_seq)) {
            LOG_WARN("Replay protection, SEQ outside of replay window "
                "(incoming_seq=%" PRIu64 ", replay_window_size=%" PRIu8 ", largest_seq=%" PRIu64 ").\n",
                incoming_seq, OSCORE_DEFAULT_REPLAY_WINDOW, w->largest_seq);
            return false;
        }

        const bool set = oscore_sliding_window_test(w, incoming_seq);
        if(set) {
            LOG_WARN("Replay protection, replayed SEQ %"PRIu64" (sliding_window=%" PRIu32 ").\n",
                incoming_seq, w->sliding_window);
            return false;
        } else {
            oscore_sliding_window_set(w, incoming_seq);
        }
    }

    /* Update the last seen seq */
    w->recent_seq = incoming_seq;

    return true;
}
