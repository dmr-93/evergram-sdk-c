#include "backoff.h"

#include <sodium.h>

uint32_t evergram_backoff_base_ms(unsigned attempt, uint32_t base_ms, uint32_t cap_ms) {
    if (attempt == 0) {
        return base_ms < cap_ms ? base_ms : cap_ms;
    }

    uint64_t delay = base_ms;
    for (unsigned i = 1; i < attempt; i++) {
        if (delay >= cap_ms) {
            return cap_ms;
        }
        delay *= 2u;
    }

    return (uint32_t)(delay < cap_ms ? delay : cap_ms);
}

uint32_t evergram_backoff_delay_ms(unsigned attempt, uint32_t base_ms, uint32_t cap_ms,
                                   uint32_t jitter_ms) {
    uint32_t delay = evergram_backoff_base_ms(attempt, base_ms, cap_ms);
    if (jitter_ms == 0) {
        return delay;
    }

    uint32_t jitter = randombytes_uniform(jitter_ms);
    uint64_t total = (uint64_t)delay + jitter;
    return (uint32_t)(total < cap_ms ? total : cap_ms);
}
