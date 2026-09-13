#ifndef EVERGRAM_BACKOFF_H
#define EVERGRAM_BACKOFF_H

#include <stdint.h>

/*
 * Exponential backoff with jitter, mirroring the TypeScript SDK's backoff.ts.
 *
 * The curve is a pure function so it can be unit-tested without timers; only
 * the jitter draw needs randomness, and it is isolated in
 * evergram_backoff_delay_ms().
 */

/* Deterministic part: min(base * 2^(attempt-1), cap). attempt is 1-based. */
uint32_t evergram_backoff_base_ms(unsigned attempt, uint32_t base_ms, uint32_t cap_ms);

/* Adds a random [0, jitter_ms) draw on top of the curve, still capped. */
uint32_t evergram_backoff_delay_ms(unsigned attempt, uint32_t base_ms, uint32_t cap_ms,
                                   uint32_t jitter_ms);

/* Values the gateway-facing reconnect loop uses. */
#define EVERGRAM_BACKOFF_BASE_MS 1000u
#define EVERGRAM_BACKOFF_CAP_MS 30000u
#define EVERGRAM_BACKOFF_JITTER_MS 500u

#endif /* EVERGRAM_BACKOFF_H */
