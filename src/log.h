#ifndef EVERGRAM_LOG_H
#define EVERGRAM_LOG_H

#include "evergram.h"

/*
 * Minimal leveled logger writing to stderr.
 *
 * Level is process-wide: the single mutable global in this project. Set it once
 * at startup (evergram_log_set_level or EVERGRAM_LOG=...) before spawning
 * threads; concurrent changes are not synchronized.
 *
 * evergram_log_set_level() and evergram_log_level_from_name() are public and
 * declared in evergram.h; the rest of this header is internal.
 */

evergram_log_level_t evergram_log_get_level(void);

void evergram_log(evergram_log_level_t level, const char *format, ...) EVERGRAM_PRINTF(2, 3);

#define EG_ERROR(...) evergram_log(EVERGRAM_LOG_ERROR, __VA_ARGS__)
#define EG_WARN(...) evergram_log(EVERGRAM_LOG_WARN, __VA_ARGS__)
#define EG_INFO(...) evergram_log(EVERGRAM_LOG_INFO, __VA_ARGS__)
#define EG_DEBUG(...) evergram_log(EVERGRAM_LOG_DEBUG, __VA_ARGS__)
#define EG_TRACE(...) evergram_log(EVERGRAM_LOG_TRACE, __VA_ARGS__)

#endif /* EVERGRAM_LOG_H */
