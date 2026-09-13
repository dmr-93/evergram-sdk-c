#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "evergram/status.h"

/* Process-wide log level. See log.h for the rationale and its limits. */
static evergram_log_level_t g_level = EVERGRAM_LOG_INFO;

static const char *const LEVEL_NAMES[] = {"off", "error", "warn", "info", "debug", "trace"};

void evergram_log_set_level(evergram_log_level_t level) {
    if (level >= EVERGRAM_LOG_OFF && level <= EVERGRAM_LOG_TRACE) {
        g_level = level;
    }
}

evergram_log_level_t evergram_log_get_level(void) {
    return g_level;
}

void evergram_log(evergram_log_level_t level, const char *format, ...) {
    if (level < EVERGRAM_LOG_OFF || level > EVERGRAM_LOG_TRACE) {
        return;
    }
    if (level > g_level || g_level == EVERGRAM_LOG_OFF || format == NULL) {
        return;
    }

    va_list args;
    va_start(args, format);
    fprintf(stderr, "[evergram %s] ", LEVEL_NAMES[level]);
    vfprintf(stderr, format, args);
    fputc('\n', stderr);
    va_end(args);
}

evergram_log_level_t evergram_log_level_from_name(const char *name) {
    if (name == NULL) {
        return EVERGRAM_LOG_OFF;
    }

    for (size_t i = 0; i < sizeof(LEVEL_NAMES) / sizeof(LEVEL_NAMES[0]); i++) {
        if (strcmp(name, LEVEL_NAMES[i]) == 0) {
            return (evergram_log_level_t)i;
        }
    }
    return EVERGRAM_LOG_OFF;
}

const char *evergram_status_str(evergram_status_t status) {
    switch (status) {
    case EVERGRAM_OK:
        return "ok";
    case EVERGRAM_ERR_INVALID_ARG:
        return "invalid argument";
    case EVERGRAM_ERR_NO_MEMORY:
        return "out of memory";
    case EVERGRAM_ERR_CRYPTO:
        return "crypto failure";
    case EVERGRAM_ERR_ENCODING:
        return "malformed encoding";
    case EVERGRAM_ERR_IO:
        return "i/o failure";
    case EVERGRAM_ERR_TRANSPORT:
        return "transport failure";
    case EVERGRAM_ERR_NOT_CONNECTED:
        return "not connected";
    case EVERGRAM_ERR_PROTOCOL:
        return "protocol error";
    case EVERGRAM_ERR_AUTH:
        return "authentication failed";
    case EVERGRAM_ERR_TIMEOUT:
        return "timeout";
    case EVERGRAM_ERR_BUFFER_TOO_SMALL:
        return "buffer too small";
    case EVERGRAM_ERR_NOT_IMPLEMENTED:
        return "not implemented";
    case EVERGRAM_ERR_STATE:
        return "invalid state";
    case EVERGRAM_ERR_NO_CHAT_KEY:
        return "chat key unknown";
    case EVERGRAM_ERR_GATEWAY:
        return "gateway rejected the request";
    case EVERGRAM_ERR_NO_ROOM_KEY:
        return "visitor room key unknown";
    }
    return "unknown status";
}
