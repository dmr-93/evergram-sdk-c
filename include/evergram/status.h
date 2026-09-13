#ifndef EVERGRAM_STATUS_H
#define EVERGRAM_STATUS_H

#include "evergram/export.h"

/*
 * Every fallible public function returns one of these.
 * EVERGRAM_OK is always zero; callers may test `if (status)`.
 */
typedef enum {
    EVERGRAM_OK = 0,
    EVERGRAM_ERR_INVALID_ARG,      /* NULL, empty, or out-of-range argument */
    EVERGRAM_ERR_NO_MEMORY,        /* allocation failed */
    EVERGRAM_ERR_CRYPTO,           /* libsodium/OpenSSL failure or unusable key */
    EVERGRAM_ERR_ENCODING,         /* malformed hex, base58, or seed */
    EVERGRAM_ERR_IO,               /* file or socket operation failed */
    EVERGRAM_ERR_TRANSPORT,        /* websocket layer failure */
    EVERGRAM_ERR_NOT_CONNECTED,    /* operation needs an open connection */
    EVERGRAM_ERR_PROTOCOL,         /* peer sent data we cannot decode */
    EVERGRAM_ERR_AUTH,             /* gateway rejected authentication */
    EVERGRAM_ERR_TIMEOUT,          /* deadline elapsed before completion */
    EVERGRAM_ERR_BUFFER_TOO_SMALL, /* caller-owned buffer cannot hold result */
    EVERGRAM_ERR_NOT_IMPLEMENTED,  /* documented gap, see README limitations */
    EVERGRAM_ERR_STATE,            /* call is invalid in the current state */
    EVERGRAM_ERR_NO_CHAT_KEY,      /* chat symmetric key not learned yet */
    EVERGRAM_ERR_GATEWAY,          /* gateway replied non-ok; see evergram_last_error() */
    EVERGRAM_ERR_NO_ROOM_KEY,      /* visitor room key not known yet */
} evergram_status_t;

/* Stable, human-readable name. Never returns NULL. */
EVERGRAM_API const char *evergram_status_str(evergram_status_t status);

#endif /* EVERGRAM_STATUS_H */
