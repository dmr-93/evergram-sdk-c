#ifndef EVERGRAM_TRANSPORT_H
#define EVERGRAM_TRANSPORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "evergram/status.h"

/*
 * Websocket transport over libwebsockets.
 *
 * The transport owns the socket and the receive queue; the receiver never sees
 * partial frames. Callbacks fire from inside transport_service(), so event
 * handlers must not call back into the transport re-entrantly.
 */

typedef struct transport transport_t;

typedef struct {
    void (*on_open)(void *context);
    void (*on_closed)(void *context);
    void (*on_error)(void *context, evergram_status_t status, const char *detail);
    /* data is borrowed and valid only for the duration of the call. */
    void (*on_message)(void *context, const uint8_t *data, size_t len);
    void *context;
} transport_events_t;

/* Parses the URL eagerly; returns NULL on a malformed URL or library failure. */
transport_t *transport_create(const char *url, const transport_events_t *events);

/* Closes the socket, destroys the context, and wipes buffered bytes. */
void transport_destroy(transport_t *transport);

/* Starts the connection. Completion arrives asynchronously via on_open. */
evergram_status_t transport_connect(transport_t *transport);

/* Services the socket. EVERGRAM_ERR_TIMEOUT means "no event this round". */
evergram_status_t transport_service(transport_t *transport, int timeout_ms);

/* Queues one binary frame. Requires an open connection and len > 0. */
evergram_status_t transport_send(transport_t *transport, const uint8_t *data, size_t len);

bool transport_is_open(const transport_t *transport);

/* Last error reported by the library, or NULL. Borrowed. */
const char *transport_last_error(const transport_t *transport);

#endif /* EVERGRAM_TRANSPORT_H */
