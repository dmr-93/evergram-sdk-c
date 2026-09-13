#ifndef EVERGRAM_RXQUEUE_H
#define EVERGRAM_RXQUEUE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "evergram/status.h"

/*
 * Byte queue that preserves websocket message boundaries.
 *
 * Callers append fragments with rxqueue_push() and close each websocket message
 * with rxqueue_end_frame(). Complete frames are consumed in order, so a single
 * read event carrying several messages cannot be misparsed as one.
 *
 * Ownership: the queue owns its storage; rxqueue_frame() lends a pointer that
 * stays valid until the next rxqueue_pop()/push()/destroy().
 */

typedef struct rxqueue rxqueue_t;

rxqueue_t *rxqueue_create(size_t initial_capacity);
void rxqueue_destroy(rxqueue_t *queue);

/* Appends bytes to the frame being assembled. */
evergram_status_t rxqueue_push(rxqueue_t *queue, const void *data, size_t len);

/* Marks the frame being assembled as complete. Empty frames are discarded. */
evergram_status_t rxqueue_end_frame(rxqueue_t *queue);

/* Drops all data, complete frames included. */
void rxqueue_clear(rxqueue_t *queue);

bool rxqueue_has_frame(const rxqueue_t *queue);
size_t rxqueue_frame_count(const rxqueue_t *queue);

/* Front frame. Returns NULL when no complete frame is queued. */
const uint8_t *rxqueue_frame(const rxqueue_t *queue, size_t *len);

/* Discards the front frame. No-op when the queue is empty. */
void rxqueue_pop(rxqueue_t *queue);

#endif /* EVERGRAM_RXQUEUE_H */
