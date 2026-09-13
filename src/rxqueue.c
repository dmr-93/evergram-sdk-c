#include "rxqueue.h"

#include <limits.h>
#include <sodium.h>
#include <stdlib.h>
#include <string.h>

#define RXQUEUE_INITIAL_CAPACITY 4096u
#define RXQUEUE_INITIAL_FRAMES 8u

struct rxqueue {
    uint8_t *buf;
    size_t capacity;
    size_t len;      /* bytes stored in buf */
    size_t consumed; /* bytes at the front already handed to the caller */
    size_t *ends;    /* absolute end offset of each complete frame */
    size_t ends_capacity;
    size_t frame_count;
};

static bool ensure_buffer(rxqueue_t *queue, size_t needed) {
    if (needed <= queue->capacity) {
        return true;
    }

    size_t capacity = queue->capacity ? queue->capacity : RXQUEUE_INITIAL_CAPACITY;
    while (capacity < needed) {
        if (capacity > SIZE_MAX / 2u) {
            return false;
        }
        capacity *= 2u;
    }

    uint8_t *grown = realloc(queue->buf, capacity);
    if (grown == NULL) {
        return false;
    }

    queue->buf = grown;
    queue->capacity = capacity;
    return true;
}

static bool ensure_frame_slot(rxqueue_t *queue) {
    if (queue->frame_count < queue->ends_capacity) {
        return true;
    }

    size_t capacity = queue->ends_capacity ? queue->ends_capacity * 2u : RXQUEUE_INITIAL_FRAMES;
    size_t *grown = realloc(queue->ends, capacity * sizeof(*grown));
    if (grown == NULL) {
        return false;
    }

    queue->ends = grown;
    queue->ends_capacity = capacity;
    return true;
}

rxqueue_t *rxqueue_create(size_t initial_capacity) {
    rxqueue_t *queue = calloc(1, sizeof(*queue));
    if (queue == NULL) {
        return NULL;
    }

    if (initial_capacity > 0 && !ensure_buffer(queue, initial_capacity)) {
        free(queue);
        return NULL;
    }

    return queue;
}

void rxqueue_destroy(rxqueue_t *queue) {
    if (queue == NULL) {
        return;
    }

    if (queue->buf != NULL) {
        sodium_memzero(queue->buf, queue->capacity);
        free(queue->buf);
    }
    free(queue->ends);
    sodium_memzero(queue, sizeof(*queue));
    free(queue);
}

evergram_status_t rxqueue_push(rxqueue_t *queue, const void *data, size_t len) {
    if (queue == NULL || (data == NULL && len > 0)) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (len == 0) {
        return EVERGRAM_OK;
    }
    if (len > SIZE_MAX - queue->len) {
        return EVERGRAM_ERR_NO_MEMORY;
    }
    if (!ensure_buffer(queue, queue->len + len)) {
        return EVERGRAM_ERR_NO_MEMORY;
    }

    memcpy(queue->buf + queue->len, data, len);
    queue->len += len;
    return EVERGRAM_OK;
}

evergram_status_t rxqueue_end_frame(rxqueue_t *queue) {
    if (queue == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    size_t start = queue->frame_count > 0 ? queue->ends[queue->frame_count - 1] : queue->consumed;
    if (queue->len <= start) {
        return EVERGRAM_OK; /* empty message: nothing to deliver */
    }
    if (!ensure_frame_slot(queue)) {
        return EVERGRAM_ERR_NO_MEMORY;
    }

    queue->ends[queue->frame_count] = queue->len;
    queue->frame_count++;
    return EVERGRAM_OK;
}

void rxqueue_clear(rxqueue_t *queue) {
    if (queue == NULL) {
        return;
    }

    if (queue->buf != NULL) {
        sodium_memzero(queue->buf, queue->capacity);
    }
    queue->len = 0;
    queue->consumed = 0;
    queue->frame_count = 0;
}

bool rxqueue_has_frame(const rxqueue_t *queue) {
    return queue != NULL && queue->frame_count > 0;
}

size_t rxqueue_frame_count(const rxqueue_t *queue) {
    return queue != NULL ? queue->frame_count : 0;
}

const uint8_t *rxqueue_frame(const rxqueue_t *queue, size_t *len) {
    if (len != NULL) {
        *len = 0;
    }
    if (queue == NULL || queue->frame_count == 0) {
        return NULL;
    }

    size_t end = queue->ends[0];
    if (len != NULL) {
        *len = end - queue->consumed;
    }
    return queue->buf + queue->consumed;
}

void rxqueue_pop(rxqueue_t *queue) {
    if (queue == NULL || queue->frame_count == 0) {
        return;
    }

    queue->consumed = queue->ends[0];
    queue->frame_count--;
    memmove(queue->ends, queue->ends + 1, queue->frame_count * sizeof(*queue->ends));

    if (queue->consumed == 0) {
        return;
    }

    /* Compact so the buffer does not grow without bound across frames. */
    size_t remaining = queue->len - queue->consumed;
    if (remaining > 0) {
        memmove(queue->buf, queue->buf + queue->consumed, remaining);
    }
    queue->len = remaining;
    for (size_t i = 0; i < queue->frame_count; i++) {
        queue->ends[i] -= queue->consumed;
    }
    queue->consumed = 0;
}
