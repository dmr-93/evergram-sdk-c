#ifndef EVERGRAM_CHATKEYS_H
#define EVERGRAM_CHATKEYS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "e2ee.h"
#include "evergram/status.h"

/*
 * chatId -> 32-byte symmetric key map.
 *
 * Ownership: the store owns its entries; destroy() and remove() wipe the key
 * bytes. Lookup is a linear scan because a bot holds tens of chats, which keeps
 * the structure allocation-light and predictable. Keys are only ever held in
 * memory: nothing here writes them anywhere.
 */

typedef struct chatkeys chatkeys_t;

chatkeys_t *chatkeys_create(void);

/* Wipes every key and frees the store. Accepts NULL. */
void chatkeys_destroy(chatkeys_t *keys);

/* Inserts or replaces the key for chat_id. */
evergram_status_t chatkeys_set(chatkeys_t *keys, const char *chat_id,
                               const uint8_t key[E2EE_KEY_BYTES]);

/*
 * Same, carrying an opaque caller tag. The store never interprets it; the room
 * store uses it to remember which slot this side holds, which decides whether a
 * reconnect must re-claim the room. A plain set() clears the tag to 0.
 */
evergram_status_t chatkeys_set_tagged(chatkeys_t *keys, const char *chat_id,
                                      const uint8_t key[E2EE_KEY_BYTES], unsigned tag);

/* Tag of a known entry, or 0 when unknown. */
unsigned chatkeys_tag(const chatkeys_t *keys, const char *chat_id);

/* Entry at index, in insertion order. False when index is out of range. */
bool chatkeys_at(const chatkeys_t *keys, size_t index, const char **chat_id_out);

/* Borrowed pointer, valid until the next set/remove/destroy. NULL when unknown. */
const uint8_t *chatkeys_get(const chatkeys_t *keys, const char *chat_id);

bool chatkeys_has(const chatkeys_t *keys, const char *chat_id);

void chatkeys_remove(chatkeys_t *keys, const char *chat_id);

size_t chatkeys_count(const chatkeys_t *keys);

#endif /* EVERGRAM_CHATKEYS_H */
