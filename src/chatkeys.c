#include "chatkeys.h"

#include <sodium.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"

#define CHATKEYS_INITIAL_CAPACITY 8u

typedef struct {
    char chat_id[EVERGRAM_CHAT_ID_SIZE];
    uint8_t key[E2EE_KEY_BYTES];
    unsigned tag; /* opaque to this store; see chatkeys.h */
} chatkeys_entry_t;

struct chatkeys {
    chatkeys_entry_t *entries;
    size_t count;
    size_t capacity;
};

static chatkeys_entry_t *find_entry(chatkeys_t *keys, const char *chat_id) {
    for (size_t i = 0; i < keys->count; i++) {
        if (strcmp(keys->entries[i].chat_id, chat_id) == 0) {
            return &keys->entries[i];
        }
    }
    return NULL;
}

chatkeys_t *chatkeys_create(void) {
    chatkeys_t *keys = calloc(1, sizeof(*keys));
    if (keys == NULL) {
        return NULL;
    }

    keys->entries = calloc(CHATKEYS_INITIAL_CAPACITY, sizeof(*keys->entries));
    if (keys->entries == NULL) {
        free(keys);
        return NULL;
    }
    keys->capacity = CHATKEYS_INITIAL_CAPACITY;
    return keys;
}

void chatkeys_destroy(chatkeys_t *keys) {
    if (keys == NULL) {
        return;
    }

    if (keys->entries != NULL) {
        sodium_memzero(keys->entries, keys->capacity * sizeof(*keys->entries));
        free(keys->entries);
    }
    sodium_memzero(keys, sizeof(*keys));
    free(keys);
}

evergram_status_t chatkeys_set(chatkeys_t *keys, const char *chat_id,
                               const uint8_t key[E2EE_KEY_BYTES]) {
    return chatkeys_set_tagged(keys, chat_id, key, 0);
}

evergram_status_t chatkeys_set_tagged(chatkeys_t *keys, const char *chat_id,
                                      const uint8_t key[E2EE_KEY_BYTES], unsigned tag) {
    if (keys == NULL || chat_id == NULL || key == NULL || chat_id[0] == '\0') {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (strlen(chat_id) >= EVERGRAM_CHAT_ID_SIZE) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    chatkeys_entry_t *entry = find_entry(keys, chat_id);
    if (entry == NULL) {
        if (keys->count == keys->capacity) {
            size_t capacity = keys->capacity * 2u;
            chatkeys_entry_t *grown = realloc(keys->entries, capacity * sizeof(*grown));
            if (grown == NULL) {
                return EVERGRAM_ERR_NO_MEMORY;
            }
            keys->entries = grown;
            keys->capacity = capacity;
        }
        entry = &keys->entries[keys->count];
        keys->count++;
        memcpy(entry->chat_id, chat_id, strlen(chat_id) + 1u);
    }

    memcpy(entry->key, key, E2EE_KEY_BYTES);
    entry->tag = tag;
    EG_DEBUG("key stored for %s", chat_id);
    return EVERGRAM_OK;
}

const uint8_t *chatkeys_get(const chatkeys_t *keys, const char *chat_id) {
    if (keys == NULL || chat_id == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < keys->count; i++) {
        if (strcmp(keys->entries[i].chat_id, chat_id) == 0) {
            return keys->entries[i].key;
        }
    }
    return NULL;
}

unsigned chatkeys_tag(const chatkeys_t *keys, const char *chat_id) {
    if (keys == NULL || chat_id == NULL) {
        return 0;
    }
    const chatkeys_entry_t *entry = find_entry((chatkeys_t *)keys, chat_id);
    return entry != NULL ? entry->tag : 0;
}

bool chatkeys_at(const chatkeys_t *keys, size_t index, const char **chat_id_out) {
    if (keys == NULL || index >= keys->count) {
        return false;
    }
    if (chat_id_out != NULL) {
        *chat_id_out = keys->entries[index].chat_id;
    }
    return true;
}

bool chatkeys_has(const chatkeys_t *keys, const char *chat_id) {
    return chatkeys_get(keys, chat_id) != NULL;
}

void chatkeys_remove(chatkeys_t *keys, const char *chat_id) {
    if (keys == NULL || chat_id == NULL) {
        return;
    }

    for (size_t i = 0; i < keys->count; i++) {
        if (strcmp(keys->entries[i].chat_id, chat_id) != 0) {
            continue;
        }

        sodium_memzero(&keys->entries[i], sizeof(keys->entries[i]));
        keys->count--;
        if (i != keys->count) {
            memmove(&keys->entries[i], &keys->entries[i + 1],
                    (keys->count - i) * sizeof(keys->entries[0]));
        }
        return;
    }
}

size_t chatkeys_count(const chatkeys_t *keys) {
    return keys != NULL ? keys->count : 0;
}
