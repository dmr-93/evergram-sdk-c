#include "chats.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHATS_INITIAL_CAPACITY 8u

struct chats {
    evergram_chat_info_t *entries;
    size_t count;
    size_t capacity;
};

/* Every owned list in a chat entry is handled the same way. */
typedef struct {
    char ***names;
    size_t *count;
} name_list_t;

static name_list_t chat_participants(evergram_chat_info_t *chat) {
    return (name_list_t){&chat->participants, &chat->participant_count};
}

static name_list_t chat_admins(evergram_chat_info_t *chat) {
    return (name_list_t){&chat->admins, &chat->admin_count};
}

static name_list_t chat_moderators(evergram_chat_info_t *chat) {
    return (name_list_t){&chat->moderators, &chat->moderator_count};
}

static void free_names(name_list_t list) {
    if (*list.names == NULL) {
        *list.count = 0;
        return;
    }

    for (size_t i = 0; i < *list.count; i++) {
        free((*list.names)[i]);
    }
    free(*list.names);
    *list.names = NULL;
    *list.count = 0;
}

static evergram_status_t set_names(name_list_t list, char *const *source, size_t count) {
    free_names(list);

    if (count == 0 || source == NULL) {
        return EVERGRAM_OK;
    }

    char **names = calloc(count, sizeof(*names));
    if (names == NULL) {
        return EVERGRAM_ERR_NO_MEMORY;
    }

    for (size_t i = 0; i < count; i++) {
        if (source[i] == NULL) {
            continue;
        }

        size_t len = strlen(source[i]);
        names[i] = malloc(len + 1u);
        if (names[i] == NULL) {
            for (size_t j = 0; j < i; j++) {
                free(names[j]);
            }
            free(names);
            return EVERGRAM_ERR_NO_MEMORY;
        }
        memcpy(names[i], source[i], len + 1u);
    }

    *list.names = names;
    *list.count = count;
    return EVERGRAM_OK;
}

static evergram_chat_info_t *find_entry(chats_t *chats, const char *chat_id) {
    for (size_t i = 0; i < chats->count; i++) {
        if (strcmp(chats->entries[i].chat_id, chat_id) == 0) {
            return &chats->entries[i];
        }
    }
    return NULL;
}

chats_t *chats_create(void) {
    chats_t *chats = calloc(1, sizeof(*chats));
    if (chats == NULL) {
        return NULL;
    }

    chats->entries = calloc(CHATS_INITIAL_CAPACITY, sizeof(*chats->entries));
    if (chats->entries == NULL) {
        free(chats);
        return NULL;
    }
    chats->capacity = CHATS_INITIAL_CAPACITY;
    return chats;
}

void chats_destroy(chats_t *chats) {
    if (chats == NULL) {
        return;
    }

    for (size_t i = 0; i < chats->count; i++) {
        free_names(chat_participants(&chats->entries[i]));
        free_names(chat_admins(&chats->entries[i]));
        free_names(chat_moderators(&chats->entries[i]));
    }
    free(chats->entries);
    free(chats);
}

evergram_status_t chats_upsert(chats_t *chats, const evergram_chat_info_t *record) {
    if (chats == NULL || record == NULL || record->chat_id[0] == '\0') {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    evergram_chat_info_t *entry = find_entry(chats, record->chat_id);
    bool is_new = entry == NULL;

    if (is_new) {
        if (chats->count == chats->capacity) {
            size_t capacity = chats->capacity * 2u;
            evergram_chat_info_t *grown = realloc(chats->entries, capacity * sizeof(*grown));
            if (grown == NULL) {
                return EVERGRAM_ERR_NO_MEMORY;
            }
            chats->entries = grown;
            chats->capacity = capacity;
        }
        entry = &chats->entries[chats->count];
        memset(entry, 0, sizeof(*entry));
        memcpy(entry->chat_id, record->chat_id, strlen(record->chat_id) + 1u);
    }

    snprintf(entry->type, sizeof(entry->type), "%s", record->type);
    snprintf(entry->name, sizeof(entry->name), "%s", record->name);
    snprintf(entry->created_by, sizeof(entry->created_by), "%s", record->created_by);
    entry->chat_version = record->chat_version;
    entry->meta_version = record->meta_version;

    evergram_status_t status = set_names(chat_participants(entry), record->participants,
                                         record->participant_count);
    if (status == EVERGRAM_OK) {
        status = set_names(chat_admins(entry), record->admins, record->admin_count);
    }
    if (status == EVERGRAM_OK) {
        status = set_names(chat_moderators(entry), record->moderators, record->moderator_count);
    }
    if (status != EVERGRAM_OK) {
        if (is_new) {
            free_names(chat_participants(entry));
            free_names(chat_admins(entry));
            free_names(chat_moderators(entry));
        }
        return status;
    }

    if (is_new) {
        chats->count++;
    }
    return EVERGRAM_OK;
}

const evergram_chat_info_t *chats_find(const chats_t *chats, const char *chat_id) {
    if (chats == NULL || chat_id == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < chats->count; i++) {
        if (strcmp(chats->entries[i].chat_id, chat_id) == 0) {
            return &chats->entries[i];
        }
    }
    return NULL;
}

const evergram_chat_info_t *chats_at(const chats_t *chats, size_t index) {
    if (chats == NULL || index >= chats->count) {
        return NULL;
    }
    return &chats->entries[index];
}

size_t chats_count(const chats_t *chats) {
    return chats != NULL ? chats->count : 0;
}

void chats_remove(chats_t *chats, const char *chat_id) {
    if (chats == NULL || chat_id == NULL) {
        return;
    }

    for (size_t i = 0; i < chats->count; i++) {
        if (strcmp(chats->entries[i].chat_id, chat_id) != 0) {
            continue;
        }

        free_names(chat_participants(&chats->entries[i]));
        free_names(chat_admins(&chats->entries[i]));
        free_names(chat_moderators(&chats->entries[i]));
        chats->count--;
        if (i != chats->count) {
            memmove(&chats->entries[i], &chats->entries[i + 1],
                    (chats->count - i) * sizeof(chats->entries[0]));
        }
        return;
    }
}

bool chats_has_participant(const evergram_chat_info_t *chat, const char *identity_key) {
    if (chat == NULL || identity_key == NULL) {
        return false;
    }

    for (size_t i = 0; i < chat->participant_count; i++) {
        if (chat->participants[i] != NULL && strcmp(chat->participants[i], identity_key) == 0) {
            return true;
        }
    }
    return false;
}
