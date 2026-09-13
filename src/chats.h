#ifndef EVERGRAM_CHATS_H
#define EVERGRAM_CHATS_H

#include <stdbool.h>
#include <stddef.h>

#include "evergram/status.h"
#include "evergram/types.h"

/*
 * Local chat store: chatId -> chat metadata.
 *
 * The gateway has no "get chat" command, so chat metadata is accumulated from
 * every message that can carry a ChatInfo (registerDeviceResponse,
 * createChatResponse, queryChatsResponse, rotateChatVersionResponse,
 * acceptChatRequestResponse). Lookups are therefore local and never block.
 *
 * Ownership: the store owns each entry's participant array. Entries returned by
 * chats_find()/chats_at() are borrowed and stay valid until that chat is
 * upserted again or the store is destroyed.
 */

typedef struct chats chats_t;

chats_t *chats_create(void);
void chats_destroy(chats_t *chats);

/* Inserts or replaces a chat. Replaces the participant array wholesale. */
evergram_status_t chats_upsert(chats_t *chats, const evergram_chat_info_t *record);

/* Borrowed entry, or NULL when the chat is unknown. */
const evergram_chat_info_t *chats_find(const chats_t *chats, const char *chat_id);

const evergram_chat_info_t *chats_at(const chats_t *chats, size_t index);
size_t chats_count(const chats_t *chats);

/* Drops a chat and its participants. */
void chats_remove(chats_t *chats, const char *chat_id);

/* True when the given identity participates in the chat. */
bool chats_has_participant(const evergram_chat_info_t *chat, const char *identity_key);

#endif /* EVERGRAM_CHATS_H */
