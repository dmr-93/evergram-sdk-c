#include "evergram/bot.h"

#include <sodium.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "backoff.h"
#include "internal.h"

/*
 * Bot layer. Responsibilities kept here (and nowhere else):
 *   - identity persistence across restarts
 *   - reconnect scheduling with exponential backoff + jitter
 *   - deferred delivery (mailbox) for payloads whose chat key is not known yet
 *   - a nickname applied once per connection
 * Everything protocol-shaped stays in the client; this layer only sequences it.
 */

#define BOT_PATH_SIZE 512
#define BOT_POLL_INTERVAL_MS 100
/* Bounds mirror the TypeScript SDK's mailbox caps. */
#define BOT_MAX_PENDING_PER_CHAT 500u
#define BOT_MAX_PENDING_CHATS 200u
#define BOT_MAX_PENDING_TOTAL 4000u
/* Bounds the deferred-operation queue. */
#define BOT_MAX_ACTIONS 256u
/* Rooms tracked for handle lookups. Old rooms are evicted first. */
#define BOT_MAX_ROOMS 64u

typedef struct {
    char chat_id[EVERGRAM_CHAT_ID_SIZE];
    uint8_t *frame;
    size_t frame_len;
} bot_pending_t;

static void drain_actions(evergram_bot_t *bot);
static void drain_mailbox(evergram_bot_t *bot);

typedef enum {
    BOT_ACTION_NONE = 0,
    BOT_ACTION_APPROVE_JOIN,
    BOT_ACTION_ADD_PARTICIPANT,
    BOT_ACTION_DENY_JOIN,
    BOT_ACTION_REMOVE_PARTICIPANT,
    BOT_ACTION_PROMOTE_MODERATOR,
    BOT_ACTION_REPORT_USER,
    BOT_ACTION_LEAVE_CHAT,
    BOT_ACTION_ROTATE_KEY,
    BOT_ACTION_ACCEPT_CHAT_REQUEST,
    BOT_ACTION_DECLINE_CHAT_REQUEST,
    BOT_ACTION_ACCEPT_GROUP_INVITE,
    BOT_ACTION_DECLINE_GROUP_INVITE,
    BOT_ACTION_SEND,
} bot_action_kind_t;

typedef struct {
    bot_action_kind_t kind;
    char chat_id[EVERGRAM_CHAT_ID_SIZE];
    char identity[EVERGRAM_IDENTITY_SIZE];
    char note[EVERGRAM_BIO_SIZE];
    char *text; /* owned, for BOT_ACTION_SEND */
} bot_action_t;


/* Meta kept per room so a later frame can carry a complete handle. */
typedef struct {
    evergram_visitor_handle_t handle;
} bot_room_t;

struct evergram_bot {
    evergram_t *client;
    evergram_wallet_t wallet;
    evergram_device_t device;
    void *user_data;

    char url[EVERGRAM_URL_SIZE];
    char identity_path[BOT_PATH_SIZE];
    char name[EVERGRAM_NICKNAME_SIZE];
    bool has_name;

    bool online;
    bool should_stop;
    bool nickname_applied;
    unsigned reconnect_attempts;
    uint64_t next_attempt_ms; /* 0 = nothing scheduled */

    bot_pending_t *pending;
    size_t pending_count;
    size_t pending_capacity;

    bot_action_t *actions;
    size_t action_count;
    size_t action_capacity;

    evergram_message_fn on_message;
    evergram_message_edited_fn on_message_edited;
    evergram_message_deleted_fn on_message_deleted;
    evergram_reaction_fn on_reaction;
    evergram_typing_fn on_typing;
    evergram_join_request_fn on_join_request;
    evergram_chat_request_fn on_chat_request;
    evergram_group_invite_fn on_group_invite;
    evergram_chat_removed_fn on_chat_removed;
    evergram_presence_fn on_presence;
    evergram_profile_fn on_profile_updated;
    evergram_error_fn on_error;
    evergram_connected_fn on_connected;
    evergram_disconnected_fn on_disconnected;

    bot_room_t rooms[BOT_MAX_ROOMS];
    size_t room_count;

    evergram_bot_visitor_room_fn on_visitor_room;
    evergram_bot_visitor_message_fn on_visitor_message;
    evergram_bot_visitor_react_fn on_visitor_react;
    evergram_bot_visitor_edit_fn on_visitor_edit;
    evergram_bot_visitor_remove_fn on_visitor_remove;
    evergram_bot_visitor_typing_fn on_visitor_typing;
    evergram_bot_visitor_state_fn on_visitor_state;
    evergram_bot_visitor_timed_out_fn on_visitor_timed_out;
};

/* --- client callbacks ------------------------------------------------------ */

static void bot_on_chat_request(evergram_t *eg, const evergram_chat_request_t *request);
static void bot_on_group_invite(evergram_t *eg, const evergram_group_invite_t *invite);
static void bot_on_chat_removed(evergram_t *eg, const char *chat_id);
static void bot_on_visitor_room(evergram_t *eg, const evergram_visitor_room_t *room);
static void bot_on_visitor_text(evergram_t *eg, const char *room_token,
                                const evergram_relay_text_t *event);
static void bot_on_visitor_react(evergram_t *eg, const char *room_token,
                                 const evergram_relay_react_t *event);
static void bot_on_visitor_edit(evergram_t *eg, const char *room_token,
                                const evergram_relay_edit_t *event);
static void bot_on_visitor_remove(evergram_t *eg, const char *room_token,
                                  const evergram_relay_remove_t *event);
static void bot_on_visitor_typing(evergram_t *eg, const char *room_token,
                                  const evergram_relay_typing_t *event);
static void bot_on_visitor_state(evergram_t *eg, const char *room_token,
                                 const evergram_visitor_state_event_t *event);
static void bot_on_visitor_timed_out(evergram_t *eg, const char *room_token);

/* --- mailbox -------------------------------------------------------------- */

static size_t pending_for_chat(const evergram_bot_t *bot, const char *chat_id) {
    size_t count = 0;
    for (size_t i = 0; i < bot->pending_count; i++) {
        if (strcmp(bot->pending[i].chat_id, chat_id) == 0) {
            count++;
        }
    }
    return count;
}

static size_t pending_chats(const evergram_bot_t *bot) {
    size_t chats = 0;
    for (size_t i = 0; i < bot->pending_count; i++) {
        bool seen = false;
        for (size_t j = 0; j < i && !seen; j++) {
            seen = strcmp(bot->pending[j].chat_id, bot->pending[i].chat_id) == 0;
        }
        if (!seen) {
            chats++;
        }
    }
    return chats;
}

static bool pending_contains(const evergram_bot_t *bot, const char *chat_id, const uint8_t *frame,
                             size_t len) {
    for (size_t i = 0; i < bot->pending_count; i++) {
        if (bot->pending[i].frame_len == len && strcmp(bot->pending[i].chat_id, chat_id) == 0 &&
            memcmp(bot->pending[i].frame, frame, len) == 0) {
            return true;
        }
    }
    return false;
}

static void pending_remove(evergram_bot_t *bot, size_t index) {
    free(bot->pending[index].frame);
    bot->pending_count--;
    if (index != bot->pending_count) {
        memmove(&bot->pending[index], &bot->pending[index + 1],
                (bot->pending_count - index) * sizeof(bot->pending[0]));
    }
}

/* Defer hook: keeps a frame whose chat key is still unknown. */
static void bot_defer(void *context, const char *chat_id, const uint8_t *frame, size_t len) {
    evergram_bot_t *bot = context;
    if (bot == NULL || chat_id == NULL || frame == NULL || len == 0) {
        return;
    }

    if (bot->pending_count >= BOT_MAX_PENDING_TOTAL) {
        EG_WARN("mailbox full (%zu frames), dropping one from %s", bot->pending_count, chat_id);
        return;
    }
    if (pending_for_chat(bot, chat_id) >= BOT_MAX_PENDING_PER_CHAT) {
        EG_WARN("mailbox cap for chat %s reached, dropping frame", chat_id);
        return;
    }
    if (pending_chats(bot) >= BOT_MAX_PENDING_CHATS) {
        const bool known_chat = pending_for_chat(bot, chat_id) > 0;
        if (!known_chat) {
            EG_WARN("mailbox holds %u chats already, dropping frame for %s",
                    BOT_MAX_PENDING_CHATS, chat_id);
            return;
        }
    }
    if (pending_contains(bot, chat_id, frame, len)) {
        return; /* duplicate deferral of the same frame */
    }

    if (bot->pending_count == bot->pending_capacity) {
        size_t capacity = bot->pending_capacity ? bot->pending_capacity * 2u : 8u;
        bot_pending_t *grown = realloc(bot->pending, capacity * sizeof(*grown));
        if (grown == NULL) {
            return;
        }
        bot->pending = grown;
        bot->pending_capacity = capacity;
    }

    uint8_t *copy = malloc(len);
    if (copy == NULL) {
        return;
    }
    memcpy(copy, frame, len);

    bot_pending_t *entry = &bot->pending[bot->pending_count];
    evergram_copy_bounded(entry->chat_id, sizeof(entry->chat_id), chat_id);
    entry->frame = copy;
    entry->frame_len = len;
    bot->pending_count++;

    EG_DEBUG("mailbox: holding a frame for %s until its key arrives", chat_id);
}

/* Re-dispatches frames whose chat key has since been learned. */
static void drain_mailbox(evergram_bot_t *bot) {
    for (size_t i = 0; i < bot->pending_count;) {
        if (!evergram_has_chat_key(bot->client, bot->pending[i].chat_id)) {
            i++;
            continue;
        }

        EG_DEBUG("mailbox: delivering a held frame for %s", bot->pending[i].chat_id);
        uint8_t *frame = bot->pending[i].frame;
        size_t len = bot->pending[i].frame_len;
        /* Detach before dispatching so a nested defer cannot free it. */
        bot->pending[i].frame = NULL;
        pending_remove(bot, i);
        parser_dispatch(bot->client, frame, len);
        free(frame);
    }
}

/* --- client callbacks ----------------------------------------------------- */

static void bot_on_connected(evergram_t *eg) {
    evergram_bot_t *bot = evergram_user_data(eg);
    if (bot == NULL) {
        return;
    }

    bot->online = true;
    bot->reconnect_attempts = 0;
    bot->next_attempt_ms = 0;
    bot->nickname_applied = false; /* reapply after every reconnect */

    if (bot->on_connected != NULL) {
        bot->on_connected(eg);
    }
}

static void bot_on_disconnected(evergram_t *eg) {
    evergram_bot_t *bot = evergram_user_data(eg);
    if (bot != NULL) {
        bot->online = false;
        if (!bot->should_stop && bot->next_attempt_ms == 0) {
            bot->reconnect_attempts++;
            uint32_t delay = evergram_backoff_delay_ms(bot->reconnect_attempts,
                                                       EVERGRAM_BACKOFF_BASE_MS,
                                                       EVERGRAM_BACKOFF_CAP_MS,
                                                       EVERGRAM_BACKOFF_JITTER_MS);
            bot->next_attempt_ms = evergram_now_ms() + delay;
            EG_INFO("connection lost, reconnecting in %u ms (attempt %u)", delay,
                    bot->reconnect_attempts);
        }
    }

    if (bot != NULL && bot->on_disconnected != NULL) {
        bot->on_disconnected(eg);
    }
}

static void bot_on_error(evergram_t *eg, evergram_status_t status, const char *detail) {
    evergram_bot_t *bot = evergram_user_data(eg);
    if (bot != NULL && bot->on_error != NULL) {
        bot->on_error(eg, status, detail);
    }
}

/* --- visitor rooms --------------------------------------------------------- */

static bot_room_t *find_room(evergram_bot_t *bot, const char *room_token) {
    if (bot == NULL || room_token == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < bot->room_count; i++) {
        if (strcmp(bot->rooms[i].handle.room_token, room_token) == 0) {
            return &bot->rooms[i];
        }
    }
    return NULL;
}

/* O(1) eviction: the table is a set, not a queue, so order carries no meaning. */
static void remove_room(evergram_bot_t *bot, const char *room_token) {
    if (bot == NULL || room_token == NULL) {
        return;
    }
    for (size_t i = 0; i < bot->room_count; i++) {
        if (strcmp(bot->rooms[i].handle.room_token, room_token) == 0) {
            bot->rooms[i] = bot->rooms[bot->room_count - 1u];
            bot->room_count--;
            return;
        }
    }
}

static void remember_room(evergram_bot_t *bot, const evergram_visitor_room_t *room) {
    if (bot == NULL || room == NULL || room->room_token[0] == '\0') {
        return;
    }
    bot_room_t *existing = find_room(bot, room->room_token);
    if (existing == NULL) {
        if (bot->room_count == BOT_MAX_ROOMS) {
            EG_WARN("room table full, forgetting %s", bot->rooms[0].handle.room_token);
            remove_room(bot, bot->rooms[0].handle.room_token);
        }
        existing = &bot->rooms[bot->room_count];
        bot->room_count++;
        memset(existing, 0, sizeof(*existing));
        evergram_copy_bounded(existing->handle.room_token, sizeof(existing->handle.room_token),
                              room->room_token);
    }

    evergram_copy_bounded(existing->handle.widget_id, sizeof(existing->handle.widget_id),
                          room->widget_id);
    evergram_copy_bounded(existing->handle.visitor_label, sizeof(existing->handle.visitor_label),
                          room->visitor_label);
    evergram_copy_bounded(existing->handle.origin, sizeof(existing->handle.origin), room->origin);
}

static void bot_on_visitor_room(evergram_t *eg, const evergram_visitor_room_t *room) {
    evergram_bot_t *bot = evergram_user_data(eg);
    if (bot == NULL || room == NULL) {
        return;
    }

    remember_room(bot, room);
    if (bot->on_visitor_room != NULL) {
        bot->on_visitor_room(bot, room->room_token, &find_room(bot, room->room_token)->handle,
                             room->has_first_message ? &room->first_message : NULL);
    }
}

static void bot_on_visitor_text(evergram_t *eg, const char *room_token,
                                const evergram_relay_text_t *event) {
    evergram_bot_t *bot = evergram_user_data(eg);
    if (bot == NULL || bot->on_visitor_message == NULL) {
        return;
    }
    bot_room_t *room = find_room(bot, room_token);
    bot->on_visitor_message(bot, room_token, room != NULL ? &room->handle : NULL, event);
}

static void bot_on_visitor_react(evergram_t *eg, const char *room_token,
                                 const evergram_relay_react_t *event) {
    evergram_bot_t *bot = evergram_user_data(eg);
    if (bot == NULL || bot->on_visitor_react == NULL) {
        return;
    }
    bot_room_t *room = find_room(bot, room_token);
    bot->on_visitor_react(bot, room_token, room != NULL ? &room->handle : NULL, event);
}

static void bot_on_visitor_edit(evergram_t *eg, const char *room_token,
                                const evergram_relay_edit_t *event) {
    evergram_bot_t *bot = evergram_user_data(eg);
    if (bot == NULL || bot->on_visitor_edit == NULL) {
        return;
    }
    bot_room_t *room = find_room(bot, room_token);
    bot->on_visitor_edit(bot, room_token, room != NULL ? &room->handle : NULL, event);
}

static void bot_on_visitor_remove(evergram_t *eg, const char *room_token,
                                  const evergram_relay_remove_t *event) {
    evergram_bot_t *bot = evergram_user_data(eg);
    if (bot == NULL || bot->on_visitor_remove == NULL) {
        return;
    }
    bot_room_t *room = find_room(bot, room_token);
    bot->on_visitor_remove(bot, room_token, room != NULL ? &room->handle : NULL, event);
}

static void bot_on_visitor_typing(evergram_t *eg, const char *room_token,
                                  const evergram_relay_typing_t *event) {
    evergram_bot_t *bot = evergram_user_data(eg);
    if (bot == NULL || bot->on_visitor_typing == NULL) {
        return;
    }
    bot_room_t *room = find_room(bot, room_token);
    bot->on_visitor_typing(bot, room_token, room != NULL ? &room->handle : NULL, event);
}

/* Final states drop the room, so later frames report a NULL handle. */
static void bot_on_visitor_state(evergram_t *eg, const char *room_token,
                                 const evergram_visitor_state_event_t *event) {
    evergram_bot_t *bot = evergram_user_data(eg);
    if (bot == NULL || event == NULL) {
        return;
    }

    bot_room_t *room = find_room(bot, room_token);
    if (bot->on_visitor_state != NULL) {
        bot->on_visitor_state(bot, room_token, room != NULL ? &room->handle : NULL, event);
    }

    switch (event->state) {
    case EVERGRAM_VISITOR_STATE_ENDED:
    case EVERGRAM_VISITOR_STATE_CLAIMED_ELSEWHERE:
    case EVERGRAM_VISITOR_STATE_KICKED:
        remove_room(bot, room_token);
        break;
    default:
        break;
    }
}

static void bot_on_visitor_timed_out(evergram_t *eg, const char *room_token) {
    evergram_bot_t *bot = evergram_user_data(eg);
    if (bot == NULL) {
        return;
    }
    remove_room(bot, room_token);
    if (bot->on_visitor_timed_out != NULL) {
        bot->on_visitor_timed_out(bot, room_token);
    }
}

/* --- visitor sends --------------------------------------------------------- */

static evergram_t *visitor_client(evergram_bot_t *bot, const evergram_visitor_handle_t *handle) {
    if (bot == NULL || handle == NULL || handle->room_token[0] == '\0') {
        return NULL;
    }
    return bot->client;
}

evergram_status_t evergram_bot_visitor_reply(evergram_bot_t *bot,
                                             const evergram_visitor_handle_t *handle,
                                             const char *text) {
    evergram_t *eg = visitor_client(bot, handle);
    if (eg == NULL || text == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    return evergram_visitor_send_text(eg, handle->room_token, NULL, text);
}

evergram_status_t evergram_bot_visitor_reply_with_typing(evergram_bot_t *bot,
                                                         const evergram_visitor_handle_t *handle,
                                                         const char *format, ...) {
    evergram_t *eg = visitor_client(bot, handle);
    if (eg == NULL || format == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    char text[EVERGRAM_TEXT_SIZE];
    va_list args;
    va_start(args, format);
    int length = vsnprintf(text, sizeof(text), format, args);
    va_end(args);

    if (length < 0 || (size_t)length >= sizeof(text)) {
        sodium_memzero(text, sizeof(text));
        return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }

    /* Both are plain sends, so no deferral is needed. The indicator is
     * cosmetic: a room that closed in between must not stop the reply. */
    evergram_visitor_send_typing(eg, handle->room_token, true, NULL);
    evergram_visitor_send_typing(eg, handle->room_token, false, NULL);

    evergram_status_t status = evergram_visitor_send_text(eg, handle->room_token, NULL, text);
    sodium_memzero(text, sizeof(text));
    return status;
}

evergram_status_t evergram_bot_visitor_react(evergram_bot_t *bot,
                                             const evergram_visitor_handle_t *handle,
                                             const char *msg_id, const char *emoji) {
    evergram_t *eg = visitor_client(bot, handle);
    if (eg == NULL || msg_id == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    return evergram_visitor_send_react(eg, handle->room_token, msg_id, emoji);
}

evergram_status_t evergram_bot_visitor_edit(evergram_bot_t *bot,
                                            const evergram_visitor_handle_t *handle,
                                            const char *msg_id, const char *text) {
    evergram_t *eg = visitor_client(bot, handle);
    if (eg == NULL || msg_id == NULL || text == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    return evergram_visitor_send_edit(eg, handle->room_token, msg_id, text);
}

evergram_status_t evergram_bot_visitor_remove(evergram_bot_t *bot,
                                              const evergram_visitor_handle_t *handle,
                                              const char *msg_id) {
    evergram_t *eg = visitor_client(bot, handle);
    if (eg == NULL || msg_id == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    return evergram_visitor_send_remove(eg, handle->room_token, msg_id);
}

evergram_status_t evergram_bot_visitor_typing(evergram_bot_t *bot,
                                              const evergram_visitor_handle_t *handle,
                                              bool is_typing) {
    evergram_t *eg = visitor_client(bot, handle);
    if (eg == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    return evergram_visitor_send_typing(eg, handle->room_token, is_typing, NULL);
}

evergram_status_t evergram_bot_visitor_end(evergram_bot_t *bot,
                                           const evergram_visitor_handle_t *handle) {
    evergram_t *eg = visitor_client(bot, handle);
    if (eg == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    evergram_status_t status = evergram_visitor_end_room(eg, handle->room_token);
    remove_room(bot, handle->room_token);
    return status;
}

evergram_status_t evergram_bot_visitor_register(evergram_bot_t *bot, const char *room_token,
                                                const uint8_t key[EVERGRAM_SYM_KEY_SIZE],
                                                const evergram_visitor_handle_t *handle) {
    if (bot == NULL || room_token == NULL || key == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    evergram_status_t status = evergram_visitor_register_room(bot->client, room_token, key);
    if (status != EVERGRAM_OK) {
        return status;
    }

    if (handle != NULL) {
        evergram_visitor_room_t room;
        memset(&room, 0, sizeof(room));
        evergram_copy_bounded(room.room_token, sizeof(room.room_token), room_token);
        evergram_copy_bounded(room.widget_id, sizeof(room.widget_id), handle->widget_id);
        evergram_copy_bounded(room.visitor_label, sizeof(room.visitor_label),
                              handle->visitor_label);
        evergram_copy_bounded(room.origin, sizeof(room.origin), handle->origin);
        remember_room(bot, &room);
    }
    return EVERGRAM_OK;
}

void evergram_bot_visitor_forget(evergram_bot_t *bot, const char *room_token) {
    remove_room(bot, room_token);
}

static void bot_on_message(evergram_t *eg, const evergram_message_t *message) {
    evergram_bot_t *bot = evergram_user_data(eg);
    if (bot != NULL && bot->on_message != NULL) {
        bot->on_message(eg, message);
    }
}

static void bot_on_message_edited(evergram_t *eg, const evergram_message_edited_t *message) {
    evergram_bot_t *bot = evergram_user_data(eg);
    if (bot != NULL && bot->on_message_edited != NULL) {
        bot->on_message_edited(eg, message);
    }
}

static void bot_on_message_deleted(evergram_t *eg, const evergram_message_deleted_t *message) {
    evergram_bot_t *bot = evergram_user_data(eg);
    if (bot != NULL && bot->on_message_deleted != NULL) {
        bot->on_message_deleted(eg, message);
    }
}

static void bot_on_reaction(evergram_t *eg, const evergram_reaction_t *reaction) {
    evergram_bot_t *bot = evergram_user_data(eg);
    if (bot != NULL && bot->on_reaction != NULL) {
        bot->on_reaction(eg, reaction);
    }
}

static void bot_on_typing(evergram_t *eg, const evergram_typing_event_t *event) {
    evergram_bot_t *bot = evergram_user_data(eg);
    if (bot != NULL && bot->on_typing != NULL) {
        bot->on_typing(eg, event);
    }
}

static void bot_on_join_request(evergram_t *eg, const evergram_join_request_t *request) {
    evergram_bot_t *bot = evergram_user_data(eg);
    if (bot != NULL && bot->on_join_request != NULL) {
        bot->on_join_request(eg, request);
    }
}

static void bot_on_presence(evergram_t *eg, const evergram_presence_t *presence) {
    evergram_bot_t *bot = evergram_user_data(eg);
    if (bot != NULL && bot->on_presence != NULL) {
        bot->on_presence(eg, presence);
    }
}

static void bot_on_profile_updated(evergram_t *eg, const evergram_profile_t *profile) {
    evergram_bot_t *bot = evergram_user_data(eg);
    if (bot != NULL && bot->on_profile_updated != NULL) {
        bot->on_profile_updated(eg, profile);
    }
}

/* --- lifecycle ------------------------------------------------------------ */

static evergram_status_t bot_load_identity(evergram_bot_t *bot) {
    if (bot->identity_path[0] == '\0') {
        evergram_status_t status = evergram_wallet_generate(&bot->wallet);
        if (status != EVERGRAM_OK) {
            return status;
        }
        return evergram_device_generate(&bot->device);
    }

    if (evergram_identity_load(bot->identity_path, &bot->wallet, &bot->device) == EVERGRAM_OK) {
        EG_INFO("identity loaded from %s (%s)", bot->identity_path, bot->wallet.address);
        return EVERGRAM_OK;
    }

    EG_INFO("no usable identity at %s, generating one", bot->identity_path);
    evergram_status_t status = evergram_wallet_generate(&bot->wallet);
    if (status == EVERGRAM_OK) {
        status = evergram_device_generate(&bot->device);
    }
    if (status != EVERGRAM_OK) {
        return status;
    }

    if (evergram_identity_save(bot->identity_path, &bot->wallet, &bot->device) != EVERGRAM_OK) {
        /* Not fatal: the bot can still run with an in-memory identity. */
        EG_WARN("identity could not be saved to %s", bot->identity_path);
    }
    return EVERGRAM_OK;
}

evergram_bot_t *evergram_bot_create(const evergram_bot_options_t *options) {
    if (options == NULL || options->url == NULL || options->url[0] == '\0') {
        return NULL;
    }
    if (strlen(options->url) >= EVERGRAM_URL_SIZE) {
        return NULL;
    }
    if (options->identity_path != NULL && strlen(options->identity_path) >= BOT_PATH_SIZE) {
        return NULL;
    }
    if (options->name != NULL && strlen(options->name) >= EVERGRAM_NICKNAME_SIZE) {
        return NULL;
    }

    evergram_bot_t *bot = calloc(1, sizeof(*bot));
    if (bot == NULL) {
        return NULL;
    }

    snprintf(bot->url, sizeof(bot->url), "%s", options->url);
    if (options->identity_path != NULL) {
        snprintf(bot->identity_path, sizeof(bot->identity_path), "%s", options->identity_path);
    }
    if (options->name != NULL) {
        snprintf(bot->name, sizeof(bot->name), "%s", options->name);
        bot->has_name = true;
    }
    bot->user_data = options->user_data;

    if (bot_load_identity(bot) != EVERGRAM_OK) {
        evergram_wallet_wipe(&bot->wallet);
        free(bot);
        return NULL;
    }

    const evergram_options_t client_options = {
        .url = bot->url,
        .wallet = &bot->wallet,
        .device = &bot->device,
        .platform = options->platform,
        .user_data = bot, /* callbacks recover the bot from the client */
    };

    bot->client = evergram_create(&client_options);
    if (bot->client == NULL) {
        evergram_wallet_wipe(&bot->wallet);
        evergram_device_wipe(&bot->device);
        free(bot);
        return NULL;
    }

    evergram_set_defer_hook(bot->client, bot_defer, bot);
    evergram_on_message(bot->client, bot_on_message);
    evergram_on_message_edited(bot->client, bot_on_message_edited);
    evergram_on_message_deleted(bot->client, bot_on_message_deleted);
    evergram_on_reaction(bot->client, bot_on_reaction);
    evergram_on_typing(bot->client, bot_on_typing);
    evergram_on_join_request(bot->client, bot_on_join_request);
    evergram_on_chat_request(bot->client, bot_on_chat_request);
    evergram_on_group_invite(bot->client, bot_on_group_invite);
    evergram_on_chat_removed(bot->client, bot_on_chat_removed);
    evergram_on_presence(bot->client, bot_on_presence);
    evergram_on_profile_updated(bot->client, bot_on_profile_updated);
    evergram_on_error(bot->client, bot_on_error);
    evergram_on_connected(bot->client, bot_on_connected);
    evergram_on_disconnected(bot->client, bot_on_disconnected);
    evergram_on_visitor_room(bot->client, bot_on_visitor_room);
    evergram_on_visitor_text(bot->client, bot_on_visitor_text);
    evergram_on_visitor_react(bot->client, bot_on_visitor_react);
    evergram_on_visitor_edit(bot->client, bot_on_visitor_edit);
    evergram_on_visitor_remove(bot->client, bot_on_visitor_remove);
    evergram_on_visitor_typing(bot->client, bot_on_visitor_typing);
    evergram_on_visitor_state(bot->client, bot_on_visitor_state);
    evergram_on_visitor_timed_out(bot->client, bot_on_visitor_timed_out);

    EG_DEBUG("bot created for %s as %s", bot->url, bot->wallet.address);
    return bot;
}

void evergram_bot_destroy(evergram_bot_t *bot) {
    if (bot == NULL) {
        return;
    }

    for (size_t i = 0; i < bot->pending_count; i++) {
        free(bot->pending[i].frame);
    }
    free(bot->pending);
    for (size_t i = 0; i < bot->action_count; i++) {
        free(bot->actions[i].text);
    }
    free(bot->actions);

    evergram_destroy(bot->client);
    evergram_wallet_wipe(&bot->wallet);
    evergram_device_wipe(&bot->device);
    sodium_memzero(bot, sizeof(*bot));
    free(bot);
}

evergram_status_t evergram_bot_start(evergram_bot_t *bot) {
    if (bot == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    evergram_status_t status = evergram_start(bot->client);
    if (status != EVERGRAM_OK) {
        bot->reconnect_attempts++;
        uint32_t delay = evergram_backoff_delay_ms(bot->reconnect_attempts,
                                                   EVERGRAM_BACKOFF_BASE_MS,
                                                   EVERGRAM_BACKOFF_CAP_MS,
                                                   EVERGRAM_BACKOFF_JITTER_MS);
        bot->next_attempt_ms = evergram_now_ms() + delay;
        EG_WARN("initial connection failed, retrying in %u ms", delay);
    }
    return status;
}

/* Runs outside any callback, so blocking calls are allowed here. */
static void apply_nickname(evergram_bot_t *bot) {
    if (!bot->has_name || bot->nickname_applied || !evergram_is_connected(bot->client)) {
        return;
    }

    bot->nickname_applied = true;
    evergram_status_t status =
        evergram_profile_set(bot->client, bot->name, NULL, NULL, -1, NULL);
    if (status != EVERGRAM_OK) {
        EG_WARN("could not set nickname %s: %s", bot->name, evergram_status_str(status));
    }
}

static void maybe_reconnect(evergram_bot_t *bot) {
    if (bot->should_stop || bot->next_attempt_ms == 0 || evergram_is_connected(bot->client)) {
        return;
    }
    if (evergram_now_ms() < bot->next_attempt_ms) {
        return;
    }

    bot->next_attempt_ms = 0;
    EG_INFO("reconnecting (attempt %u)", bot->reconnect_attempts);

    evergram_status_t status = evergram_start(bot->client);
    if (status != EVERGRAM_OK) {
        bot->reconnect_attempts++;
        uint32_t delay = evergram_backoff_delay_ms(bot->reconnect_attempts,
                                                   EVERGRAM_BACKOFF_BASE_MS,
                                                   EVERGRAM_BACKOFF_CAP_MS,
                                                   EVERGRAM_BACKOFF_JITTER_MS);
        bot->next_attempt_ms = evergram_now_ms() + delay;
        EG_WARN("reconnect failed (%s), next attempt in %u ms", evergram_status_str(status),
                delay);
    }
}

evergram_status_t evergram_bot_poll(evergram_bot_t *bot, int timeout_ms) {
    if (bot == NULL || timeout_ms < 0) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    maybe_reconnect(bot);

    evergram_status_t status = evergram_poll(bot->client, timeout_ms);

    apply_nickname(bot);
    drain_actions(bot);
    drain_mailbox(bot);

    return status;
}

evergram_status_t evergram_bot_run(evergram_bot_t *bot) {
    if (bot == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    evergram_status_t status = evergram_bot_start(bot);
    if (status != EVERGRAM_OK && bot->next_attempt_ms == 0) {
        return status;
    }

    while (!bot->should_stop) {
        evergram_status_t polled = evergram_bot_poll(bot, BOT_POLL_INTERVAL_MS);
        if (polled != EVERGRAM_OK && polled != EVERGRAM_ERR_TIMEOUT &&
            polled != EVERGRAM_ERR_NOT_CONNECTED) {
            EG_ERROR("poll failed: %s", evergram_status_str(polled));
            return polled;
        }
    }

    return EVERGRAM_OK;
}

void evergram_bot_stop(evergram_bot_t *bot) {
    if (bot != NULL) {
        bot->should_stop = true;
    }
}

evergram_t *evergram_bot_client(evergram_bot_t *bot) {
    return bot != NULL ? bot->client : NULL;
}

evergram_status_t evergram_bot_status(const evergram_bot_t *bot) {
    if (bot == NULL || bot->client == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    return evergram_is_connected(bot->client) ? EVERGRAM_OK : EVERGRAM_ERR_NOT_CONNECTED;
}

evergram_bot_t *evergram_bot_from_client(const evergram_t *eg) {
    return evergram_user_data(eg);
}

void *evergram_bot_user_data(const evergram_bot_t *bot) {
    return bot != NULL ? bot->user_data : NULL;
}

bool evergram_bot_is_online(const evergram_bot_t *bot) {
    return bot != NULL && bot->online;
}

size_t evergram_bot_pending_count(const evergram_bot_t *bot) {
    return bot != NULL ? bot->pending_count : 0;
}

unsigned evergram_bot_reconnect_attempts(const evergram_bot_t *bot) {
    return bot != NULL ? bot->reconnect_attempts : 0;
}

/* --- handler registration -------------------------------------------------- */

void evergram_bot_on_message(evergram_bot_t *bot, evergram_message_fn fn) {
    if (bot != NULL) {
        bot->on_message = fn;
    }
}

void evergram_bot_on_message_edited(evergram_bot_t *bot, evergram_message_edited_fn fn) {
    if (bot != NULL) {
        bot->on_message_edited = fn;
    }
}

void evergram_bot_on_message_deleted(evergram_bot_t *bot, evergram_message_deleted_fn fn) {
    if (bot != NULL) {
        bot->on_message_deleted = fn;
    }
}

void evergram_bot_on_reaction(evergram_bot_t *bot, evergram_reaction_fn fn) {
    if (bot != NULL) {
        bot->on_reaction = fn;
    }
}

void evergram_bot_on_typing(evergram_bot_t *bot, evergram_typing_fn fn) {
    if (bot != NULL) {
        bot->on_typing = fn;
    }
}

void evergram_bot_on_join_request(evergram_bot_t *bot, evergram_join_request_fn fn) {
    if (bot != NULL) {
        bot->on_join_request = fn;
    }
}

void evergram_bot_on_presence(evergram_bot_t *bot, evergram_presence_fn fn) {
    if (bot != NULL) {
        bot->on_presence = fn;
    }
}

void evergram_bot_on_profile_updated(evergram_bot_t *bot, evergram_profile_fn fn) {
    if (bot != NULL) {
        bot->on_profile_updated = fn;
    }
}

void evergram_bot_on_error(evergram_bot_t *bot, evergram_error_fn fn) {
    if (bot != NULL) {
        bot->on_error = fn;
    }
}

static void bot_on_chat_request(evergram_t *eg, const evergram_chat_request_t *request) {
    evergram_bot_t *bot = evergram_user_data(eg);
    if (bot != NULL && bot->on_chat_request != NULL) {
        bot->on_chat_request(eg, request);
    }
}

static void bot_on_group_invite(evergram_t *eg, const evergram_group_invite_t *invite) {
    evergram_bot_t *bot = evergram_user_data(eg);
    if (bot != NULL && bot->on_group_invite != NULL) {
        bot->on_group_invite(eg, invite);
    }
}

static void bot_on_chat_removed(evergram_t *eg, const char *chat_id) {
    evergram_bot_t *bot = evergram_user_data(eg);
    if (bot != NULL && bot->on_chat_removed != NULL) {
        bot->on_chat_removed(eg, chat_id);
    }
}

void evergram_bot_on_chat_request(evergram_bot_t *bot, evergram_chat_request_fn fn) {
    if (bot != NULL) {
        bot->on_chat_request = fn;
    }
}

void evergram_bot_on_group_invite(evergram_bot_t *bot, evergram_group_invite_fn fn) {
    if (bot != NULL) {
        bot->on_group_invite = fn;
    }
}

void evergram_bot_on_chat_removed(evergram_bot_t *bot, evergram_chat_removed_fn fn) {
    if (bot != NULL) {
        bot->on_chat_removed = fn;
    }
}

void evergram_bot_on_visitor_room(evergram_bot_t *bot, evergram_bot_visitor_room_fn fn) {
    if (bot != NULL) {
        bot->on_visitor_room = fn;
    }
}

void evergram_bot_on_visitor_message(evergram_bot_t *bot, evergram_bot_visitor_message_fn fn) {
    if (bot != NULL) {
        bot->on_visitor_message = fn;
    }
}

void evergram_bot_on_visitor_react(evergram_bot_t *bot, evergram_bot_visitor_react_fn fn) {
    if (bot != NULL) {
        bot->on_visitor_react = fn;
    }
}

void evergram_bot_on_visitor_edit(evergram_bot_t *bot, evergram_bot_visitor_edit_fn fn) {
    if (bot != NULL) {
        bot->on_visitor_edit = fn;
    }
}

void evergram_bot_on_visitor_remove(evergram_bot_t *bot, evergram_bot_visitor_remove_fn fn) {
    if (bot != NULL) {
        bot->on_visitor_remove = fn;
    }
}

void evergram_bot_on_visitor_typing(evergram_bot_t *bot, evergram_bot_visitor_typing_fn fn) {
    if (bot != NULL) {
        bot->on_visitor_typing = fn;
    }
}

void evergram_bot_on_visitor_state(evergram_bot_t *bot, evergram_bot_visitor_state_fn fn) {
    if (bot != NULL) {
        bot->on_visitor_state = fn;
    }
}

void evergram_bot_on_visitor_timed_out(evergram_bot_t *bot, evergram_bot_visitor_timed_out_fn fn) {
    if (bot != NULL) {
        bot->on_visitor_timed_out = fn;
    }
}

void evergram_bot_on_connected(evergram_bot_t *bot, evergram_connected_fn fn) {
    if (bot != NULL) {
        bot->on_connected = fn;
    }
}

void evergram_bot_on_disconnected(evergram_bot_t *bot, evergram_disconnected_fn fn) {
    if (bot != NULL) {
        bot->on_disconnected = fn;
    }
}

/* --- deferred operations --------------------------------------------------- */

static evergram_status_t enqueue_action(evergram_bot_t *bot, bot_action_kind_t kind,
                                        const char *chat_id, const char *identity,
                                        const char *note) {
    if (bot == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (bot->action_count >= BOT_MAX_ACTIONS) {
        EG_WARN("deferred action queue is full, dropping operation %d", (int)kind);
        return EVERGRAM_ERR_STATE;
    }

    if (bot->action_count == bot->action_capacity) {
        size_t capacity = bot->action_capacity ? bot->action_capacity * 2u : 8u;
        bot_action_t *grown = realloc(bot->actions, capacity * sizeof(*grown));
        if (grown == NULL) {
            return EVERGRAM_ERR_NO_MEMORY;
        }
        bot->actions = grown;
        bot->action_capacity = capacity;
    }

    bot_action_t *action = &bot->actions[bot->action_count];
    memset(action, 0, sizeof(*action));
    action->kind = kind;
    if (chat_id != NULL) {
        evergram_copy_bounded(action->chat_id, sizeof(action->chat_id), chat_id);
    }
    if (identity != NULL) {
        evergram_copy_bounded(action->identity, sizeof(action->identity), identity);
    }
    if (note != NULL) {
        evergram_copy_bounded(action->note, sizeof(action->note), note);
    }
    bot->action_count++;
    return EVERGRAM_OK;
}

/* Builds current moderators + identity and replaces the role lists wholesale. */
static evergram_status_t promote_moderator(evergram_t *client, const char *chat_id,
                                           const char *identity) {
    const evergram_chat_info_t *chat = evergram_chat_get(client, chat_id);
    size_t existing = chat != NULL ? chat->moderator_count : 0;

    const char **moderators = calloc(existing + 1u, sizeof(*moderators));
    if (moderators == NULL) {
        return EVERGRAM_ERR_NO_MEMORY;
    }
    for (size_t i = 0; i < existing; i++) {
        moderators[i] = chat->moderators[i];
    }
    moderators[existing] = identity;

    const char **admins = NULL;
    size_t admin_count = 0;
    if (chat != NULL && chat->admin_count > 0) {
        admins = calloc(chat->admin_count, sizeof(*admins));
        if (admins == NULL) {
            free(moderators);
            return EVERGRAM_ERR_NO_MEMORY;
        }
        for (size_t i = 0; i < chat->admin_count; i++) {
            admins[i] = chat->admins[i];
        }
        admin_count = chat->admin_count;
    }

    evergram_status_t status = evergram_chat_update_roles(client, chat_id, admins, admin_count,
                                                          moderators, existing + 1u, -1);
    free(moderators);
    free(admins);
    return status;
}

static void run_action(evergram_bot_t *bot, const bot_action_t *action) {
    evergram_t *client = bot->client;
    evergram_status_t status;

    switch (action->kind) {
    case BOT_ACTION_APPROVE_JOIN:
        /* Approving a join request is adding the participant. */
        status = evergram_chat_add_participant(client, action->chat_id, action->identity, -1);
        break;
    case BOT_ACTION_ADD_PARTICIPANT:
        status = evergram_chat_add_participant(client, action->chat_id, action->identity, -1);
        break;
    case BOT_ACTION_DENY_JOIN:
        status = evergram_join_request_deny(client, action->chat_id, action->identity, -1);
        break;
    case BOT_ACTION_REMOVE_PARTICIPANT:
        status = evergram_chat_remove_participant(client, action->chat_id, action->identity, -1);
        break;
    case BOT_ACTION_PROMOTE_MODERATOR:
        status = promote_moderator(client, action->chat_id, action->identity);
        break;
    case BOT_ACTION_REPORT_USER:
        status = evergram_report_user(client, action->identity, action->note, -1);
        break;
    case BOT_ACTION_LEAVE_CHAT:
        status = evergram_chat_leave(client, action->chat_id, -1);
        break;
    case BOT_ACTION_ROTATE_KEY:
        status = evergram_chat_rotate_key(client, action->chat_id, -1);
        break;
    case BOT_ACTION_ACCEPT_CHAT_REQUEST:
        status = evergram_chat_request_accept(client, action->identity, -1, NULL);
        break;
    case BOT_ACTION_DECLINE_CHAT_REQUEST:
        status = evergram_chat_request_decline(client, action->identity, -1);
        break;
    case BOT_ACTION_ACCEPT_GROUP_INVITE:
        status = evergram_group_invite_accept(client, action->chat_id, -1);
        break;
    case BOT_ACTION_DECLINE_GROUP_INVITE:
        status = evergram_group_invite_decline(client, action->chat_id, -1);
        break;
    case BOT_ACTION_SEND:
        status = evergram_send(client, action->chat_id, action->text != NULL ? action->text : "");
        break;
    default:
        return;
    }

    if (status != EVERGRAM_OK) {
        EG_WARN("deferred operation %d failed: %s", (int)action->kind,
                evergram_status_str(status));
    } else {
        EG_DEBUG("deferred operation %d done", (int)action->kind);
    }
}

/* Executes at most one queued operation, outside any transport callback. */
static void drain_actions(evergram_bot_t *bot) {
    if (bot->action_count == 0 || !evergram_is_connected(bot->client)) {
        return;
    }

    bot_action_t action = bot->actions[0];
    bot->action_count--;
    if (bot->action_count > 0) {
        memmove(&bot->actions[0], &bot->actions[1], bot->action_count * sizeof(bot->actions[0]));
    }

    run_action(bot, &action);
    free(action.text);
}

evergram_status_t evergram_bot_approve_join(evergram_bot_t *bot, const char *chat_id,
                                            const char *identity) {
    if (chat_id == NULL || identity == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    return enqueue_action(bot, BOT_ACTION_APPROVE_JOIN, chat_id, identity, NULL);
}

evergram_status_t evergram_bot_deny_join(evergram_bot_t *bot, const char *chat_id,
                                         const char *identity) {
    if (chat_id == NULL || identity == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    return enqueue_action(bot, BOT_ACTION_DENY_JOIN, chat_id, identity, NULL);
}

evergram_status_t evergram_bot_remove_participant(evergram_bot_t *bot, const char *chat_id,
                                                  const char *identity) {
    if (chat_id == NULL || identity == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    return enqueue_action(bot, BOT_ACTION_REMOVE_PARTICIPANT, chat_id, identity, NULL);
}

evergram_status_t evergram_bot_promote_moderator(evergram_bot_t *bot, const char *chat_id,
                                                 const char *identity) {
    if (chat_id == NULL || identity == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    return enqueue_action(bot, BOT_ACTION_PROMOTE_MODERATOR, chat_id, identity, NULL);
}

evergram_status_t evergram_bot_report_user(evergram_bot_t *bot, const char *identity,
                                           const char *reason) {
    if (identity == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    return enqueue_action(bot, BOT_ACTION_REPORT_USER, NULL, identity, reason);
}

evergram_status_t evergram_bot_leave_chat(evergram_bot_t *bot, const char *chat_id) {
    if (chat_id == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    return enqueue_action(bot, BOT_ACTION_LEAVE_CHAT, chat_id, NULL, NULL);
}

/* Grants access to someone who is not asking to join (a paid member, say). */
evergram_status_t evergram_bot_add_participant(evergram_bot_t *bot, const char *chat_id,
                                               const char *identity) {
    if (chat_id == NULL || chat_id[0] == '\0' || identity == NULL || identity[0] == '\0') {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    return enqueue_action(bot, BOT_ACTION_ADD_PARTICIPANT, chat_id, identity, NULL);
}

/* --- request decisions ----------------------------------------------------- */

/* A chat request is keyed by the requester, not by a chat: no chat exists yet. */
static bool require_key(const char *key) {
    return key != NULL && key[0] != '\0';
}

evergram_status_t evergram_bot_accept_chat_request(evergram_bot_t *bot,
                                                   const char *from_identity) {
    if (!require_key(from_identity)) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    return enqueue_action(bot, BOT_ACTION_ACCEPT_CHAT_REQUEST, NULL, from_identity, NULL);
}

evergram_status_t evergram_bot_decline_chat_request(evergram_bot_t *bot,
                                                    const char *from_identity) {
    if (!require_key(from_identity)) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    return enqueue_action(bot, BOT_ACTION_DECLINE_CHAT_REQUEST, NULL, from_identity, NULL);
}

evergram_status_t evergram_bot_accept_group_invite(evergram_bot_t *bot, const char *chat_id) {
    if (!require_key(chat_id)) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    return enqueue_action(bot, BOT_ACTION_ACCEPT_GROUP_INVITE, chat_id, NULL, NULL);
}

evergram_status_t evergram_bot_decline_group_invite(evergram_bot_t *bot, const char *chat_id) {
    if (!require_key(chat_id)) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    return enqueue_action(bot, BOT_ACTION_DECLINE_GROUP_INVITE, chat_id, NULL, NULL);
}

evergram_status_t evergram_bot_rotate_key(evergram_bot_t *bot, const char *chat_id) {
    if (chat_id == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    return enqueue_action(bot, BOT_ACTION_ROTATE_KEY, chat_id, NULL, NULL);
}

evergram_status_t evergram_bot_send_later(evergram_bot_t *bot, const char *chat_id,
                                           const char *text) {
    if (bot == NULL || chat_id == NULL || text == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    evergram_status_t status = enqueue_action(bot, BOT_ACTION_SEND, chat_id, NULL, NULL);
    if (status != EVERGRAM_OK) {
        return status;
    }

    size_t len = strlen(text);
    char *copy = malloc(len + 1u);
    if (copy == NULL) {
        bot->action_count--; /* undo the enqueue */
        return EVERGRAM_ERR_NO_MEMORY;
    }
    memcpy(copy, text, len + 1u);
    bot->actions[bot->action_count - 1].text = copy;
    return EVERGRAM_OK;
}

size_t evergram_bot_action_count(const evergram_bot_t *bot) {
    return bot != NULL ? bot->action_count : 0;
}

evergram_status_t evergram_bot_reply_with_typing(evergram_bot_t *bot,
                                                 const evergram_message_t *to,
                                                 const char *format, ...) {
    if (bot == NULL || to == NULL || format == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    /* Both are plain sends, so no deferral is needed. */
    evergram_send_typing(bot->client, to->chat_id, true);

    char text[EVERGRAM_TEXT_SIZE];
    va_list args;
    va_start(args, format);
    int length = vsnprintf(text, sizeof(text), format, args);
    va_end(args);

    if (length < 0 || (size_t)length >= sizeof(text)) {
        sodium_memzero(text, sizeof(text));
        return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }

    evergram_status_t status = evergram_send(bot->client, to->chat_id, text);
    sodium_memzero(text, sizeof(text));
    return status;
}

uint32_t evergram_typing_delay_ms(size_t text_length) {
    size_t scaled = text_length * 35u;
    if (scaled < 500u) {
        return 500u;
    }
    if (scaled > 2000u) {
        return 2000u;
    }
    return (uint32_t)scaled;
}
