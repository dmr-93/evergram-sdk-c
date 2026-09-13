#ifndef EVERGRAM_BOT_H
#define EVERGRAM_BOT_H

#include "evergram/status.h"
#include "evergram/types.h"

/*
 * Ergonomic layer over the client, in the spirit of the TypeScript SDK's
 * EvergramBot: it owns identity persistence, reconnects with exponential
 * backoff, re-authenticates, rediscovers chats (the client does that on every
 * successful auth) and holds a mailbox for messages that arrive before their
 * chat key does, delivering them once the key lands.
 *
 * The client it wraps stays reachable through evergram_bot_client() for
 * anything this layer does not cover.
 */

typedef struct evergram_bot evergram_bot_t;

typedef struct {
    const char *url;           /* required: ws:// or wss:// endpoint */
    const char *identity_path; /* optional: loaded, or generated and saved */
    const char *name;          /* optional: nickname applied via setProfile */
    const char *platform;      /* optional: defaults to "Terminal" */
    void *user_data;           /* optional: returned by evergram_bot_user_data */
} evergram_bot_options_t;

EVERGRAM_API evergram_bot_t *evergram_bot_create(const evergram_bot_options_t *options);

/* Stops the bot and releases it, wiping the identity it holds. */
EVERGRAM_API void evergram_bot_destroy(evergram_bot_t *bot);

/* First connection. Later reconnects are automatic. */
EVERGRAM_API evergram_status_t evergram_bot_start(evergram_bot_t *bot);

/*
 * One iteration: pumps the client, fires a reconnect when its backoff timer is
 * due, applies the configured nickname, and drains the mailbox. Returns
 * EVERGRAM_ERR_TIMEOUT when the round was idle, which is not a failure.
 */
EVERGRAM_API evergram_status_t evergram_bot_poll(evergram_bot_t *bot, int timeout_ms);

/* Pumps until evergram_bot_stop() is called. Blocks the calling thread. */
EVERGRAM_API evergram_status_t evergram_bot_run(evergram_bot_t *bot);

/* Asks a running loop to finish. Safe to call from a signal handler or callback. */
EVERGRAM_API void evergram_bot_stop(evergram_bot_t *bot);

EVERGRAM_API evergram_t *evergram_bot_client(evergram_bot_t *bot);
EVERGRAM_API evergram_status_t evergram_bot_status(const evergram_bot_t *bot);

/* Recovers the bot from a callback argument. */
EVERGRAM_API evergram_bot_t *evergram_bot_from_client(const evergram_t *eg);

/* The pointer passed as evergram_bot_options_t.user_data. */
EVERGRAM_API void *evergram_bot_user_data(const evergram_bot_t *bot);

/* True between authentication and the next disconnection. */
EVERGRAM_API bool evergram_bot_is_online(const evergram_bot_t *bot);

/* Mailbox depth, for diagnostics. */
EVERGRAM_API size_t evergram_bot_pending_count(const evergram_bot_t *bot);

/* How many reconnect attempts the current outage has needed. */
EVERGRAM_API unsigned evergram_bot_reconnect_attempts(const evergram_bot_t *bot);

/* --- deferred operations ---------------------------------------------------- */

/*
 * Handlers run inside the transport callback, where blocking calls are illegal
 * (they would re-enter the socket loop). These enqueue the operation instead;
 * evergram_bot_poll() executes at most one queued operation per call, outside
 * any callback. enqueue functions return EVERGRAM_ERR_NO_MEMORY only when the
 * queue itself cannot grow.
 */

EVERGRAM_API evergram_status_t evergram_bot_approve_join(evergram_bot_t *bot, const char *chat_id,
                                                         const char *identity);
EVERGRAM_API evergram_status_t evergram_bot_deny_join(evergram_bot_t *bot, const char *chat_id,
                                                      const char *identity);
/* Adds someone to a chat without a join request (granting paid access, say). */
EVERGRAM_API evergram_status_t evergram_bot_add_participant(evergram_bot_t *bot,
                                                            const char *chat_id,
                                                            const char *identity);
EVERGRAM_API evergram_status_t evergram_bot_remove_participant(evergram_bot_t *bot,
                                                               const char *chat_id,
                                                               const char *identity);
/* Appends identity to the chat's moderator list, preserving the current one. */
EVERGRAM_API evergram_status_t evergram_bot_promote_moderator(evergram_bot_t *bot,
                                                              const char *chat_id,
                                                              const char *identity);
EVERGRAM_API evergram_status_t evergram_bot_report_user(evergram_bot_t *bot, const char *identity,
                                                        const char *reason);
EVERGRAM_API evergram_status_t evergram_bot_leave_chat(evergram_bot_t *bot, const char *chat_id);
EVERGRAM_API evergram_status_t evergram_bot_rotate_key(evergram_bot_t *bot, const char *chat_id);

/* Chat requests are keyed by the requester rather than a chat id, because no
 * chat exists until the request is approved. Group invites are chat-keyed. */
EVERGRAM_API evergram_status_t evergram_bot_accept_chat_request(evergram_bot_t *bot,
                                                                const char *from_identity);
EVERGRAM_API evergram_status_t evergram_bot_decline_chat_request(evergram_bot_t *bot,
                                                                 const char *from_identity);
EVERGRAM_API evergram_status_t evergram_bot_accept_group_invite(evergram_bot_t *bot,
                                                                const char *chat_id);
EVERGRAM_API evergram_status_t evergram_bot_decline_group_invite(evergram_bot_t *bot,
                                                                 const char *chat_id);

/* Queues a message to send after any earlier queued operation, so ordering is
 * preserved (approve a join, then welcome the member). */
EVERGRAM_API evergram_status_t evergram_bot_send_later(evergram_bot_t *bot, const char *chat_id,
                                                       const char *text);

/* Typing-indicator delay scaled to the reply length: min(2000, max(500, len*35)). */
EVERGRAM_API uint32_t evergram_typing_delay_ms(size_t text_length);

/* Queued operations still waiting to run. */
EVERGRAM_API size_t evergram_bot_action_count(const evergram_bot_t *bot);

/* Replies with a typing indicator first; both are plain sends, so this is safe
 * to call from a handler. */
EVERGRAM_API evergram_status_t evergram_bot_reply_with_typing(evergram_bot_t *bot,
                                                              const evergram_message_t *to,
                                                              const char *format, ...)
    EVERGRAM_PRINTF(3, 4);

/* --- visitor rooms ---------------------------------------------------------- */

/*
 * An ongoing visitor conversation. Unlike the one-shot join/invite handles
 * above, this is handed to every visitor handler for the same room so a bot can
 * keep acting on it across the whole exchange. The same sends the plain client
 * exposes are available here; they are fire-and-forget, hence safe to call from
 * a handler.
 */
typedef struct {
    char room_token[EVERGRAM_ROOM_TOKEN_SIZE];
    char widget_id[EVERGRAM_WIDGET_ID_SIZE];
    char visitor_label[EVERGRAM_VISITOR_LABEL_SIZE];
    char origin[EVERGRAM_VISITOR_ORIGIN_SIZE];
} evergram_visitor_handle_t;

/* `sender` NULL means this identity; the bot's configured nickname is not used,
 * because the room layer has no profile lookup. */
EVERGRAM_API evergram_status_t evergram_bot_visitor_reply(evergram_bot_t *bot,
                                                          const evergram_visitor_handle_t *handle,
                                                          const char *text);

/* Raises and clears the typing indicator around the reply; both are plain
 * sends, so this is safe to call from a handler. */
EVERGRAM_API evergram_status_t evergram_bot_visitor_reply_with_typing(
    evergram_bot_t *bot, const evergram_visitor_handle_t *handle, const char *format, ...)
    EVERGRAM_PRINTF(3, 4);

/* A NULL emoji clears the reaction. */
EVERGRAM_API evergram_status_t evergram_bot_visitor_react(evergram_bot_t *bot,
                                                          const evergram_visitor_handle_t *handle,
                                                          const char *msg_id, const char *emoji);

EVERGRAM_API evergram_status_t evergram_bot_visitor_edit(evergram_bot_t *bot,
                                                         const evergram_visitor_handle_t *handle,
                                                         const char *msg_id, const char *text);

EVERGRAM_API evergram_status_t evergram_bot_visitor_remove(evergram_bot_t *bot,
                                                           const evergram_visitor_handle_t *handle,
                                                           const char *msg_id);

EVERGRAM_API evergram_status_t evergram_bot_visitor_typing(evergram_bot_t *bot,
                                                           const evergram_visitor_handle_t *handle,
                                                           bool is_typing);

/* Ends the conversation for both sides. */
EVERGRAM_API evergram_status_t evergram_bot_visitor_end(evergram_bot_t *bot,
                                                        const evergram_visitor_handle_t *handle);

/* Re-arms a room saved before a restart; see evergram_visitor_register_room().
 * The handle is optional and only used to remember the room's labels. */
EVERGRAM_API evergram_status_t evergram_bot_visitor_register(
    evergram_bot_t *bot, const char *room_token, const uint8_t key[EVERGRAM_SYM_KEY_SIZE],
    const evergram_visitor_handle_t *handle);

/* Asks the room list to forget a room, so later frames no longer report it. */
EVERGRAM_API void evergram_bot_visitor_forget(evergram_bot_t *bot, const char *room_token);

/* --- handlers -------------------------------------------------------------- */

EVERGRAM_API void evergram_bot_on_message(evergram_bot_t *bot, evergram_message_fn fn);
EVERGRAM_API void evergram_bot_on_message_edited(evergram_bot_t *bot,
                                                 evergram_message_edited_fn fn);
EVERGRAM_API void evergram_bot_on_message_deleted(evergram_bot_t *bot,
                                                  evergram_message_deleted_fn fn);
EVERGRAM_API void evergram_bot_on_reaction(evergram_bot_t *bot, evergram_reaction_fn fn);
EVERGRAM_API void evergram_bot_on_typing(evergram_bot_t *bot, evergram_typing_fn fn);
EVERGRAM_API void evergram_bot_on_join_request(evergram_bot_t *bot, evergram_join_request_fn fn);
EVERGRAM_API void evergram_bot_on_chat_request(evergram_bot_t *bot, evergram_chat_request_fn fn);
EVERGRAM_API void evergram_bot_on_group_invite(evergram_bot_t *bot, evergram_group_invite_fn fn);
EVERGRAM_API void evergram_bot_on_chat_removed(evergram_bot_t *bot, evergram_chat_removed_fn fn);
EVERGRAM_API void evergram_bot_on_presence(evergram_bot_t *bot, evergram_presence_fn fn);
EVERGRAM_API void evergram_bot_on_profile_updated(evergram_bot_t *bot, evergram_profile_fn fn);
EVERGRAM_API void evergram_bot_on_error(evergram_bot_t *bot, evergram_error_fn fn);
/*
 * Visitor handlers. `room_token` is always set; `handle` is NULL for a frame
 * that arrives for a room this bot no longer tracks (already ended, or claimed
 * by another device), which mirrors the TypeScript SDK passing an undefined
 * handle there. Handlers run inside the transport callback.
 */
typedef void (*evergram_bot_visitor_room_fn)(evergram_bot_t *bot, const char *room_token,
                                             const evergram_visitor_handle_t *handle,
                                             const evergram_relay_text_t *first_message);
typedef void (*evergram_bot_visitor_message_fn)(evergram_bot_t *bot, const char *room_token,
                                                const evergram_visitor_handle_t *handle,
                                                const evergram_relay_text_t *event);
typedef void (*evergram_bot_visitor_react_fn)(evergram_bot_t *bot, const char *room_token,
                                              const evergram_visitor_handle_t *handle,
                                              const evergram_relay_react_t *event);
typedef void (*evergram_bot_visitor_edit_fn)(evergram_bot_t *bot, const char *room_token,
                                             const evergram_visitor_handle_t *handle,
                                             const evergram_relay_edit_t *event);
typedef void (*evergram_bot_visitor_remove_fn)(evergram_bot_t *bot, const char *room_token,
                                               const evergram_visitor_handle_t *handle,
                                               const evergram_relay_remove_t *event);
typedef void (*evergram_bot_visitor_typing_fn)(evergram_bot_t *bot, const char *room_token,
                                               const evergram_visitor_handle_t *handle,
                                               const evergram_relay_typing_t *event);
typedef void (*evergram_bot_visitor_state_fn)(
    evergram_bot_t *bot, const char *room_token, const evergram_visitor_handle_t *handle,
    const evergram_visitor_state_event_t *event);
typedef void (*evergram_bot_visitor_timed_out_fn)(evergram_bot_t *bot, const char *room_token);

/* A room was opened against one of our widgets. */
EVERGRAM_API void evergram_bot_on_visitor_room(evergram_bot_t *bot,
                                               evergram_bot_visitor_room_fn fn);
EVERGRAM_API void evergram_bot_on_visitor_message(evergram_bot_t *bot,
                                                  evergram_bot_visitor_message_fn fn);
EVERGRAM_API void evergram_bot_on_visitor_react(evergram_bot_t *bot,
                                                evergram_bot_visitor_react_fn fn);
EVERGRAM_API void evergram_bot_on_visitor_edit(evergram_bot_t *bot,
                                               evergram_bot_visitor_edit_fn fn);
EVERGRAM_API void evergram_bot_on_visitor_remove(evergram_bot_t *bot,
                                                 evergram_bot_visitor_remove_fn fn);
EVERGRAM_API void evergram_bot_on_visitor_typing(evergram_bot_t *bot,
                                                 evergram_bot_visitor_typing_fn fn);
EVERGRAM_API void evergram_bot_on_visitor_state(evergram_bot_t *bot,
                                                evergram_bot_visitor_state_fn fn);
EVERGRAM_API void evergram_bot_on_visitor_timed_out(evergram_bot_t *bot,
                                                    evergram_bot_visitor_timed_out_fn fn);

EVERGRAM_API void evergram_bot_on_connected(evergram_bot_t *bot, evergram_connected_fn fn);
EVERGRAM_API void evergram_bot_on_disconnected(evergram_bot_t *bot,
                                               evergram_disconnected_fn fn);

#endif /* EVERGRAM_BOT_H */
