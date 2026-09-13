#ifndef EVERGRAM_H
#define EVERGRAM_H

#include "evergram/bot.h"
#include "evergram/status.h"
#include "evergram/types.h"

/*
 * evergram-sdk-c: C17 client for the Evergram gateway.
 *
 * Lifecycle:
 *   client = evergram_create(&options);   // copies wallet/device, no I/O
 *   evergram_on_message(client, cb);
 *   evergram_start(client);
 *   while (running) evergram_poll(client, 100);
 *   evergram_destroy(client);
 *
 * evergram_start() only opens the socket; authentication completes
 * asynchronously and is reported through the connected callback. Register
 * callbacks before evergram_start().
 *
 * Every declaration carrying EVERGRAM_API is part of the public ABI; the rest
 * of the library is compiled with hidden visibility.
 */

/* Returns NULL and leaves errno untouched on invalid options or OOM. */
EVERGRAM_API evergram_t *evergram_create(const evergram_options_t *options);

/* Accepts NULL. Zeroes secrets before releasing them. */
EVERGRAM_API void evergram_destroy(evergram_t *eg);

/* Opens the websocket. Idempotent while already connected. */
EVERGRAM_API evergram_status_t evergram_start(evergram_t *eg);

/* Services the transport for up to timeout_ms. Returns EVERGRAM_ERR_TIMEOUT
 * when nothing happened, which callers may treat as "keep polling". */
EVERGRAM_API evergram_status_t evergram_poll(evergram_t *eg, int timeout_ms);

/* True only after the gateway accepted the auth response. */
EVERGRAM_API bool evergram_is_connected(const evergram_t *eg);

EVERGRAM_API void evergram_on_message(evergram_t *eg, evergram_message_fn fn);
EVERGRAM_API void evergram_on_message_edited(evergram_t *eg, evergram_message_edited_fn fn);
EVERGRAM_API void evergram_on_message_deleted(evergram_t *eg, evergram_message_deleted_fn fn);
EVERGRAM_API void evergram_on_reaction(evergram_t *eg, evergram_reaction_fn fn);
EVERGRAM_API void evergram_on_typing(evergram_t *eg, evergram_typing_fn fn);
EVERGRAM_API void evergram_on_error(evergram_t *eg, evergram_error_fn fn);
EVERGRAM_API void evergram_on_connected(evergram_t *eg, evergram_connected_fn fn);
EVERGRAM_API void evergram_on_disconnected(evergram_t *eg, evergram_disconnected_fn fn);

/*
 * Outgoing messages are encrypted with the chat's symmetric key, so the key
 * must have been learned first (from a ChatInfo push, registerDevice, or a
 * chat operation). Without it these return EVERGRAM_ERR_NO_CHAT_KEY and send
 * nothing; use evergram_has_chat_key() to check.
 */
EVERGRAM_API evergram_status_t evergram_send(evergram_t *eg, const char *chat_id,
                                             const char *text);

/* Formats and sends to the chat the message came from. */
EVERGRAM_API evergram_status_t evergram_reply(evergram_t *eg, const evergram_message_t *to,
                                              const char *format, ...) EVERGRAM_PRINTF(3, 4);

/* Sets (removed=false) or clears (removed=true) this device's reaction. */
EVERGRAM_API evergram_status_t evergram_react(evergram_t *eg, const char *chat_id,
                                              const char *message_id, const char *emoji,
                                              bool removed);

/* Replaces the body of a message this identity sent, within the edit window. */
EVERGRAM_API evergram_status_t evergram_edit_message(evergram_t *eg, const char *chat_id,
                                                     const char *message_id, const char *text);

/* "Delete for everyone": an edit tombstone with no body. */
EVERGRAM_API evergram_status_t evergram_delete_message(evergram_t *eg, const char *chat_id,
                                                       const char *message_id);

/* Typing indicator. The gateway rate-limits is_typing=true to 1 per 2s. */
EVERGRAM_API evergram_status_t evergram_send_typing(evergram_t *eg, const char *chat_id,
                                                    bool is_typing);

/*
 * Classifies a decrypted body: plain strings are EVERGRAM_CONTENT_TEXT, JSON
 * envelopes are discriminated by their "type" field. Nothing is copied, so this
 * is cheap enough to call before deciding whether to parse.
 */
EVERGRAM_API evergram_content_type_t evergram_message_content_type(const char *text);

/*
 * Decodes a decrypted body into structured fields. Text bodies just borrow the
 * pointer; payment and audio envelopes are decoded into `out`, whose members
 * borrow from `text` — so the result is valid exactly as long as the text is,
 * and never needs freeing. A body that begins as an object but cannot be read
 * fails loudly instead of being reported as text, because a paywall must never
 * mistake an unreadable receipt for prose.
 */
EVERGRAM_API evergram_status_t evergram_message_content_parse(const char *text,
                                                              evergram_content_t *out);

/* --- payment and audio envelopes ------------------------------------------- */

/*
 * Payment messages are an ordinary chat message carrying JSON. Nothing in the
 * protocol or the gateway verifies a receipt: a paywall must check `tx_hash`
 * against the ledger for the right amount, currency and destination before
 * granting anything. These builders only guarantee the shape both SDKs use.
 */

EVERGRAM_API evergram_status_t evergram_payment_request_build(
    const evergram_payment_request_t *request, char *out, size_t out_size);

EVERGRAM_API evergram_status_t evergram_payment_receipt_build(
    const evergram_payment_receipt_t *receipt, char *out, size_t out_size);

EVERGRAM_API evergram_status_t evergram_payment_sent_build(const evergram_payment_sent_t *sent,
                                                           char *out, size_t out_size);

/* `size` is derived from the base64 payload, as the reference SDK does. */
EVERGRAM_API evergram_status_t evergram_audio_message_build(const char *mime_type,
                                                            uint64_t duration_ms,
                                                            const char *payload_b64, char *out,
                                                            size_t out_size);

/*
 * A fresh UUID v4 for evergram_payment_request_t.request_id. Callers pass their
 * own id when they must know it before the send completes (registering an
 * outstanding request without racing a second message).
 */
EVERGRAM_API evergram_status_t evergram_new_request_id(char *out, size_t out_size);

/* True once the chat's symmetric key has been learned and can be used. */
EVERGRAM_API bool evergram_has_chat_key(const evergram_t *eg, const char *chat_id);

/*
 * Requests a chat sync. The gateway answers with every chat this identity is
 * in, each carrying a key sealed for this device — that is how keys for
 * conversations that already existed are learned. It runs automatically once
 * authentication succeeds, so bots do not have to call it; the explicit call
 * is for re-syncing later.
 */
EVERGRAM_API evergram_status_t evergram_sync_chats(evergram_t *eg);

/* --- chats ---------------------------------------------------------------- */

/*
 * Chat metadata is accumulated locally from every ChatInfo the gateway sends
 * (there is no "get chat" command on the wire), so these never block.
 */

/* Borrowed view of a known chat, or NULL when it is not known yet. Invalidated
 * when that chat is updated by the gateway or the client is destroyed. */
EVERGRAM_API const evergram_chat_info_t *evergram_chat_get(const evergram_t *eg,
                                                           const char *chat_id);

EVERGRAM_API size_t evergram_chat_count(const evergram_t *eg);

/* Visits known chats in insertion order until visit() returns false. */
EVERGRAM_API void evergram_chat_list(const evergram_t *eg,
                                     bool (*visit)(const evergram_chat_info_t *chat,
                                                   void *context),
                                     void *context);

/*
 * Creates a one-on-one or group chat. The gateway seals the new chat key for
 * every participant device, so the key is usable as soon as this returns.
 * timeout_ms < 0 selects the 30s default. *out is borrowed, like
 * evergram_chat_get().
 */
EVERGRAM_API evergram_status_t evergram_chat_create(evergram_t *eg, const char *type,
                                                    const char *const *participants,
                                                    size_t participant_count, int timeout_ms,
                                                    const evergram_chat_info_t **out);

EVERGRAM_API evergram_status_t evergram_chat_leave(evergram_t *eg, const char *chat_id,
                                                   int timeout_ms);

/*
 * Asks the gateway to generate a fresh chat key and reseal it for every
 * participant device. The new key is in place when the call returns. Like the
 * TypeScript SDK, no expected_version is sent, so the contract accepts it.
 */
EVERGRAM_API evergram_status_t evergram_chat_rotate_key(evergram_t *eg, const char *chat_id,
                                                        int timeout_ms);

/* --- groups, invites and blocking ----------------------------------------- */

/* Fires when someone asks to join a group this identity moderates. Approving is
 * evergram_chat_add_participant(); denying is evergram_join_request_deny(). */
EVERGRAM_API void evergram_on_join_request(evergram_t *eg, evergram_join_request_fn fn);

EVERGRAM_API evergram_status_t evergram_chat_add_participant(evergram_t *eg, const char *chat_id,
                                                             const char *identity,
                                                             int timeout_ms);

EVERGRAM_API evergram_status_t evergram_chat_remove_participant(evergram_t *eg,
                                                                const char *chat_id,
                                                                const char *identity,
                                                                int timeout_ms);

/* Groups only: switches the moderated flag that gates join requests. */
EVERGRAM_API evergram_status_t evergram_chat_set_mode(evergram_t *eg, const char *chat_id,
                                                      bool moderated, int timeout_ms);

/* Replaces both role lists wholesale; pass NULL/0 to clear one. */
EVERGRAM_API evergram_status_t evergram_chat_update_roles(evergram_t *eg, const char *chat_id,
                                                          const char *const *admins,
                                                          size_t admin_count,
                                                          const char *const *moderators,
                                                          size_t moderator_count, int timeout_ms);

EVERGRAM_API evergram_status_t evergram_join_request_deny(evergram_t *eg, const char *chat_id,
                                                          const char *identity, int timeout_ms);

/* Creates an invite code. expires_at_ms 0 means "never"; max_uses 0 means
 * "unlimited". Writes the code into invite_code (EVERGRAM_INVITE_CODE_SIZE). */
EVERGRAM_API evergram_status_t evergram_invite_generate(evergram_t *eg, const char *chat_id,
                                                        int64_t expires_at_ms, int32_t max_uses,
                                                        int timeout_ms, char *invite_code,
                                                        size_t invite_code_size);

EVERGRAM_API evergram_status_t evergram_invite_revoke(evergram_t *eg, const char *chat_id,
                                                      int timeout_ms);

/* Inspects a code without joining; reports the chat and membership state. */
EVERGRAM_API evergram_status_t evergram_invite_resolve(evergram_t *eg, const char *invite_code,
                                                       int timeout_ms,
                                                       evergram_invite_info_t *out);

/* Asks to join using a code. Groups with approval on answer with a
 * join request instead of a chat. */
EVERGRAM_API evergram_status_t evergram_chat_request_join(evergram_t *eg, const char *invite_code,
                                                          int timeout_ms);

EVERGRAM_API evergram_status_t evergram_identity_block(evergram_t *eg, const char *identity,
                                                       int timeout_ms);

EVERGRAM_API evergram_status_t evergram_identity_unblock(evergram_t *eg, const char *identity,
                                                         int timeout_ms);

/* Flags an identity to the gateway's moderation queue. */
EVERGRAM_API evergram_status_t evergram_report_user(evergram_t *eg, const char *identity,
                                                    const char *reason, int timeout_ms);

/* --- purchases (Pro subscription) ------------------------------------------ */

/*
 * NOTE: this is the one surface with no counterpart in the reference TypeScript
 * SDK, which ships no method for these messages. It follows the protocol.
 *
 * Buying Pro is two steps because the payment happens on-chain: initiate asks
 * the gateway for a transaction, the application signs and submits it with its
 * own XRPL/Xahau client, and verify reports the resulting hash so the gateway
 * can check it. Nothing here touches a ledger.
 *
 * The answer to initiate is deliberately rich: it carries a transaction to pay,
 * or the subscription/intent that already exists — including another device's
 * open intent, whose transaction is the one that should actually be paid (it
 * wins over a fresh one when both are present).
 */
EVERGRAM_API evergram_status_t evergram_purchase_initiate(evergram_t *eg, const char *account,
                                                          const char *plan,
                                                          const char *pro_observation_jwt,
                                                          int timeout_ms,
                                                          evergram_purchase_t *out);

EVERGRAM_API evergram_status_t evergram_purchase_verify(evergram_t *eg, const char *intent_id,
                                                        const char *tx_hash,
                                                        const char *pro_observation_jwt,
                                                        int timeout_ms,
                                                        evergram_subscription_t *out);

/* Activates a subscription granted without an on-chain purchase. */
EVERGRAM_API evergram_status_t evergram_purchase_claim_pro(evergram_t *eg, const char *account,
                                                           int timeout_ms,
                                                           evergram_subscription_t *out);

/* True while expires_at is in the future. `now_ms` is passed in so the caller
 * (or a test) decides what "now" means. */
EVERGRAM_API bool evergram_subscription_is_active(const evergram_subscription_t *subscription,
                                                  uint64_t now_ms);

/* --- widgets --------------------------------------------------------------- */

/*
 * The embeddable widget: created once by its owner, configured with colors and
 * copy, and either a 1:1 room per visitor (private_chat) or one shared channel
 * (public_group, whose channel_key is the room key visitors join with).
 *
 * The owner's own calls are authenticated. evergram_widget_get_info() is
 * deliberately not: the gateway answers it with no authorization check, which
 * is what lets an embedding page describe its widget. Widget calls are slower
 * than the rest of the protocol — the reference SDK allows them 35 seconds
 * (35000 below).
 */

EVERGRAM_API evergram_status_t evergram_widget_create(evergram_t *eg, const char *name,
                                                      int timeout_ms, evergram_widget_t *out);

/* Every widget this identity owns, retired ones included (`deleted`). The
 * caller provides the array; EVERGRAM_ERR_BUFFER_TOO_SMALL means it was too
 * small, and nothing is written in that case. */
EVERGRAM_API evergram_status_t evergram_widget_list(evergram_t *eg, int timeout_ms,
                                                    evergram_widget_t *out, size_t capacity,
                                                    size_t *count);

EVERGRAM_API evergram_status_t evergram_widget_set_enabled(evergram_t *eg, const char *widget_id,
                                                           bool enabled, int timeout_ms,
                                                           evergram_widget_t *out);

/* Replaces the stored config, sending only the flagged fields. To change one
 * field, start from the config read back by evergram_widget_list(). */
EVERGRAM_API evergram_status_t evergram_widget_set_config(evergram_t *eg, const char *widget_id,
                                                          const evergram_widget_config_t *config,
                                                          int timeout_ms);

/* Retires a widget; its room tokens and channel stop being served. */
EVERGRAM_API evergram_status_t evergram_widget_delete(evergram_t *eg, const char *widget_id,
                                                      int timeout_ms);

EVERGRAM_API evergram_status_t evergram_widget_get_info(evergram_t *eg, const char *widget_id,
                                                        int timeout_ms,
                                                        evergram_widget_info_t *out);

/* --- account access -------------------------------------------------------- */

/*
 * The gateway reports what this identity may do with every successful
 * authentication, and pushes a correction when it changes. evergram_access()
 * returns NULL until the first authentication.
 */
EVERGRAM_API const evergram_access_t *evergram_access(const evergram_t *eg);

/* True while the account is restricted (reputation), the one access change a
 * bot must react to. */
EVERGRAM_API bool evergram_is_restricted(const evergram_t *eg);

/* Fires only when the account BECOMES restricted, never on every push. */
EVERGRAM_API void evergram_on_restricted(evergram_t *eg, evergram_restricted_fn fn);

EVERGRAM_API bool evergram_access_has_capability(const evergram_t *eg, const char *capability);

/* --- chat requests and group invites --------------------------------------- */

/*
 * A one-on-one chat only exists after the recipient approves it, so the
 * requester waits. The recipient is told through evergram_on_chat_request(),
 * which fires for a live request and again from the boot sync for one that was
 * already waiting (once per request, never twice). Deciding either way clears
 * the local "pending" marks; declining does not block the sender.
 */

/* Both callbacks receive a request/invite they must not retain. */
EVERGRAM_API void evergram_on_chat_request(evergram_t *eg, evergram_chat_request_fn fn);
EVERGRAM_API void evergram_on_group_invite(evergram_t *eg, evergram_group_invite_fn fn);

/* A chat this client knew about is gone (left, deleted, or removed from it).
 * Its key is dropped; anything still queued for it is the caller's to discard. */
EVERGRAM_API void evergram_on_chat_removed(evergram_t *eg, evergram_chat_removed_fn fn);

/* Approving creates the chat; `out` (optional) receives the chat record from
 * the store, which already holds its key by the time this returns. */
EVERGRAM_API evergram_status_t evergram_chat_request_accept(evergram_t *eg,
                                                            const char *from_identity,
                                                            int timeout_ms,
                                                            const evergram_chat_info_t **out);

EVERGRAM_API evergram_status_t evergram_chat_request_decline(evergram_t *eg,
                                                             const char *from_identity,
                                                             int timeout_ms);

EVERGRAM_API evergram_status_t evergram_group_invite_accept(evergram_t *eg, const char *chat_id,
                                                            int timeout_ms);

EVERGRAM_API evergram_status_t evergram_group_invite_decline(evergram_t *eg, const char *chat_id,
                                                             int timeout_ms);

/* Outstanding decisions, for diagnostics. */
EVERGRAM_API bool evergram_chat_request_is_pending(const evergram_t *eg,
                                                   const char *from_identity);
EVERGRAM_API bool evergram_group_invite_is_pending(const evergram_t *eg, const char *chat_id);
EVERGRAM_API size_t evergram_pending_chat_request_count(const evergram_t *eg);
EVERGRAM_API size_t evergram_pending_group_invite_count(const evergram_t *eg);

/* --- profile and presence -------------------------------------------------- */

/* Fetches another identity's profile. identity_key is "<chainFamily>:<address>". */
EVERGRAM_API evergram_status_t evergram_profile_get(evergram_t *eg, const char *identity_key,
                                                    int timeout_ms, evergram_profile_t *out);

/*
 * Updates this identity's own profile. Fields left NULL are unchanged, so
 * passing only nickname keeps the current avatar and bio. When out is not NULL
 * it receives the merged profile the gateway echoes back.
 */
EVERGRAM_API evergram_status_t evergram_profile_set(evergram_t *eg, const char *nickname,
                                                    const char *avatar_url, const char *bio,
                                                    int timeout_ms, evergram_profile_t *out);

/* Fire-and-forget: the gateway pushes presence for watched identities. */
EVERGRAM_API evergram_status_t evergram_identities_watch(evergram_t *eg,
                                                         const char *const *identities,
                                                         size_t count);

EVERGRAM_API evergram_status_t evergram_identities_unwatch(evergram_t *eg,
                                                           const char *const *identities,
                                                           size_t count);

/* Presence push for a watched identity. */
EVERGRAM_API void evergram_on_presence(evergram_t *eg, evergram_presence_fn fn);

/* Profile push, for this identity or anyone the gateway decides to relay. */
EVERGRAM_API void evergram_on_profile_updated(evergram_t *eg, evergram_profile_fn fn);

/* --- visitor rooms (ephemeral relay) -------------------------------------- */

/*
 * Ephemeral rooms back the embeddable widget: a visitor opens a room against a
 * widget id, the widget owner's devices are notified, and both sides exchange
 * frames that the gateway relays without being able to read them. Unlike chats,
 * a room has a single peer per side, lives only as long as both sockets do, and
 * its key is generated by whoever creates the room.
 *
 * All visitor calls are fire-and-forget except the create/reclaim pair, so they
 * are safe to call from inside a callback.
 */

/* Visitor side: mints a room key and asks the gateway to reach the widget.
 * `first_message`, when not NULL, is sealed here with that key. On success `out`
 * (optional) describes the new room, including the decrypted first message. */
EVERGRAM_API evergram_status_t evergram_visitor_room_create(evergram_t *eg,
                                                            const char *widget_id,
                                                            const char *visitor_label,
                                                            const char *first_message,
                                                            int timeout_ms,
                                                            evergram_visitor_room_t *out);

/*
 * Re-arms a room this process was a party to before it restarted. The gateway
 * keeps no record of live rooms, so a fresh process can only learn about one
 * from whatever the application persisted itself (the key from the room
 * callback). The joiner slot is then re-claimed on the next authentication,
 * exactly as it is after a reconnect.
 */
EVERGRAM_API evergram_status_t evergram_visitor_register_room(
    evergram_t *eg, const char *room_token, const uint8_t key[EVERGRAM_SYM_KEY_SIZE]);

/* True once this client holds the key for room_token. */
EVERGRAM_API bool evergram_visitor_has_room(const evergram_t *eg, const char *room_token);

/* Copies the room key out. EVERGRAM_ERR_NO_ROOM_KEY when it is not known yet. */
EVERGRAM_API evergram_status_t evergram_visitor_room_key(const evergram_t *eg,
                                                         const char *room_token,
                                                         uint8_t out[EVERGRAM_SYM_KEY_SIZE]);

EVERGRAM_API evergram_status_t evergram_visitor_send_text(evergram_t *eg,
                                                          const char *room_token,
                                                          const char *sender,
                                                          const char *text);

/* A NULL emoji clears the reaction, matching the chat API. */
EVERGRAM_API evergram_status_t evergram_visitor_send_react(evergram_t *eg,
                                                           const char *room_token,
                                                           const char *msg_id,
                                                           const char *emoji);

EVERGRAM_API evergram_status_t evergram_visitor_send_edit(evergram_t *eg,
                                                          const char *room_token,
                                                          const char *msg_id,
                                                          const char *text);

EVERGRAM_API evergram_status_t evergram_visitor_send_remove(evergram_t *eg,
                                                            const char *room_token,
                                                            const char *msg_id);

/* For a 1:1 room `sender` is ignored; channels use it to attribute the signal. */
EVERGRAM_API evergram_status_t evergram_visitor_send_typing(evergram_t *eg,
                                                            const char *room_token,
                                                            bool is_typing,
                                                            const char *sender);

/* Closes the room for both sides and forgets the key. */
EVERGRAM_API evergram_status_t evergram_visitor_end_room(evergram_t *eg, const char *room_token);

/*
 * public_group channels. The channel key (64 hex characters, from the
 * operator's widget configuration) *is* the room key, so every call above works
 * on a channel unchanged once subscribed — only the way the key is learned
 * differs. A channel key that has gone stale is replaced by the one the gateway
 * returns.
 *
 * A channel is not a slot in a room registry, so it cannot be re-claimed with a
 * JOINED frame: the application re-subscribes after a reconnect (the
 * widget-channel-bot example shows where).
 */
EVERGRAM_API evergram_status_t evergram_visitor_subscribe_channel(evergram_t *eg,
                                                                  const char *widget_id,
                                                                  const char *channel_key_hex,
                                                                  int timeout_ms,
                                                                  evergram_visitor_room_t *out);

/* Kick, ban, unban, op, voice or toggle +m on a subscribed channel. The new
 * moderation snapshot is reported through evergram_on_visitor_moderation(). */
EVERGRAM_API evergram_status_t evergram_visitor_moderate_channel(
    evergram_t *eg, const char *room_token, evergram_moderation_action_t action,
    const char *target_participant, int timeout_ms);

/* Announces this client's nickname to the channel roster. `previous_sender`
 * (optional) marks a rename instead of a fresh join. Plaintext by design. */
EVERGRAM_API evergram_status_t evergram_visitor_announce_presence(evergram_t *eg,
                                                                  const char *room_token,
                                                                  const char *sender,
                                                                  const char *previous_sender);

/* Owner side: a room was opened against one of our widgets. Every device of the
 * owner is told, but only the one that claims the room receives frames. */
EVERGRAM_API void evergram_on_visitor_room(evergram_t *eg, evergram_visitor_room_fn fn);

EVERGRAM_API void evergram_on_visitor_text(evergram_t *eg, evergram_visitor_text_fn fn);
EVERGRAM_API void evergram_on_visitor_react(evergram_t *eg, evergram_visitor_react_fn fn);
EVERGRAM_API void evergram_on_visitor_edit(evergram_t *eg, evergram_visitor_edit_fn fn);
EVERGRAM_API void evergram_on_visitor_remove(evergram_t *eg, evergram_visitor_remove_fn fn);
EVERGRAM_API void evergram_on_visitor_typing(evergram_t *eg, evergram_visitor_typing_fn fn);

/* Session state changes: peer claiming/leaving, deliberate close, ejection. */
EVERGRAM_API void evergram_on_visitor_state(evergram_t *eg, evergram_visitor_state_fn fn);

/* Channel (public_group) presence; `joined` distinguishes join from part. */
EVERGRAM_API void evergram_on_visitor_presence(evergram_t *eg,
                                               evergram_visitor_presence_fn fn);

/* Channel moderation snapshot. `state` and its string arrays are valid only for
 * the duration of the call. */
EVERGRAM_API void evergram_on_visitor_moderation(evergram_t *eg,
                                                 evergram_visitor_moderation_fn fn);

/* Visitor side: the room was never claimed before its deadline. */
EVERGRAM_API void evergram_on_visitor_timed_out(evergram_t *eg,
                                                evergram_visitor_timed_out_fn fn);

/* Gateway error context from the most recent rejected request, or NULL. */
EVERGRAM_API const char *evergram_last_error(const evergram_t *eg);
EVERGRAM_API const char *evergram_last_error_code(const evergram_t *eg);

/* Returns the pointer passed as evergram_options_t.user_data, or NULL. */
EVERGRAM_API void *evergram_user_data(const evergram_t *eg);

/*
 * This client's identity key, "<chainFamily>:<address>" (for XRPL, "1:r...").
 * That is the form used in envelope sender fields and in every protocol map
 * key, so it is what callbacks must compare against to recognise their own
 * messages. Never NULL for a successfully created client.
 */
EVERGRAM_API const char *evergram_identity_key(const evergram_t *eg);

/* This client's ledger address alone ("r..." for XRPL), as payment payloads
 * carry it. Never NULL for a successfully created client. */
EVERGRAM_API const char *evergram_address(const evergram_t *eg);

/*
 * Decodes an XRPL address ("r...") into the 20-byte account id that ledger
 * transactions and signing payloads carry, checking its base58 checksum. Only
 * needed by callers that talk to a ledger themselves; the SDK never does.
 */
EVERGRAM_API evergram_status_t evergram_address_to_account_id(
    const char *address, uint8_t out[EVERGRAM_ACCOUNT_ID_BYTES]);

/* Fills length bytes with cryptographically secure random data. */
EVERGRAM_API evergram_status_t evergram_random_bytes(uint8_t *out, size_t length);

/* --- identity ------------------------------------------------------------ */

/*
 * Builds a wallet that authenticates AS account_address while signing with
 * regular_key_seed's keypair. The account must exist on-ledger with a
 * SetRegularKey transaction pointing at that key; the gateway checks it.
 * Requires importing the same behaviour as the TypeScript SDK's
 * walletFromRegularKey().
 */
EVERGRAM_API evergram_status_t evergram_wallet_from_regular_key(const char *account_address,
                                                                const char *regular_key_seed,
                                                                evergram_wallet_t *out);

/* Derives an ed25519 keypair and XRPL address. Fails only on RNG/crypto error. */
EVERGRAM_API evergram_status_t evergram_wallet_generate(evergram_wallet_t *out);

/*
 * Derives the same thing from an existing seed, so a wallet created elsewhere
 * can be used as-is. The seed is either the raw 32-byte ed25519 seed as hex
 * (what the identity file stores) or an XRPL base58 family seed ("sEd...").
 */
EVERGRAM_API evergram_status_t evergram_wallet_from_seed(const char *seed,
                                                         evergram_wallet_t *out);

/* Generates a curve25519 device keypair and its derived device id. */
EVERGRAM_API evergram_status_t evergram_device_generate(evergram_device_t *out);

/* Loads the "key=value\n" identity file written by evergram_identity_save(). */
EVERGRAM_API evergram_status_t evergram_identity_load(const char *path,
                                                      evergram_wallet_t *wallet,
                                                      evergram_device_t *device);

/* Writes the identity file with mode 0600, replacing it atomically. */
EVERGRAM_API evergram_status_t evergram_identity_save(const char *path,
                                                      const evergram_wallet_t *wallet,
                                                      const evergram_device_t *device);

/* Overwrite secret material. Callers should wipe after use. */
EVERGRAM_API void evergram_wallet_wipe(evergram_wallet_t *wallet);
EVERGRAM_API void evergram_device_wipe(evergram_device_t *device);

/* --- diagnostics --------------------------------------------------------- */

/* Default level is EVERGRAM_LOG_INFO. Set it once at startup. */
EVERGRAM_API void evergram_log_set_level(evergram_log_level_t level);

/* Maps "off|error|warn|info|debug|trace"; EVERGRAM_LOG_OFF when unrecognized. */
EVERGRAM_API evergram_log_level_t evergram_log_level_from_name(const char *name);

#endif /* EVERGRAM_H */
