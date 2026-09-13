#ifndef EVERGRAM_INTERNAL_H
#define EVERGRAM_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "evergram.h"
#include "chatkeys.h"
#include "chats.h"
#include "e2ee.h"
#include "log.h"
#include "transport.h"

/* Mirrors the TypeScript SDK's default request timeout. */
#define EVERGRAM_DEFAULT_TIMEOUT_MS 30000
#define EVERGRAM_ERROR_CODE_SIZE 64
#define EVERGRAM_ERROR_MESSAGE_SIZE 256

/* Milliseconds since the Unix epoch; 0 when the clock is unavailable. */
static inline uint64_t evergram_now_ms(void) {
    struct timespec now;
    if (timespec_get(&now, TIME_UTC) == 0) {
        return 0;
    }
    return (uint64_t)now.tv_sec * 1000u + (uint64_t)(now.tv_nsec / 1000000);
}

/* Bounded string copy that always terminates. destination_size 0 is a no-op. */
static inline void evergram_copy_bounded(char *destination, size_t destination_size,
                                         const char *source) {
    if (destination_size == 0 || source == NULL) {
        return;
    }

    size_t len = 0;
    while (len + 1u < destination_size && source[len] != '\0') {
        len++;
    }
    memcpy(destination, source, len);
    destination[len] = '\0';
}

/*
 * Private state. Defined once here; every translation unit includes this header
 * so the layout can never drift between modules.
 */

#define EVERGRAM_URL_SIZE 512
#define EVERGRAM_CHALLENGE_SIZE 192
/* Mirrors the TypeScript SDK's MAX_SYNC_CHATS_PAGES bound. */
#define EVERGRAM_MAX_SYNC_PAGES 50

typedef enum {
    EG_STATE_IDLE = 0,
    EG_STATE_CONNECTING,
    EG_STATE_AWAITING_CHALLENGE,
    EG_STATE_AWAITING_AUTH,
    EG_STATE_REGISTERING, /* registerDevice sent; auth is retried on its reply */
    EG_STATE_AUTHENTICATED,
} eg_state_t;

struct Evergram__ServerMessage;
struct Evergram__ResponseStatus;
struct Evergram__Profile;

/*
 * Synchronous request slot. The C API has no futures, so a call blocks while
 * pumping the transport until the matching response lands here. Only one call
 * can be in flight at a time, which keeps matching trivial.
 */
typedef struct {
    bool pending;
    uint32_t request_id;
    uint32_t expected_case;
    bool resolved;
    struct Evergram__ServerMessage *response; /* owned until evergram_call_finish */
} eg_call_t;

/*
 * Deferred-delivery hook. Called when a payload cannot be decrypted purely
 * because its chat key is still unknown; the frame is borrowed and only valid
 * during the call. The bot layer uses it as a mailbox so such messages are
 * delivered once the key arrives instead of being dropped.
 */
typedef void (*evergram_defer_fn)(void *context, const char *chat_id, const uint8_t *frame,
                                  size_t len);

void evergram_set_defer_hook(evergram_t *eg, evergram_defer_fn fn, void *context);

/* Re-claims every room this client holds the joiner slot for. Called after each
 * successful authentication, because the gateway pairs a slot with a live
 * socket. Safe to call when there are no rooms. */
void evergram_rooms_rejoin(evergram_t *eg);

/*
 * Which slot this side holds in an ephemeral room. The owner of a widget is the
 * *joiner*: it must claim the room with a JOINED frame, and re-claim it on every
 * reconnect. Whoever created the room just waits to be joined.
 */
typedef enum {
    EVERGRAM_ROOM_ROLE_JOINER = 0,
    EVERGRAM_ROOM_ROLE_CREATOR = 1,
    /* A channel subscription is re-established by re-subscribing, not by
     * sending JOINED, so the client cannot re-claim it on its own. */
    EVERGRAM_ROOM_ROLE_CHANNEL = 2,
} evergram_room_role_t;

/*
 * Scratch space for the delta-sync maps QueryChats carries. The entries point
 * into the chat store, so the scratch must not outlive a store mutation.
 */
/* Generated protobuf types, referenced by pointer only. */
struct Evergram__QueryChats;
struct Evergram__Widget;
struct Evergram__WidgetConfig;
struct Evergram__GetWidgetInfoResponse;
struct Evergram__InitiatePurchaseResponse;
struct Evergram__Subscription;
struct Evergram__QueryChats__KnownVersionsEntry;
struct Evergram__QueryChats__KnownMetaVersionsEntry;

typedef struct {
    struct Evergram__QueryChats__KnownVersionsEntry *versions;
    struct Evergram__QueryChats__KnownMetaVersionsEntry *meta;
    struct Evergram__QueryChats__KnownVersionsEntry **version_entries;
    struct Evergram__QueryChats__KnownMetaVersionsEntry **meta_entries;
} evergram_known_versions_t;

/* Fills query->known_versions / known_meta_versions from the local chat store.
 * Pair with evergram_known_versions_dispose() before sending. */
evergram_status_t evergram_fill_known_versions(const evergram_t *eg,
                                               struct Evergram__QueryChats *query,
                                               evergram_known_versions_t *scratch);
void evergram_known_versions_dispose(evergram_known_versions_t *scratch);

/* client.c: remembers a pending chat request / group invite, emitting the
 * callback only the first time. Both are idempotent and bounded. */
void evergram_note_chat_request(evergram_t *eg, const evergram_chat_request_t *request);
void evergram_note_group_invite(evergram_t *eg, const evergram_group_invite_t *invite);

/* client.c: drops a chat and its key, then reports it as removed. */
void evergram_forget_chat(evergram_t *eg, const char *chat_id);

/* client.c: maps a purchase answer onto the caller's structs. This is the one
 * surface with no reference-SDK counterpart, so the mapping is tested directly. */
void evergram_purchase_from_initiate(const struct Evergram__InitiatePurchaseResponse *response,
                                     evergram_purchase_t *out);
void evergram_subscription_from_proto(const struct Evergram__Subscription *subscription,
                                      evergram_subscription_t *out);

/* client.c: converts a widget record / fills a WidgetConfig for the wire. Used
 * by the widget calls and by tests, since these two mappings are the whole of
 * the widget wire contract. */
void evergram_widget_from_proto(const struct Evergram__Widget *widget, evergram_widget_t *out);
void evergram_widget_info_from_proto(const struct Evergram__GetWidgetInfoResponse *response,
                                     evergram_widget_info_t *out);
void evergram_fill_widget_config(const evergram_widget_config_t *config,
                                 struct Evergram__WidgetConfig *out);

/* client.c: reports a channel's participant and moderation snapshot. The string
 * arrays stay owned by the response, so callbacks see them as borrowed. */
void evergram_visitor_report_snapshot(evergram_t *eg, const char *room_token,
                                      char *const *participants, size_t participant_count,
                                      bool moderated, char *const *ops, size_t ops_count,
                                      char *const *voiced, size_t voiced_count);

/* client.c: fire-and-forget relay frame for an ephemeral room. */
evergram_status_t evergram_visitor_send_frame(evergram_t *eg, const char *room_token,
                                              evergram_relay_kind_t kind, const char *payload);

struct evergram {
    char url[EVERGRAM_URL_SIZE];
    char platform[EVERGRAM_PLATFORM_SIZE];
    /* "<chainFamily>:<address>", the map key the protocol uses everywhere. */
    char identity_key[EVERGRAM_IDENTITY_SIZE];
    evergram_wallet_t wallet;
    evergram_device_t device;
    void *user_data;

    transport_t *transport;
    chatkeys_t *chat_keys;
    /*
     * Chat requests and group invites that are still awaiting a decision. The
     * boot sync replays them, so remembering them is what keeps a bot from
     * being asked to decide the same request on every reconnect.
     */
    evergram_chat_request_t *pending_requests;
    size_t pending_request_count;
    size_t pending_request_capacity;
    evergram_group_invite_t *pending_invites;
    size_t pending_invite_count;
    size_t pending_invite_capacity;
    chatkeys_t *room_keys; /* room_token -> ephemeral room key */
    chats_t *chats;

    /* Latest access information, from authentication and later pushes. */
    evergram_access_t access;
    bool has_access;

    eg_state_t state;
    uint32_t next_request_id; /* per-client, so no shared mutable counter */
    unsigned sync_pages;      /* pages requested in the current chat sync */
    char challenge[EVERGRAM_CHALLENGE_SIZE + 1];
    size_t challenge_len;

    eg_call_t call;
    char last_error_code[EVERGRAM_ERROR_CODE_SIZE];
    char last_error_message[EVERGRAM_ERROR_MESSAGE_SIZE];

    /* Frame currently being dispatched, for the defer hook. */
    const uint8_t *frame;
    size_t frame_len;
    evergram_defer_fn defer;
    void *defer_context;

    /* Decrypt targets. Reused per message; borrowed by callbacks only for the
     * duration of the call, which is safe because parsing is single-threaded. */
    char text_buffer[EVERGRAM_TEXT_SIZE];
    char ciphertext_buffer[E2EE_CIPHERTEXT_B64_SIZE(EVERGRAM_TEXT_SIZE)];

    evergram_message_fn on_message;
    evergram_message_edited_fn on_message_edited;
    evergram_message_deleted_fn on_message_deleted;
    evergram_join_request_fn on_join_request;
    evergram_presence_fn on_presence;
    evergram_chat_request_fn on_chat_request;
    evergram_group_invite_fn on_group_invite;
    evergram_chat_removed_fn on_chat_removed;
    evergram_restricted_fn on_restricted;
    evergram_profile_fn on_profile_updated;
    evergram_visitor_room_fn on_visitor_room;
    evergram_visitor_text_fn on_visitor_text;
    evergram_visitor_react_fn on_visitor_react;
    evergram_visitor_edit_fn on_visitor_edit;
    evergram_visitor_remove_fn on_visitor_remove;
    evergram_visitor_typing_fn on_visitor_typing;
    evergram_visitor_state_fn on_visitor_state;
    evergram_visitor_presence_fn on_visitor_presence;
    evergram_visitor_moderation_fn on_visitor_moderation;
    evergram_visitor_timed_out_fn on_visitor_timed_out;
    evergram_reaction_fn on_reaction;
    evergram_typing_fn on_typing;
    evergram_error_fn on_error;
    evergram_connected_fn on_connected;
    evergram_disconnected_fn on_disconnected;
};

/* Monotonic request ids; 0 means "unset" on the wire, so ids start at 1. */
uint32_t evergram_take_request_id(evergram_t *eg);

/* Reports to the error callback when one is registered; always logs. */
void evergram_emit_error(evergram_t *eg, evergram_status_t status, const char *detail);

/* client.c: packs and sends a ClientMessage, wiping the buffer afterwards. */
struct Evergram__ClientMessage;
evergram_status_t evergram_send_client_message(evergram_t *eg,
                                               const struct Evergram__ClientMessage *message,
                                               const char *label);

/* One page of chat sync. Empty cursor starts from the beginning. */
evergram_status_t evergram_sync_chats_page(evergram_t *eg, const char *cursor);

/*
 * Sends a request and pumps the transport until its response arrives.
 * On success *response is owned by the caller and must be released with
 * evergram_call_finish(). Returns EVERGRAM_ERR_TIMEOUT when the deadline passes
 * and EVERGRAM_ERR_STATE when another call is already in flight.
 */
evergram_status_t evergram_call(evergram_t *eg, struct Evergram__ClientMessage *message,
                                uint32_t expected_case, int timeout_ms,
                                struct Evergram__ServerMessage **response);

/* Releases the response kept by the last evergram_call and clears the slot. */
void evergram_call_finish(evergram_t *eg);

/*
 * Records the gateway's error context and maps a non-ok status to
 * EVERGRAM_ERR_GATEWAY. EVERGRAM_OK is passed through unchanged.
 */
/* Gateway error context helpers, implemented in client.c. */
evergram_status_t evergram_check_status(evergram_t *eg,
                                        const struct Evergram__ResponseStatus *status);

/*
 * Sets request_id together with its proto2 presence flag. Without the flag the
 * field is simply not serialized, so the gateway has nothing to echo back.
 */
void evergram_set_request_id(struct Evergram__ClientMessage *message, uint32_t request_id);

/* Stores a ChatInfo-shaped record into the local chat store. */
evergram_status_t evergram_apply_chat_record(evergram_t *eg, const evergram_chat_info_t *record);

/* Copies a wire profile into the public shape. NULL yields an empty profile. */
void evergram_profile_from_message(evergram_profile_t *out,
                                   const struct Evergram__Profile *profile);

/* handshake.c */
evergram_status_t handshake_send_auth(evergram_t *eg);
evergram_status_t handshake_send_register_device(evergram_t *eg);

/* parser.c */
void parser_dispatch(evergram_t *eg, const uint8_t *data, size_t len);

#endif /* EVERGRAM_INTERNAL_H */
