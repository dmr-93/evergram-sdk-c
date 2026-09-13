#ifndef EVERGRAM_TYPES_H
#define EVERGRAM_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "evergram/export.h"
#include "evergram/status.h"

/*
 * Public data types.
 *
 * Ownership: every struct here is caller-owned POD. Strings are NUL-terminated
 * and sized to include the terminator. Pointers inside evergram_message_t are
 * borrowed from the decoded frame and are only valid for the duration of the
 * callback that received them.
 */

#define EVERGRAM_ADDRESS_SIZE 64
#define EVERGRAM_SEED_SIZE 65
#define EVERGRAM_ACCOUNT_ID_BYTES 20 /* an XRPL address decodes to this */
#define EVERGRAM_HEX_KEY_SIZE 129 /* 33-byte ed25519 key as hex, plus NUL */
#define EVERGRAM_SYM_KEY_SIZE 32  /* nacl secretbox/box key bytes */
#define EVERGRAM_DEVICE_ID_SIZE 65
#define EVERGRAM_CHAT_ID_SIZE 128
#define EVERGRAM_IDENTITY_SIZE 128
#define EVERGRAM_MESSAGE_ID_SIZE 128
#define EVERGRAM_TEXT_SIZE 10000
#define EVERGRAM_EMOJI_SIZE 16
#define EVERGRAM_PLATFORM_SIZE 128
#define EVERGRAM_NONCE_SIZE 24

typedef struct evergram evergram_t; /* opaque */

typedef struct {
    char seed[EVERGRAM_SEED_SIZE];               /* ed25519 seed as 64 hex chars */
    char address[EVERGRAM_ADDRESS_SIZE];         /* XRPL "r..." account address */
    char public_key_hex[EVERGRAM_HEX_KEY_SIZE];  /* "ED" + 64 hex chars */
    char private_key_hex[EVERGRAM_HEX_KEY_SIZE]; /* "ED" + 64 hex chars */
} evergram_wallet_t;

typedef struct {
    char device_id[EVERGRAM_DEVICE_ID_SIZE];        /* sha256(public_key)[:16] as hex */
    char public_key_hex[EVERGRAM_HEX_KEY_SIZE];     /* 64 hex chars (curve25519) */
    char private_key_hex[EVERGRAM_HEX_KEY_SIZE];    /* 64 hex chars (curve25519) */
} evergram_device_t;

typedef struct {
    char chat_id[EVERGRAM_CHAT_ID_SIZE];
    char sender[EVERGRAM_IDENTITY_SIZE];
    char message_id[EVERGRAM_MESSAGE_ID_SIZE];
    uint64_t timestamp_ms;
    const char *text;                /* borrowed; NULL when absent */
    const char *reply_to_message_id; /* borrowed; NULL when not a reply */
} evergram_message_t;

typedef struct {
    char chat_id[EVERGRAM_CHAT_ID_SIZE];
    char sender[EVERGRAM_IDENTITY_SIZE];
    char message_id[EVERGRAM_MESSAGE_ID_SIZE];
    char emoji[EVERGRAM_EMOJI_SIZE];
    bool removed;
    uint64_t timestamp_ms;
} evergram_reaction_t;

typedef struct {
    char chat_id[EVERGRAM_CHAT_ID_SIZE];
    char sender[EVERGRAM_IDENTITY_SIZE];
    bool is_typing;
    uint64_t timestamp_ms;
} evergram_typing_event_t;

#define EVERGRAM_NAME_SIZE 128
#define EVERGRAM_INVITE_CODE_SIZE 128
#define EVERGRAM_NICKNAME_SIZE 128
#define EVERGRAM_AVATAR_URL_SIZE 256
#define EVERGRAM_BIO_SIZE 512

typedef struct {
    char identity_key[EVERGRAM_IDENTITY_SIZE];
    char nickname[EVERGRAM_NICKNAME_SIZE];
    char avatar_url[EVERGRAM_AVATAR_URL_SIZE];
    char bio[EVERGRAM_BIO_SIZE];
} evergram_profile_t;

typedef struct {
    char identity_key[EVERGRAM_IDENTITY_SIZE];
    bool online;
    uint64_t timestamp_ms;
} evergram_presence_t;

typedef struct {
    char chat_id[EVERGRAM_CHAT_ID_SIZE];
    char identity[EVERGRAM_IDENTITY_SIZE];
    char name[EVERGRAM_NAME_SIZE]; /* group name, for notification copy */
    uint64_t timestamp_ms;
} evergram_join_request_t;

/*
 * A one-on-one chat request waiting for this identity's decision. Approving
 * creates the chat; declining only refuses this request (block the sender
 * separately if that is the intent). Either way the request stops being pending.
 */
typedef struct {
    char from_identity[EVERGRAM_IDENTITY_SIZE];
    char nickname[EVERGRAM_NICKNAME_SIZE]; /* the requester's profile name, when known */
    uint64_t requested_at_ms;
} evergram_chat_request_t;

/* An invitation to a group chat, waiting for this identity's decision. */
typedef struct {
    char chat_id[EVERGRAM_CHAT_ID_SIZE];
    char invited_by[EVERGRAM_IDENTITY_SIZE];
    char name[EVERGRAM_NAME_SIZE]; /* group name */
    uint64_t invited_at_ms;
} evergram_group_invite_t;

typedef struct {
    char chat_id[EVERGRAM_CHAT_ID_SIZE];
    char name[EVERGRAM_NAME_SIZE];
    int member_count;
    bool already_member;
    bool already_requested;
} evergram_invite_info_t;

typedef struct {
    char chat_id[EVERGRAM_CHAT_ID_SIZE];
    char type[16]; /* EVERGRAM_CHAT_TYPE_ONE_ON_ONE or EVERGRAM_CHAT_TYPE_GROUP */
    char name[EVERGRAM_NAME_SIZE]; /* group name from the chat metadata, "" when unset */
    char created_by[EVERGRAM_IDENTITY_SIZE];
    uint64_t chat_version;
    /* Bumped by metadata-only changes; separate from chat_version so that
     * moderation edits never look like a key rotation. */
    uint64_t meta_version;
    size_t participant_count;
    char **participants; /* owned by the client's chat store */
    size_t admin_count;
    char **admins;
    size_t moderator_count;
    char **moderators;
} evergram_chat_info_t;

#define EVERGRAM_CHAT_TYPE_ONE_ON_ONE "one-on-one"
#define EVERGRAM_CHAT_TYPE_GROUP "group"

/*
 * What a decrypted body actually is. Plain text travels as a raw string; audio
 * and payment messages travel as JSON envelopes discriminated by "type", the
 * same vocabulary the TypeScript SDK's parseMessageContent() uses.
 */
typedef enum {
    EVERGRAM_CONTENT_TEXT = 0,
    EVERGRAM_CONTENT_AUDIO,
    EVERGRAM_CONTENT_PAYMENT_REQUEST,
    EVERGRAM_CONTENT_PAYMENT_RECEIPT,
    EVERGRAM_CONTENT_PAYMENT_SENT,
    EVERGRAM_CONTENT_UNKNOWN,
} evergram_content_type_t;

typedef struct {
    char chat_id[EVERGRAM_CHAT_ID_SIZE];
    char sender[EVERGRAM_IDENTITY_SIZE];
    char message_id[EVERGRAM_MESSAGE_ID_SIZE];
    uint64_t edited_at_ms;
    const char *text; /* borrowed; NULL when the chat key is unknown */
} evergram_message_edited_t;

/* --- structured content (payments and audio) ------------------------------ */

/*
 * Payment messages are a client-side convention, not a gateway feature: they
 * are ordinary chat messages carrying a JSON envelope. Nothing verifies a
 * receipt's transaction hash, so a paywall must check it against the ledger
 * before trusting it — the SDK only guarantees the shape.
 */

#define EVERGRAM_REQUEST_ID_SIZE 40 /* UUID v4, as text */
#define EVERGRAM_TX_HASH_SIZE 80
#define EVERGRAM_AMOUNT_SIZE 32
#define EVERGRAM_CURRENCY_SIZE 16
#define EVERGRAM_CURRENCY_ID_SIZE 32
#define EVERGRAM_LEDGER_ADDRESS_SIZE 64
#define EVERGRAM_NOTE_SIZE 256
#define EVERGRAM_MIME_TYPE_SIZE 64

/*
 * Room for the largest envelope these builders produce: the payment_sent shape
 * plus a long note. Base64 audio needs the caller's own sizing, since its
 * payload is unbounded.
 */
#define EVERGRAM_PAYMENT_CONTENT_SIZE 1024

typedef struct {
    char request_id[EVERGRAM_REQUEST_ID_SIZE];
    char amount[EVERGRAM_AMOUNT_SIZE];
    char currency[EVERGRAM_CURRENCY_SIZE];
    char currency_id[EVERGRAM_CURRENCY_ID_SIZE];
    bool has_note;
    char note[EVERGRAM_NOTE_SIZE];
    char to[EVERGRAM_LEDGER_ADDRESS_SIZE]; /* ledger address of the requester */
    char to_identity_key[EVERGRAM_IDENTITY_SIZE];
} evergram_payment_request_t;

typedef struct {
    char request_id[EVERGRAM_REQUEST_ID_SIZE];
    char tx_hash[EVERGRAM_TX_HASH_SIZE];
    char amount[EVERGRAM_AMOUNT_SIZE];
    char currency[EVERGRAM_CURRENCY_SIZE];
    char currency_id[EVERGRAM_CURRENCY_ID_SIZE];
    char from[EVERGRAM_LEDGER_ADDRESS_SIZE]; /* ledger address of the payer */
    char from_identity_key[EVERGRAM_IDENTITY_SIZE];
} evergram_payment_receipt_t;

typedef struct {
    char id[EVERGRAM_REQUEST_ID_SIZE];
    char tx_hash[EVERGRAM_TX_HASH_SIZE];
    char amount[EVERGRAM_AMOUNT_SIZE];
    char currency[EVERGRAM_CURRENCY_SIZE];
    char currency_id[EVERGRAM_CURRENCY_ID_SIZE];
    bool has_note;
    char note[EVERGRAM_NOTE_SIZE];
    char from[EVERGRAM_LEDGER_ADDRESS_SIZE];
    char from_identity_key[EVERGRAM_IDENTITY_SIZE];
    char to[EVERGRAM_LEDGER_ADDRESS_SIZE];
    char to_identity_key[EVERGRAM_IDENTITY_SIZE];
} evergram_payment_sent_t;

typedef struct {
    char mime_type[EVERGRAM_MIME_TYPE_SIZE];
    uint64_t duration_ms;
    size_t size; /* decoded size, as declared by the sender */
    /* Borrowed from the parsed text and NOT unescaped: base64 never needs
     * escaping, which is why the payload can be handed over without a copy. */
    const char *payload_b64;
} evergram_audio_t;

/*
 * A decrypted body. `raw` always points at the input; `text` points into it for
 * plain text, and the payment/audio members are filled according to `type`.
 * Everything is borrowed from `raw`, so it stays valid exactly as long as the
 * input does.
 */
/* --- purchases (Pro subscription) ------------------------------------------ */

/*
 * The purchase flow is the one protocol area the reference TypeScript SDK leaves
 * unwrapped (it ships no method for these four messages), so this surface has no
 * counterpart to match field for field. It follows the proto.
 *
 * The flow is: initiate (the gateway answers with a payment transaction to sign
 * and submit on-chain), then verify with the resulting hash. ClaimPro activates
 * a subscription that was granted out of band. Nothing here touches a ledger: an
 * application needs its own XRPL/Xahau client to sign and submit `payment`.
 */

#define EVERGRAM_PLAN_SIZE 16
#define EVERGRAM_INTENT_ID_SIZE 128
#define EVERGRAM_TX_TYPE_SIZE 32
#define EVERGRAM_HOOK_PARAM_NAME_SIZE 48
#define EVERGRAM_HOOK_PARAM_VALUE_SIZE 256
#define EVERGRAM_MAX_HOOK_PARAMS 8
#define EVERGRAM_MEMO_DATA_SIZE 256
#define EVERGRAM_MEMO_TYPE_SIZE 32
#define EVERGRAM_MAX_MEMOS 4
#define EVERGRAM_SUBSCRIPTION_TYPE_SIZE 16

typedef struct {
    char name[EVERGRAM_HOOK_PARAM_NAME_SIZE];
    char value[EVERGRAM_HOOK_PARAM_VALUE_SIZE];
} evergram_hook_param_t;

typedef struct {
    char data[EVERGRAM_MEMO_DATA_SIZE];
    char type[EVERGRAM_MEMO_TYPE_SIZE];
    char format[EVERGRAM_MEMO_TYPE_SIZE];
} evergram_memo_t;

/* The transaction the gateway wants submitted; the SDK never signs it. */
typedef struct {
    char transaction_type[EVERGRAM_TX_TYPE_SIZE];
    char destination[EVERGRAM_LEDGER_ADDRESS_SIZE];
    char amount[EVERGRAM_AMOUNT_SIZE];
    size_t hook_param_count;
    evergram_hook_param_t hook_params[EVERGRAM_MAX_HOOK_PARAMS];
    size_t memo_count;
    evergram_memo_t memos[EVERGRAM_MAX_MEMOS];
} evergram_payment_txn_t;

typedef struct {
    char type[EVERGRAM_SUBSCRIPTION_TYPE_SIZE]; /* "pro" */
    uint64_t issued_at_ms;
    uint64_t expires_at_ms;
    int days_remaining;
    char token_id[EVERGRAM_INTENT_ID_SIZE];
} evergram_subscription_t;

typedef struct {
    char intent_id[EVERGRAM_INTENT_ID_SIZE];
    char plan[EVERGRAM_PLAN_SIZE];
    uint64_t created_at_ms;
    uint64_t expires_at_ms;
} evergram_purchase_intent_t;

typedef struct {
    char intent_id[EVERGRAM_INTENT_ID_SIZE];
    bool has_payment;
    evergram_payment_txn_t payment;

    bool has_subscription;
    evergram_subscription_t subscription;

    /* Set when this account is already subscribed, so nothing was purchased. */
    bool already_subscribed;
    evergram_subscription_t existing_subscription;
    char existing_source[EVERGRAM_SUBSCRIPTION_TYPE_SIZE];

    /* Set when an earlier intent is still open, instead of issuing a new one. */
    bool has_existing_intent;
    evergram_purchase_intent_t existing_intent;
} evergram_purchase_t;

/* --- widgets (the embeddable visitor surface) ------------------------------ */

#define EVERGRAM_WIDGET_ID_SIZE 128
#define EVERGRAM_WIDGET_NAME_SIZE 64
#define EVERGRAM_WIDGET_COLOR_SIZE 16  /* "#rrggbb" */
#define EVERGRAM_WIDGET_URL_SIZE 512
#define EVERGRAM_WIDGET_TEXT_SIZE 512
#define EVERGRAM_WIDGET_POSITION_SIZE 16
#define EVERGRAM_WIDGET_MODE_SIZE 16
#define EVERGRAM_CHANNEL_KEY_SIZE 65 /* 64 hex chars for 32 bytes, plus NUL */

#define EVERGRAM_WIDGET_MODE_PRIVATE_CHAT "private_chat"
#define EVERGRAM_WIDGET_MODE_PUBLIC_GROUP "public_group"

/*
 * A widget's stored configuration. Each field is optional, and only the ones
 * whose has_* flag is set are sent: updateWidgetConfig replaces the stored
 * config, so a caller that wants to change one field copies the current config
 * (read it back from the widget record) and adjusts that field.
 */
typedef struct {
    bool has_primary_color;
    char primary_color[EVERGRAM_WIDGET_COLOR_SIZE];
    bool has_logo_url;
    char logo_url[EVERGRAM_WIDGET_URL_SIZE];
    bool has_welcome_message;
    char welcome_message[EVERGRAM_WIDGET_TEXT_SIZE];
    bool has_input_placeholder;
    char input_placeholder[EVERGRAM_WIDGET_TEXT_SIZE];
    bool has_agent_name;
    char agent_name[EVERGRAM_WIDGET_NAME_SIZE];
    bool has_position;
    char position[EVERGRAM_WIDGET_POSITION_SIZE];
    bool has_mode;
    char mode[EVERGRAM_WIDGET_MODE_SIZE];
    /* Only meaningful with mode == public_group: the 64-hex key new visitors
     * join the channel with. */
    bool has_channel_key;
    char channel_key[EVERGRAM_CHANNEL_KEY_SIZE];
} evergram_widget_config_t;

typedef struct {
    char widget_id[EVERGRAM_WIDGET_ID_SIZE];
    char name[EVERGRAM_WIDGET_NAME_SIZE];
    bool enabled;
    bool deleted;
    uint64_t widget_version;
    uint64_t created_at_ms;
    bool has_config;
    evergram_widget_config_t config;
} evergram_widget_t;

/* What anyone (including a visitor's browser) may ask about a widget. */
typedef struct {
    char widget_id[EVERGRAM_WIDGET_ID_SIZE];
    char owner_identity_key[EVERGRAM_IDENTITY_SIZE];
    bool enabled;
    size_t device_count;
    bool has_config;
    evergram_widget_config_t config;
} evergram_widget_info_t;

/* --- account access (tiers, reputation) ------------------------------------ */

#define EVERGRAM_TIER_SIZE 32
#define EVERGRAM_CAPABILITY_SIZE 48
#define EVERGRAM_MAX_CAPABILITIES 16

/*
 * What the gateway says this identity may do. It arrives with every successful
 * authentication, so a bot can check before trying something the account is not
 * entitled to instead of discovering it from a refusal.
 */
typedef struct {
    char tier[EVERGRAM_TIER_SIZE];
    bool is_admin;
    bool is_restricted;
    /* Absent means no device limit is enforced (an admin's unlimited tier), so
     * the flag is what a caller must check — not the value. */
    bool has_max_devices;
    uint64_t max_devices;
    uint64_t joined_at_ms;
    char invited_by[EVERGRAM_IDENTITY_SIZE];
    size_t subscription_count; /* the subscriptions themselves are not modelled */
    size_t capability_count;
    char capabilities[EVERGRAM_MAX_CAPABILITIES][EVERGRAM_CAPABILITY_SIZE];
} evergram_access_t;

typedef struct {
    char identity[EVERGRAM_IDENTITY_SIZE]; /* who this is about */
    bool is_restricted;
    bool has_score;
    int score;
    char reason[EVERGRAM_NOTE_SIZE];
} evergram_reputation_t;

typedef void (*evergram_restricted_fn)(evergram_t *eg, const evergram_reputation_t *event);

typedef struct {
    evergram_content_type_t type;
    const char *raw;
    const char *text;
    evergram_payment_request_t payment_request;
    evergram_payment_receipt_t payment_receipt;
    evergram_payment_sent_t payment_sent;
    evergram_audio_t audio;
} evergram_content_t;

typedef struct {
    char chat_id[EVERGRAM_CHAT_ID_SIZE];
    char sender[EVERGRAM_IDENTITY_SIZE];
    char message_id[EVERGRAM_MESSAGE_ID_SIZE];
    uint64_t timestamp_ms;
} evergram_message_deleted_t;

typedef void (*evergram_message_fn)(evergram_t *eg, const evergram_message_t *message);
typedef void (*evergram_reaction_fn)(evergram_t *eg, const evergram_reaction_t *reaction);
typedef void (*evergram_typing_fn)(evergram_t *eg, const evergram_typing_event_t *event);
typedef void (*evergram_message_edited_fn)(evergram_t *eg,
                                           const evergram_message_edited_t *message);
typedef void (*evergram_message_deleted_fn)(evergram_t *eg,
                                            const evergram_message_deleted_t *message);
typedef void (*evergram_join_request_fn)(evergram_t *eg,
                                         const evergram_join_request_t *request);

/* A one-on-one chat request arrived (live, or replayed by the boot sync). */
typedef void (*evergram_chat_request_fn)(evergram_t *eg, const evergram_chat_request_t *request);

/* A group invitation arrived (live, or replayed by the boot sync). */
typedef void (*evergram_group_invite_fn)(evergram_t *eg, const evergram_group_invite_t *invite);

/* A chat this client knew about no longer exists server-side: it was left,
 * deleted, or this identity was removed from it. The chat's key is dropped
 * with it, so nothing lingers. */
typedef void (*evergram_chat_removed_fn)(evergram_t *eg, const char *chat_id);
typedef void (*evergram_presence_fn)(evergram_t *eg, const evergram_presence_t *presence);
typedef void (*evergram_profile_fn)(evergram_t *eg, const evergram_profile_t *profile);
typedef void (*evergram_error_fn)(evergram_t *eg, evergram_status_t status, const char *detail);
typedef void (*evergram_connected_fn)(evergram_t *eg);
typedef void (*evergram_disconnected_fn)(evergram_t *eg);

typedef struct {
    const char *url;                 /* required: ws:// or wss:// endpoint */
    const evergram_wallet_t *wallet; /* required: copied by evergram_create */
    const evergram_device_t *device; /* required: copied by evergram_create */
    const char *platform;            /* optional: defaults to "Terminal" */
    void *user_data;                 /* optional: returned by evergram_user_data */
} evergram_options_t;

typedef enum {
    EVERGRAM_LOG_OFF = 0,
    EVERGRAM_LOG_ERROR,
    EVERGRAM_LOG_WARN,
    EVERGRAM_LOG_INFO,
    EVERGRAM_LOG_DEBUG,
    EVERGRAM_LOG_TRACE,
} evergram_log_level_t;

/* --- ephemeral relay (visitor rooms, widget channels) --------------------- */

typedef enum {
    EVERGRAM_RELAY_KIND_UNKNOWN = -1,
    EVERGRAM_RELAY_KIND_JOINED = 0,
    EVERGRAM_RELAY_KIND_TEXT = 1,
    EVERGRAM_RELAY_KIND_LEFT = 2,
    EVERGRAM_RELAY_KIND_REACT = 3,
    EVERGRAM_RELAY_KIND_EDIT = 4,
    EVERGRAM_RELAY_KIND_REMOVE = 5,
    EVERGRAM_RELAY_KIND_RECLAIM = 6,
    EVERGRAM_RELAY_KIND_END = 7,
    EVERGRAM_RELAY_KIND_CLAIMED_ELSEWHERE = 8,
    EVERGRAM_RELAY_KIND_TYPING = 9,
    EVERGRAM_RELAY_KIND_CHANNEL_JOIN = 10,
    EVERGRAM_RELAY_KIND_CHANNEL_PART = 11,
    EVERGRAM_RELAY_KIND_CHANNEL_KICKED = 12,
    EVERGRAM_RELAY_KIND_CHANNEL_MODE = 13,
} evergram_relay_kind_t;

#define EVERGRAM_RELAY_MSG_ID_SIZE 128
#define EVERGRAM_RELAY_SENDER_SIZE EVERGRAM_IDENTITY_SIZE
#define EVERGRAM_RELAY_EMOJI_SIZE 64

typedef struct {
    char msg_id[EVERGRAM_RELAY_MSG_ID_SIZE];
    char sender[EVERGRAM_RELAY_SENDER_SIZE];
    char text[EVERGRAM_TEXT_SIZE];
    uint64_t timestamp_ms;
} evergram_relay_text_t;

typedef struct {
    char msg_id[EVERGRAM_RELAY_MSG_ID_SIZE];
    char emoji[EVERGRAM_RELAY_EMOJI_SIZE];
    bool removed; /* the sender cleared their reaction (emoji was null) */
} evergram_relay_react_t;

typedef struct {
    char msg_id[EVERGRAM_RELAY_MSG_ID_SIZE];
    char text[EVERGRAM_TEXT_SIZE];
    uint64_t edited_at_ms;
} evergram_relay_edit_t;

typedef struct {
    char msg_id[EVERGRAM_RELAY_MSG_ID_SIZE];
    uint64_t removed_at_ms;
} evergram_relay_remove_t;

typedef struct {
    bool is_typing;
    char sender[EVERGRAM_RELAY_SENDER_SIZE]; /* empty when the frame omits it */
} evergram_relay_typing_t;

typedef struct {
    char sender[EVERGRAM_RELAY_SENDER_SIZE];
    char previous_sender[EVERGRAM_RELAY_SENDER_SIZE];
    bool has_previous;
} evergram_relay_presence_t;

/* Owned string arrays; release with evergram_relay_moderation_dispose(). */
typedef struct {
    bool moderated;
    char **ops;
    size_t ops_count;
    char **voiced;
    size_t voiced_count;
} evergram_relay_moderation_t;

typedef struct {
    bool banned; /* the reason was "banned" rather than a plain kick */
} evergram_relay_kicked_t;

/* Visitor room offered by the gateway to a widget owner. The room key is
 * already opened with this device's key, so the session can talk immediately. */
#define EVERGRAM_ROOM_TOKEN_SIZE 128
#define EVERGRAM_VISITOR_LABEL_SIZE 128
#define EVERGRAM_VISITOR_ORIGIN_SIZE 256

typedef struct {
    char room_token[EVERGRAM_ROOM_TOKEN_SIZE];
    char widget_id[EVERGRAM_WIDGET_ID_SIZE];
    char visitor_label[EVERGRAM_VISITOR_LABEL_SIZE];
    char origin[EVERGRAM_VISITOR_ORIGIN_SIZE];
    uint64_t timestamp_ms;
    bool has_first_message;
    evergram_relay_text_t first_message;
} evergram_visitor_room_t;

/*
 * Session state of a 1:1 room. CONNECTED covers both the first claim and a
 * reclaim after a drop; PEER_LEFT is a drop the peer may still recover from;
 * ENDED, CLAIMED_ELSEWHERE and KICKED are final.
 */
typedef enum {
    EVERGRAM_VISITOR_STATE_CONNECTED = 0,
    EVERGRAM_VISITOR_STATE_PEER_LEFT,
    EVERGRAM_VISITOR_STATE_ENDED,
    EVERGRAM_VISITOR_STATE_CLAIMED_ELSEWHERE,
    EVERGRAM_VISITOR_STATE_KICKED,
} evergram_visitor_state_t;

typedef struct {
    evergram_visitor_state_t state;
    char reason[32];      /* "kicked" or "banned" for KICKED, else empty */
    uint64_t deadline_ms; /* PEER_LEFT only: reconnect grace deadline, 0 if unknown */
} evergram_visitor_state_event_t;

/* public_group channel moderation. Values are the wire values. */
typedef enum {
    EVERGRAM_MODERATION_KICK = 0,
    EVERGRAM_MODERATION_BAN = 1,
    EVERGRAM_MODERATION_UNBAN = 2,
    EVERGRAM_MODERATION_GRANT_OP = 3,
    EVERGRAM_MODERATION_REVOKE_OP = 4,
    EVERGRAM_MODERATION_GRANT_VOICE = 5,
    EVERGRAM_MODERATION_REVOKE_VOICE = 6,
    EVERGRAM_MODERATION_SET_MODERATED = 7,
    EVERGRAM_MODERATION_UNSET_MODERATED = 8,
} evergram_moderation_action_t;

typedef void (*evergram_visitor_room_fn)(evergram_t *eg, const evergram_visitor_room_t *room);
typedef void (*evergram_visitor_text_fn)(evergram_t *eg, const char *room_token,
                                         const evergram_relay_text_t *event);
typedef void (*evergram_visitor_react_fn)(evergram_t *eg, const char *room_token,
                                          const evergram_relay_react_t *event);
typedef void (*evergram_visitor_edit_fn)(evergram_t *eg, const char *room_token,
                                         const evergram_relay_edit_t *event);
typedef void (*evergram_visitor_remove_fn)(evergram_t *eg, const char *room_token,
                                           const evergram_relay_remove_t *event);
typedef void (*evergram_visitor_typing_fn)(evergram_t *eg, const char *room_token,
                                           const evergram_relay_typing_t *event);
typedef void (*evergram_visitor_state_fn)(evergram_t *eg, const char *room_token,
                                          const evergram_visitor_state_event_t *event);
/* Channel presence: joined == true for a join, false for a part. */
typedef void (*evergram_visitor_presence_fn)(evergram_t *eg, const char *room_token,
                                             const evergram_relay_presence_t *event,
                                             bool joined);
typedef void (*evergram_visitor_moderation_fn)(evergram_t *eg, const char *room_token,
                                               const evergram_relay_moderation_t *state);
typedef void (*evergram_visitor_timed_out_fn)(evergram_t *eg, const char *room_token);

#endif /* EVERGRAM_TYPES_H */
