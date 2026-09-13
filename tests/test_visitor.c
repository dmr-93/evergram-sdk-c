#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "e2ee_vectors.h"
#include "evergram.h"
#include "evergram.pb-c.h"
#include "internal.h"
#include "relay.h"
#include "test.h"

/*
 * The visitor layer is driven through the parser, exactly as frames arrive from
 * the gateway, and the room key arrives sealed by tweetnacl vectors. A passing
 * run therefore covers the wire contract, not just local bookkeeping.
 */

#define TEST_URL "wss://gateway.test/ws"
#define TEST_ADDRESS "rVisitorOwnerAddress"
#define TEST_DEVICE_ID "owner-device-1"
#define TEST_ROOM_TOKEN "room-token-1"
#define TEST_WIDGET_ID "widget-1"
#define TEST_VISITOR_LABEL "web visitor"
#define TEST_ORIGIN "https://example.com"

static evergram_t *g_client;

/* --- captured callbacks --------------------------------------------------- */

static int g_room_calls;
static evergram_visitor_room_t g_room;

static int g_text_calls;
static char g_text_room[EVERGRAM_ROOM_TOKEN_SIZE];
static evergram_relay_text_t g_text;

static int g_react_calls;
static evergram_relay_react_t g_react;

static int g_edit_calls;
static evergram_relay_edit_t g_edit;

static int g_remove_calls;
static evergram_relay_remove_t g_remove;

static int g_typing_calls;
static evergram_relay_typing_t g_typing;

static int g_state_calls;
static evergram_visitor_state_event_t g_state;

static int g_presence_calls;
static char g_presence_sender[EVERGRAM_RELAY_SENDER_SIZE];
static bool g_presence_joined;

static int g_moderation_calls;
static bool g_moderated;
static size_t g_ops_count;
static size_t g_voiced_count;

static int g_timed_out_calls;
static char g_timed_out_room[EVERGRAM_ROOM_TOKEN_SIZE];

static void on_room(evergram_t *eg, const evergram_visitor_room_t *room) {
    (void)eg;
    g_room_calls++;
    g_room = *room;
}

static void on_text(evergram_t *eg, const char *room_token, const evergram_relay_text_t *event) {
    (void)eg;
    g_text_calls++;
    snprintf(g_text_room, sizeof(g_text_room), "%s", room_token);
    g_text = *event;
}

static void on_react(evergram_t *eg, const char *room_token, const evergram_relay_react_t *event) {
    (void)eg;
    (void)room_token;
    g_react_calls++;
    g_react = *event;
}

static void on_edit(evergram_t *eg, const char *room_token, const evergram_relay_edit_t *event) {
    (void)eg;
    (void)room_token;
    g_edit_calls++;
    g_edit = *event;
}

static void on_remove(evergram_t *eg, const char *room_token, const evergram_relay_remove_t *event) {
    (void)eg;
    (void)room_token;
    g_remove_calls++;
    g_remove = *event;
}

static void on_typing(evergram_t *eg, const char *room_token, const evergram_relay_typing_t *event) {
    (void)eg;
    (void)room_token;
    g_typing_calls++;
    g_typing = *event;
}

static void on_state(evergram_t *eg, const char *room_token, const evergram_visitor_state_event_t *event) {
    (void)eg;
    (void)room_token;
    g_state_calls++;
    g_state = *event;
}

static void on_presence(evergram_t *eg, const char *room_token, const evergram_relay_presence_t *event,
                        bool joined) {
    (void)eg;
    (void)room_token;
    g_presence_calls++;
    snprintf(g_presence_sender, sizeof(g_presence_sender), "%s", event->sender);
    g_presence_joined = joined;
}

static void on_moderation(evergram_t *eg, const char *room_token,
                          const evergram_relay_moderation_t *state) {
    (void)eg;
    (void)room_token;
    g_moderation_calls++;
    g_moderated = state->moderated;
    g_ops_count = state->ops_count;
    g_voiced_count = state->voiced_count;
}

static void on_timed_out(evergram_t *eg, const char *room_token) {
    (void)eg;
    g_timed_out_calls++;
    snprintf(g_timed_out_room, sizeof(g_timed_out_room), "%s", room_token);
}

/* --- harness -------------------------------------------------------------- */

static void destroy_client(void) {
    evergram_destroy(g_client);
    g_client = NULL;
}

static void reset_state(void) {
    if (g_client != NULL) {
        evergram_destroy(g_client);
        g_client = NULL;
    }

    g_room_calls = 0;
    memset(&g_room, 0, sizeof(g_room));
    g_text_calls = 0;
    g_text_room[0] = '\0';
    memset(&g_text, 0, sizeof(g_text));
    g_react_calls = 0;
    memset(&g_react, 0, sizeof(g_react));
    g_edit_calls = 0;
    memset(&g_edit, 0, sizeof(g_edit));
    g_remove_calls = 0;
    memset(&g_remove, 0, sizeof(g_remove));
    g_typing_calls = 0;
    memset(&g_typing, 0, sizeof(g_typing));
    g_state_calls = 0;
    memset(&g_state, 0, sizeof(g_state));
    g_presence_calls = 0;
    g_presence_sender[0] = '\0';
    g_presence_joined = false;
    g_moderation_calls = 0;
    g_moderated = false;
    g_ops_count = 0;
    g_voiced_count = 0;
    g_timed_out_calls = 0;
    g_timed_out_room[0] = '\0';
}

/* A client whose device key matches the tweetnacl vectors, so the sealed room
 * key from the vectors opens. No socket is opened until evergram_start(). */
static evergram_t *client(void) {
    if (g_client != NULL) {
        return g_client;
    }

    evergram_wallet_t wallet;
    evergram_device_t device;
    memset(&wallet, 0, sizeof(wallet));
    memset(&device, 0, sizeof(device));

    snprintf(wallet.address, sizeof(wallet.address), "%s", TEST_ADDRESS);
    snprintf(device.device_id, sizeof(device.device_id), "%s", TEST_DEVICE_ID);
    snprintf(device.public_key_hex, sizeof(device.public_key_hex), "%s",
             VECTOR_DEVICE_PUBLIC_KEY_HEX);
    snprintf(device.private_key_hex, sizeof(device.private_key_hex), "%s",
             VECTOR_DEVICE_PRIVATE_KEY_HEX);

    const evergram_options_t options = {
        .url = TEST_URL,
        .wallet = &wallet,
        .device = &device,
        .platform = "Test",
    };

    g_client = evergram_create(&options);
    evergram_wallet_wipe(&wallet);
    evergram_device_wipe(&device);
    if (g_client == NULL) {
        return NULL;
    }

    atexit(destroy_client);
    evergram_on_visitor_room(g_client, on_room);
    evergram_on_visitor_text(g_client, on_text);
    evergram_on_visitor_react(g_client, on_react);
    evergram_on_visitor_edit(g_client, on_edit);
    evergram_on_visitor_remove(g_client, on_remove);
    evergram_on_visitor_typing(g_client, on_typing);
    evergram_on_visitor_state(g_client, on_state);
    evergram_on_visitor_presence(g_client, on_presence);
    evergram_on_visitor_moderation(g_client, on_moderation);
    evergram_on_visitor_timed_out(g_client, on_timed_out);
    return g_client;
}

static void feed(Evergram__ServerMessage *message) {
    size_t size = evergram__server_message__get_packed_size(message);
    CHECK(size > 0);
    if (size == 0) {
        return;
    }

    uint8_t *packed = malloc(size);
    CHECK(packed != NULL);
    if (packed == NULL) {
        return;
    }

    evergram__server_message__pack(message, packed);
    parser_dispatch(client(), packed, size);
    free(packed);
}

static void room_key(uint8_t key[EVERGRAM_SYM_KEY_SIZE]) {
    CHECK_EQ_INT(sodium_hex2bin(key, EVERGRAM_SYM_KEY_SIZE, VECTOR_ROOM_KEY_HEX,
                                2u * EVERGRAM_SYM_KEY_SIZE, NULL, NULL, NULL),
                 0);
}

/* Offers the room to this client's device, as the gateway does for a widget. */
static void feed_room_requested(const char *device_key, const char *sealed_ciphertext,
                                const char *sealed_nonce) {
    Evergram__SealedKeyForDevice sealed = EVERGRAM__SEALED_KEY_FOR_DEVICE__INIT;
    sealed.ciphertext = (char *)sealed_ciphertext;
    sealed.nonce = (char *)sealed_nonce;
    sealed.ephemeral_pubkey = (char *)VECTOR_EPHEMERAL_PUBLIC_KEY_B64;

    Evergram__VisitorRoomRequestedEvent__SealedKeyByDeviceEntry entry =
        EVERGRAM__VISITOR_ROOM_REQUESTED_EVENT__SEALED_KEY_BY_DEVICE_ENTRY__INIT;
    entry.key = (char *)device_key;
    entry.value = &sealed;
    Evergram__VisitorRoomRequestedEvent__SealedKeyByDeviceEntry *entries[1] = {&entry};

    Evergram__VisitorRoomRequestedEvent event = EVERGRAM__VISITOR_ROOM_REQUESTED_EVENT__INIT;
    event.room_token = (char *)TEST_ROOM_TOKEN;
    event.widget_id = (char *)TEST_WIDGET_ID;
    event.visitor_label = (char *)TEST_VISITOR_LABEL;
    event.origin = (char *)TEST_ORIGIN;
    event.has_ts = 1;
    event.ts = 1700000000123;
    event.n_sealed_key_by_device = 1;
    event.sealed_key_by_device = entries;
    event.has_first_message_payload = 1;
    event.first_message_payload.data = (uint8_t *)VECTOR_RELAY_TEXT_PAYLOAD;
    event.first_message_payload.len = strlen(VECTOR_RELAY_TEXT_PAYLOAD);

    Evergram__ServerMessage message = EVERGRAM__SERVER_MESSAGE__INIT;
    message.visitor_room_requested_event = &event;
    message.payload_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_VISITOR_ROOM_REQUESTED_EVENT;
    feed(&message);
}

static void feed_relay(const char *room_token, int wire_kind, const char *payload) {
    Evergram__RelayMessage relay = EVERGRAM__RELAY_MESSAGE__INIT;
    relay.room_token = (char *)room_token;
    relay.has_kind = 1;
    relay.kind = (Evergram__RelayMessageKind)wire_kind;
    if (payload != NULL) {
        relay.has_payload = 1;
        relay.payload.data = (uint8_t *)payload;
        relay.payload.len = strlen(payload);
    }

    Evergram__ServerMessage message = EVERGRAM__SERVER_MESSAGE__INIT;
    message.relay_message = &relay;
    message.payload_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_RELAY_MESSAGE;
    feed(&message);
}

/* --- tests ---------------------------------------------------------------- */

static void test_no_key_until_offered(void) {
    reset_state();

    uint8_t key[EVERGRAM_SYM_KEY_SIZE];
    CHECK(!evergram_visitor_has_room(client(), TEST_ROOM_TOKEN));
    CHECK_EQ_INT(evergram_visitor_room_key(client(), TEST_ROOM_TOKEN, key),
                 EVERGRAM_ERR_NO_ROOM_KEY);
    CHECK_EQ_INT(evergram_visitor_send_text(client(), TEST_ROOM_TOKEN, NULL, "hi"),
                 EVERGRAM_ERR_NO_ROOM_KEY);
    CHECK_EQ_INT(evergram_visitor_send_react(client(), TEST_ROOM_TOKEN, "m1", "*"),
                 EVERGRAM_ERR_NO_ROOM_KEY);
    CHECK_EQ_INT(evergram_visitor_send_edit(client(), TEST_ROOM_TOKEN, "m1", "hi"),
                 EVERGRAM_ERR_NO_ROOM_KEY);
    CHECK_EQ_INT(evergram_visitor_send_remove(client(), TEST_ROOM_TOKEN, "m1"),
                 EVERGRAM_ERR_NO_ROOM_KEY);
    /* Not connected, so nothing is sent even when the arguments are fine. */
    CHECK_EQ_INT(evergram_visitor_send_typing(client(), TEST_ROOM_TOKEN, true, NULL),
                 EVERGRAM_ERR_NOT_CONNECTED);
    CHECK_EQ_INT(evergram_visitor_room_create(NULL, TEST_WIDGET_ID, NULL, NULL, 0, NULL),
                 EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(evergram_visitor_room_create(client(), "", NULL, NULL, 0, NULL),
                 EVERGRAM_ERR_INVALID_ARG);
}

static void test_room_requested_reaches_callback(void) {
    reset_state();

    feed_room_requested(TEST_DEVICE_ID, VECTOR_SEALED_ROOM_CIPHERTEXT_B64,
                        VECTOR_SEALED_ROOM_NONCE_B64);

    CHECK_EQ_INT(g_room_calls, 1);
    CHECK_EQ_STR(g_room.room_token, TEST_ROOM_TOKEN);
    CHECK_EQ_STR(g_room.widget_id, TEST_WIDGET_ID);
    CHECK_EQ_STR(g_room.visitor_label, TEST_VISITOR_LABEL);
    CHECK_EQ_STR(g_room.origin, TEST_ORIGIN);
    CHECK_EQ_INT((long long)g_room.timestamp_ms, 1700000000123LL);
    CHECK(g_room.has_first_message);
    CHECK_EQ_STR(g_room.first_message.text, VECTOR_RELAY_TEXT_MESSAGE);
    CHECK_EQ_STR(g_room.first_message.sender, VECTOR_RELAY_TEXT_SENDER);
    CHECK_EQ_STR(g_room.first_message.msg_id, VECTOR_RELAY_TEXT_MSG_ID);
    CHECK(evergram_visitor_has_room(client(), TEST_ROOM_TOKEN));

    uint8_t key[EVERGRAM_SYM_KEY_SIZE];
    uint8_t expected[EVERGRAM_SYM_KEY_SIZE];
    room_key(expected);
    CHECK_EQ_INT(evergram_visitor_room_key(client(), TEST_ROOM_TOKEN, key), EVERGRAM_OK);
    CHECK_EQ_INT(sodium_memcmp(key, expected, sizeof(key)), 0);
}

/* A room sealed for a different device must not be opened or stored. */
static void test_room_for_another_device_is_ignored(void) {
    reset_state();

    feed_room_requested("some-other-device", VECTOR_SEALED_ROOM_CIPHERTEXT_B64,
                        VECTOR_SEALED_ROOM_NONCE_B64);

    CHECK_EQ_INT(g_room_calls, 0);
    CHECK(!evergram_visitor_has_room(client(), TEST_ROOM_TOKEN));
}

/* A tampered room key must fail closed: no callback, no stored key. */
static void test_tampered_room_key_is_rejected(void) {
    reset_state();

    char tampered[sizeof(VECTOR_SEALED_ROOM_CIPHERTEXT_B64)];
    snprintf(tampered, sizeof(tampered), "%s", VECTOR_SEALED_ROOM_CIPHERTEXT_B64);
    tampered[0] = (tampered[0] == 'A') ? 'B' : 'A';

    feed_room_requested(TEST_DEVICE_ID, tampered, VECTOR_SEALED_ROOM_NONCE_B64);

    CHECK_EQ_INT(g_room_calls, 0);
    CHECK(!evergram_visitor_has_room(client(), TEST_ROOM_TOKEN));
}

static void test_text_frame_reaches_callback(void) {
    reset_state();
    feed_room_requested(TEST_DEVICE_ID, VECTOR_SEALED_ROOM_CIPHERTEXT_B64,
                        VECTOR_SEALED_ROOM_NONCE_B64);

    feed_relay(TEST_ROOM_TOKEN, EVERGRAM__RELAY_MESSAGE_KIND__RELAY_TEXT,
               VECTOR_RELAY_TEXT_PAYLOAD);

    CHECK_EQ_INT(g_text_calls, 1);
    CHECK_EQ_STR(g_text_room, TEST_ROOM_TOKEN);
    CHECK_EQ_STR(g_text.text, VECTOR_RELAY_TEXT_MESSAGE);
    CHECK_EQ_STR(g_text.sender, VECTOR_RELAY_TEXT_SENDER);
    CHECK_EQ_STR(g_text.msg_id, VECTOR_RELAY_TEXT_MSG_ID);
}

static void test_content_frames_without_key_are_ignored(void) {
    reset_state();

    feed_relay(TEST_ROOM_TOKEN, EVERGRAM__RELAY_MESSAGE_KIND__RELAY_TEXT,
               VECTOR_RELAY_TEXT_PAYLOAD);
    CHECK_EQ_INT(g_text_calls, 0);

    /* A room's key always arrives with the room, so an unknown room is not a
     * wait state: its frames are dropped. */
    feed_relay(TEST_ROOM_TOKEN, EVERGRAM__RELAY_MESSAGE_KIND__RELAY_REACT,
               VECTOR_RELAY_REACT_PAYLOAD);
    CHECK_EQ_INT(g_react_calls, 0);
}

static void test_react_edit_and_remove_frames(void) {
    reset_state();
    feed_room_requested(TEST_DEVICE_ID, VECTOR_SEALED_ROOM_CIPHERTEXT_B64,
                        VECTOR_SEALED_ROOM_NONCE_B64);

    uint8_t key[EVERGRAM_SYM_KEY_SIZE];
    room_key(key);

    feed_relay(TEST_ROOM_TOKEN, EVERGRAM__RELAY_MESSAGE_KIND__RELAY_REACT,
               VECTOR_RELAY_REACT_PAYLOAD);
    CHECK_EQ_INT(g_react_calls, 1);
    CHECK_EQ_STR(g_react.msg_id, VECTOR_RELAY_TEXT_MSG_ID);
    CHECK(!g_react.removed);

    feed_relay(TEST_ROOM_TOKEN, EVERGRAM__RELAY_MESSAGE_KIND__RELAY_REACT,
               VECTOR_RELAY_REACT_CLEARED_PAYLOAD);
    CHECK_EQ_INT(g_react_calls, 2);
    CHECK(g_react.removed);

    char payload[EVERGRAM_RELAY_PAYLOAD_MAX];
    CHECK_EQ_INT(evergram_relay_build_edit(key, "m2", "edited text", payload, sizeof(payload)),
                 EVERGRAM_OK);
    feed_relay(TEST_ROOM_TOKEN, EVERGRAM__RELAY_MESSAGE_KIND__RELAY_EDIT, payload);
    CHECK_EQ_INT(g_edit_calls, 1);
    CHECK_EQ_STR(g_edit.msg_id, "m2");
    CHECK_EQ_STR(g_edit.text, "edited text");

    CHECK_EQ_INT(evergram_relay_build_remove(key, "m2", payload, sizeof(payload)), EVERGRAM_OK);
    feed_relay(TEST_ROOM_TOKEN, EVERGRAM__RELAY_MESSAGE_KIND__RELAY_REMOVE, payload);
    CHECK_EQ_INT(g_remove_calls, 1);
    CHECK_EQ_STR(g_remove.msg_id, "m2");
}

static void test_typing_and_state_frames(void) {
    reset_state();
    feed_room_requested(TEST_DEVICE_ID, VECTOR_SEALED_ROOM_CIPHERTEXT_B64,
                        VECTOR_SEALED_ROOM_NONCE_B64);

    char payload[EVERGRAM_RELAY_PAYLOAD_MAX];
    CHECK_EQ_INT(evergram_relay_build_typing(true, NULL, payload, sizeof(payload)), EVERGRAM_OK);
    feed_relay(TEST_ROOM_TOKEN, EVERGRAM__RELAY_MESSAGE_KIND__RELAY_TYPING, payload);
    CHECK_EQ_INT(g_typing_calls, 1);
    CHECK(g_typing.is_typing);

    feed_relay(TEST_ROOM_TOKEN, EVERGRAM__RELAY_MESSAGE_KIND__RELAY_JOINED, NULL);
    CHECK_EQ_INT(g_state_calls, 1);
    CHECK_EQ_INT(g_state.state, EVERGRAM_VISITOR_STATE_CONNECTED);
    CHECK(evergram_visitor_has_room(client(), TEST_ROOM_TOKEN)); /* key survives a claim */

    feed_relay(TEST_ROOM_TOKEN, EVERGRAM__RELAY_MESSAGE_KIND__RELAY_RECLAIM, NULL);
    CHECK_EQ_INT(g_state_calls, 2);
    CHECK_EQ_INT(g_state.state, EVERGRAM_VISITOR_STATE_CONNECTED);

    feed_relay(TEST_ROOM_TOKEN, EVERGRAM__RELAY_MESSAGE_KIND__RELAY_LEFT,
               "{\"deadlineAt\":1700000060000}");
    CHECK_EQ_INT(g_state_calls, 3);
    CHECK_EQ_INT(g_state.state, EVERGRAM_VISITOR_STATE_PEER_LEFT);
    CHECK_EQ_INT((long long)g_state.deadline_ms, 1700000060000LL);
    CHECK(evergram_visitor_has_room(client(), TEST_ROOM_TOKEN)); /* a drop is recoverable */

    feed_relay(TEST_ROOM_TOKEN, EVERGRAM__RELAY_MESSAGE_KIND__RELAY_END, NULL);
    CHECK_EQ_INT(g_state_calls, 4);
    CHECK_EQ_INT(g_state.state, EVERGRAM_VISITOR_STATE_ENDED);
    CHECK(!evergram_visitor_has_room(client(), TEST_ROOM_TOKEN));

    /* A left frame with no deadline reports none rather than a bogus value. */
    feed_relay(TEST_ROOM_TOKEN, EVERGRAM__RELAY_MESSAGE_KIND__RELAY_LEFT, NULL);
    CHECK_EQ_INT(g_state_calls, 5);
    CHECK_EQ_INT((long long)g_state.deadline_ms, 0LL);
}

static void test_claimed_elsewhere_forgets_the_room(void) {
    reset_state();
    feed_room_requested(TEST_DEVICE_ID, VECTOR_SEALED_ROOM_CIPHERTEXT_B64,
                        VECTOR_SEALED_ROOM_NONCE_B64);

    feed_relay(TEST_ROOM_TOKEN, EVERGRAM__RELAY_MESSAGE_KIND__RELAY_CLAIMED_ELSEWHERE, NULL);
    CHECK_EQ_INT(g_state_calls, 1);
    CHECK_EQ_INT(g_state.state, EVERGRAM_VISITOR_STATE_CLAIMED_ELSEWHERE);
    CHECK(!evergram_visitor_has_room(client(), TEST_ROOM_TOKEN));
}

static void test_channel_frames(void) {
    reset_state();
    feed_room_requested(TEST_DEVICE_ID, VECTOR_SEALED_ROOM_CIPHERTEXT_B64,
                        VECTOR_SEALED_ROOM_NONCE_B64);

    char payload[EVERGRAM_RELAY_PAYLOAD_MAX];
    CHECK_EQ_INT(evergram_relay_build_presence("1:rAlice", NULL, payload, sizeof(payload)),
                 EVERGRAM_OK);
    feed_relay(TEST_ROOM_TOKEN, EVERGRAM__RELAY_MESSAGE_KIND__RELAY_CHANNEL_JOIN, payload);
    CHECK_EQ_INT(g_presence_calls, 1);
    CHECK_EQ_STR(g_presence_sender, "1:rAlice");
    CHECK(g_presence_joined);

    feed_relay(TEST_ROOM_TOKEN, EVERGRAM__RELAY_MESSAGE_KIND__RELAY_CHANNEL_PART, payload);
    CHECK_EQ_INT(g_presence_calls, 2);
    CHECK(!g_presence_joined);

    feed_relay(TEST_ROOM_TOKEN, EVERGRAM__RELAY_MESSAGE_KIND__RELAY_CHANNEL_MODE,
               "{\"moderated\":true,\"ops\":[\"1:rAlice\"],\"voiced\":[]}");
    CHECK_EQ_INT(g_moderation_calls, 1);
    CHECK(g_moderated);
    CHECK_EQ_INT((long long)g_ops_count, 1);
    CHECK_EQ_INT((long long)g_voiced_count, 0);

    feed_relay(TEST_ROOM_TOKEN, EVERGRAM__RELAY_MESSAGE_KIND__RELAY_CHANNEL_KICKED,
               "{\"reason\":\"banned\"}");
    CHECK_EQ_INT(g_state_calls, 1);
    CHECK_EQ_INT(g_state.state, EVERGRAM_VISITOR_STATE_KICKED);
    CHECK_EQ_STR(g_state.reason, "banned");
    CHECK(!evergram_visitor_has_room(client(), TEST_ROOM_TOKEN));
}

static void test_timed_out_event(void) {
    reset_state();
    feed_room_requested(TEST_DEVICE_ID, VECTOR_SEALED_ROOM_CIPHERTEXT_B64,
                        VECTOR_SEALED_ROOM_NONCE_B64);

    Evergram__VisitorRoomTimedOutEvent event = EVERGRAM__VISITOR_ROOM_TIMED_OUT_EVENT__INIT;
    event.room_token = (char *)TEST_ROOM_TOKEN;

    Evergram__ServerMessage message = EVERGRAM__SERVER_MESSAGE__INIT;
    message.visitor_room_timed_out_event = &event;
    message.payload_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_VISITOR_ROOM_TIMED_OUT_EVENT;
    feed(&message);

    CHECK_EQ_INT(g_timed_out_calls, 1);
    CHECK_EQ_STR(g_timed_out_room, TEST_ROOM_TOKEN);
    CHECK(!evergram_visitor_has_room(client(), TEST_ROOM_TOKEN));
}

/* An oversized payload must be refused rather than truncated into the parser. */
static void test_oversized_payload_is_rejected(void) {
    reset_state();
    feed_room_requested(TEST_DEVICE_ID, VECTOR_SEALED_ROOM_CIPHERTEXT_B64,
                        VECTOR_SEALED_ROOM_NONCE_B64);

    char *huge = malloc(EVERGRAM_RELAY_PAYLOAD_MAX + 1);
    CHECK(huge != NULL);
    if (huge == NULL) {
        return;
    }
    memset(huge, 'x', EVERGRAM_RELAY_PAYLOAD_MAX);
    huge[EVERGRAM_RELAY_PAYLOAD_MAX] = '\0';

    feed_relay(TEST_ROOM_TOKEN, EVERGRAM__RELAY_MESSAGE_KIND__RELAY_TEXT, huge);
    CHECK_EQ_INT(g_text_calls, 0);

    free(huge);
}

static void test_unset_kind_and_token_are_ignored(void) {
    reset_state();

    Evergram__RelayMessage relay = EVERGRAM__RELAY_MESSAGE__INIT;
    relay.room_token = (char *)TEST_ROOM_TOKEN;
    /* No kind: the gateway would never do this, so it must be ignored. */
    Evergram__ServerMessage message = EVERGRAM__SERVER_MESSAGE__INIT;
    message.relay_message = &relay;
    message.payload_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_RELAY_MESSAGE;
    feed(&message);

    Evergram__RelayMessage empty = EVERGRAM__RELAY_MESSAGE__INIT;
    empty.has_kind = 1;
    empty.kind = EVERGRAM__RELAY_MESSAGE_KIND__RELAY_TEXT;
    Evergram__ServerMessage second = EVERGRAM__SERVER_MESSAGE__INIT;
    second.relay_message = &empty;
    second.payload_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_RELAY_MESSAGE;
    feed(&second);

    CHECK_EQ_INT(g_text_calls, 0);
    CHECK_EQ_INT(g_state_calls, 0);
}

/* The frame the owner sends to claim a room: the gateway matches on kind, and
 * a payload on JOINED would be rejected, so the shape matters. */
static void test_joined_frame_shape(void) {
    reset_state();

    Evergram__RelayMessage relay;
    evergram_relay_fill_message(&relay, TEST_ROOM_TOKEN, EVERGRAM_RELAY_KIND_JOINED, NULL);
    CHECK_EQ_STR(relay.room_token, TEST_ROOM_TOKEN);
    CHECK_EQ_INT(relay.has_kind, 1);
    CHECK_EQ_INT(relay.kind, EVERGRAM__RELAY_MESSAGE_KIND__RELAY_JOINED);
    CHECK_EQ_INT(relay.has_payload, 0);
    CHECK(!evergram_relay_kind_is_content(EVERGRAM_RELAY_KIND_JOINED));

    /* A payload is handed over as raw bytes, not as a NUL-terminated string. */
    evergram_relay_fill_message(&relay, TEST_ROOM_TOKEN, EVERGRAM_RELAY_KIND_TEXT, "{\"a\":1}");
    CHECK_EQ_INT(relay.has_payload, 1);
    CHECK_EQ_INT((long long)relay.payload.len, 7);
    CHECK_EQ_INT(memcmp(relay.payload.data, "{\"a\":1}", 7), 0);
    CHECK_EQ_INT(relay.kind, EVERGRAM__RELAY_MESSAGE_KIND__RELAY_TEXT);

    /* An empty payload is omitted rather than sent as a zero-length field. */
    evergram_relay_fill_message(&relay, TEST_ROOM_TOKEN, EVERGRAM_RELAY_KIND_END, "");
    CHECK_EQ_INT(relay.has_payload, 0);

    /* An unmapped kind must not silently become a valid one. */
    evergram_relay_fill_message(&relay, TEST_ROOM_TOKEN, EVERGRAM_RELAY_KIND_UNKNOWN, NULL);
    CHECK_EQ_INT(relay.has_kind, 0);
}

/* A persisted room must be usable again after a restart, before any frame
 * arrives from the gateway. */
static void test_register_room_restores_a_session(void) {
    reset_state();

    uint8_t expected[EVERGRAM_SYM_KEY_SIZE];
    room_key(expected);
    CHECK_EQ_INT(evergram_visitor_register_room(client(), TEST_ROOM_TOKEN, expected), EVERGRAM_OK);
    CHECK(evergram_visitor_has_room(client(), TEST_ROOM_TOKEN));

    uint8_t key[EVERGRAM_SYM_KEY_SIZE];
    CHECK_EQ_INT(evergram_visitor_room_key(client(), TEST_ROOM_TOKEN, key), EVERGRAM_OK);
    CHECK_EQ_INT(sodium_memcmp(key, expected, sizeof(key)), 0);

    /* The restored key decrypts frames, so the room is fully functional. */
    feed_relay(TEST_ROOM_TOKEN, EVERGRAM__RELAY_MESSAGE_KIND__RELAY_TEXT,
               VECTOR_RELAY_TEXT_PAYLOAD);
    CHECK_EQ_INT(g_text_calls, 1);
    CHECK_EQ_STR(g_text.text, VECTOR_RELAY_TEXT_MESSAGE);

    CHECK_EQ_INT(evergram_visitor_register_room(NULL, TEST_ROOM_TOKEN, expected),
                 EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(evergram_visitor_register_room(client(), NULL, expected),
                 EVERGRAM_ERR_INVALID_ARG);
}

/* The channel snapshot is reported through the same callbacks the live frames
 * use; the arrays stay owned by the response, so the callback contract is
 * "borrowed for the duration of the call". */
static void test_channel_snapshot_reaches_callbacks(void) {
    reset_state();

    char *participants[] = {(char *)"1:rAlice", (char *)"1:rBob"};
    char *ops[] = {(char *)"1:rAlice"};
    evergram_visitor_report_snapshot(client(), TEST_ROOM_TOKEN, participants, 2, true, ops, 1, NULL,
                                     0);

    CHECK_EQ_INT(g_presence_calls, 2);
    CHECK_EQ_STR(g_presence_sender, "1:rBob"); /* the last one is kept */
    CHECK(g_presence_joined);
    CHECK_EQ_INT(g_moderation_calls, 1);
    CHECK(g_moderated);
    CHECK_EQ_INT((long long)g_ops_count, 1);
    CHECK_EQ_INT((long long)g_voiced_count, 0);

    /* An unmoderated channel with no ops or voices reports no snapshot at all,
     * rather than an empty one on every subscribe. */
    reset_state();
    evergram_visitor_report_snapshot(client(), TEST_ROOM_TOKEN, participants, 1, false, NULL, 0,
                                     NULL, 0);
    CHECK_EQ_INT(g_presence_calls, 1);
    CHECK_EQ_INT(g_moderation_calls, 0);
    CHECK_EQ_INT(g_ops_count, 0);
}

static void test_channel_call_validation(void) {
    reset_state();

    evergram_visitor_room_t room;
    CHECK_EQ_INT(evergram_visitor_subscribe_channel(client(), NULL, "aabb", 0, &room),
                 EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(evergram_visitor_subscribe_channel(client(), "widget", NULL, 0, &room),
                 EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(evergram_visitor_subscribe_channel(client(), "", "aabb", 0, &room),
                 EVERGRAM_ERR_INVALID_ARG);
    /* The channel key is 32 bytes of hex, so a short one is a caller bug. */
    CHECK_EQ_INT(evergram_visitor_subscribe_channel(client(), "widget", "zz", 0, &room),
                 EVERGRAM_ERR_INVALID_ARG);

    CHECK_EQ_INT(evergram_visitor_moderate_channel(client(), NULL, EVERGRAM_MODERATION_KICK, "x",
                                                   0),
                 EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(evergram_visitor_announce_presence(client(), TEST_ROOM_TOKEN, NULL, NULL),
                 EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(evergram_visitor_announce_presence(client(), TEST_ROOM_TOKEN, "", NULL),
                 EVERGRAM_ERR_INVALID_ARG);

    /* Presence is plaintext, so it only needs a connection. */
    CHECK_EQ_INT(evergram_visitor_announce_presence(client(), TEST_ROOM_TOKEN, "1:rBot", NULL),
                 EVERGRAM_ERR_NOT_CONNECTED);
}

/* A registered room is one this client must re-claim; a channel is not, because
 * only a fresh subscribe rejoins it. */
static void test_room_role_tagging(void) {
    reset_state();

    uint8_t key[EVERGRAM_SYM_KEY_SIZE];
    room_key(key);
    CHECK_EQ_INT(evergram_visitor_register_room(client(), TEST_ROOM_TOKEN, key), EVERGRAM_OK);
    CHECK_EQ_INT(chatkeys_tag(client()->room_keys, TEST_ROOM_TOKEN),
                 EVERGRAM_ROOM_ROLE_JOINER);

    /* Re-claiming is a no-op while offline, and must not touch the key. */
    evergram_rooms_rejoin(client());
    CHECK(evergram_visitor_has_room(client(), TEST_ROOM_TOKEN));

    CHECK_EQ_INT(chatkeys_set_tagged(client()->room_keys, "channel-1", key,
                                     EVERGRAM_ROOM_ROLE_CHANNEL),
                 EVERGRAM_OK);
    evergram_rooms_rejoin(client());
    CHECK(evergram_visitor_has_room(client(), "channel-1"));
}

static const test_case_t visitor_cases[] = {
    {"visitor: no room key until one is offered", test_no_key_until_offered},
    {"visitor: offered room reaches the callback", test_room_requested_reaches_callback},
    {"visitor: room sealed for another device is ignored",
     test_room_for_another_device_is_ignored},
    {"visitor: tampered room key is rejected", test_tampered_room_key_is_rejected},
    {"visitor: encrypted text frame decrypts", test_text_frame_reaches_callback},
    {"visitor: content frames without a key are ignored",
     test_content_frames_without_key_are_ignored},
    {"visitor: react, edit and remove frames", test_react_edit_and_remove_frames},
    {"visitor: typing and session state frames", test_typing_and_state_frames},
    {"visitor: a room claimed elsewhere is forgotten", test_claimed_elsewhere_forgets_the_room},
    {"visitor: channel presence, mode and kick", test_channel_frames},
    {"visitor: timed out event drops the key", test_timed_out_event},
    {"visitor: oversized payload is rejected", test_oversized_payload_is_rejected},
    {"visitor: joined frame shape", test_joined_frame_shape},
    {"visitor: a persisted room is restored", test_register_room_restores_a_session},
    {"visitor: channel snapshot reaches callbacks", test_channel_snapshot_reaches_callbacks},
    {"visitor: channel call validation", test_channel_call_validation},
    {"visitor: room and channel roles differ", test_room_role_tagging},
    {"visitor: unset kind and token are ignored", test_unset_kind_and_token_are_ignored},
};

const test_case_t *visitor_tests(size_t *count) {
    *count = sizeof(visitor_cases) / sizeof(visitor_cases[0]);
    return visitor_cases;
}
