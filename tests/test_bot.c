#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "e2ee_vectors.h"
#include "evergram.pb-c.h"
#include "internal.h"
#include "test.h"

/*
 * Bot-layer tests. The interesting one is the mailbox: a SEND that arrives
 * before its chat key must be held and delivered once the key lands, instead of
 * being dropped as undecryptable.
 */

#define BOT_URL "wss://127.0.0.1:1/api/ws"
#define BOT_IDENTITY_PATH "build/test_bot_identity.json"
#define BOT_DEVICE_ID "test-device-id"
#define BOT_CHAT_ID "bot-chat"
#define BOT_WALLET_SEED "db7fc7a261e8082cc0f3fdb3b3f15f95bb727ba9b533246eb4d46ec70604ea96"
#define BOT_WALLET_ADDRESS "rMibrQV7rCNq5bMkaWx9wZkF9vt23fw2yB"
#define BOT_IDENTITY_KEY "1:" BOT_WALLET_ADDRESS

static int g_messages;
static char g_text[256];

static void on_message(evergram_t *eg, const evergram_message_t *message) {
    (void)eg;
    g_messages++;
    snprintf(g_text, sizeof(g_text), "%s", message->text != NULL ? message->text : "");
}

/* An identity whose device key matches the tweetnacl sealed-key vectors. */
static bool write_bot_identity(void) {
    FILE *file = fopen(BOT_IDENTITY_PATH, "w");
    if (file == NULL) {
        return false;
    }

    fprintf(file,
            "seed=%s\n"
            "address=%s\n"
            "pubkey=ED%s\n"
            "privkey=ED%s\n"
            "device_pub=%s\n"
            "device_priv=%s\n"
            "device_id=%s\n",
            BOT_WALLET_SEED, BOT_WALLET_ADDRESS, BOT_WALLET_SEED, BOT_WALLET_SEED,
            VECTOR_DEVICE_PUBLIC_KEY_HEX, VECTOR_DEVICE_PRIVATE_KEY_HEX, BOT_DEVICE_ID);
    fclose(file);
    return true;
}

static void feed(evergram_t *eg, Evergram__ServerMessage *message) {
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
    parser_dispatch(eg, packed, size);
    free(packed);
}

static void feed_chat_key(evergram_t *eg) {
    Evergram__SymKeyEncrypted sealed = EVERGRAM__SYM_KEY_ENCRYPTED__INIT;
    sealed.ephemeral_pubkey = (char *)VECTOR_EPHEMERAL_PUBLIC_KEY_B64;
    sealed.ciphertext = (char *)VECTOR_SEALED_CIPHERTEXT_B64;
    sealed.nonce = (char *)VECTOR_SEALED_NONCE_B64;

    Evergram__AccountSymKeys__DevicesEntry device =
        EVERGRAM__ACCOUNT_SYM_KEYS__DEVICES_ENTRY__INIT;
    device.key = (char *)BOT_DEVICE_ID;
    device.value = &sealed;
    Evergram__AccountSymKeys__DevicesEntry *devices[] = {&device};

    Evergram__AccountSymKeys account = EVERGRAM__ACCOUNT_SYM_KEYS__INIT;
    account.n_devices = 1;
    account.devices = devices;

    Evergram__ChatInfo__SymKeyEncryptedEntry entry =
        EVERGRAM__CHAT_INFO__SYM_KEY_ENCRYPTED_ENTRY__INIT;
    entry.key = (char *)BOT_IDENTITY_KEY;
    entry.value = &account;
    Evergram__ChatInfo__SymKeyEncryptedEntry *entries[] = {&entry};

    Evergram__ChatInfo chat = EVERGRAM__CHAT_INFO__INIT;
    chat.chat_id = (char *)BOT_CHAT_ID;
    chat.type = "one-on-one";
    chat.n_sym_key_encrypted = 1;
    chat.sym_key_encrypted = entries;

    Evergram__CreateChatResponse response = EVERGRAM__CREATE_CHAT_RESPONSE__INIT;
    response.chat = &chat;

    Evergram__ServerMessage message = EVERGRAM__SERVER_MESSAGE__INIT;
    message.payload_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_CREATE_CHAT_RESPONSE;
    message.create_chat_response = &response;
    feed(eg, &message);
}

static void feed_send(evergram_t *eg) {
    Evergram__SendContent content = EVERGRAM__SEND_CONTENT__INIT;
    content.msg_id = "held-message";
    content.ciphertext = (char *)VECTOR_MESSAGE_CIPHERTEXT_B64;
    content.nonce = (char *)VECTOR_MESSAGE_NONCE_B64;

    Evergram__Envelope envelope = EVERGRAM__ENVELOPE__INIT;
    envelope.type = "SEND";
    envelope.chat_id = (char *)BOT_CHAT_ID;
    envelope.sender = "1:rAlice";
    envelope.send = &content;
    envelope.content_case = EVERGRAM__ENVELOPE__CONTENT_SEND;

    Evergram__ServerMessage message = EVERGRAM__SERVER_MESSAGE__INIT;
    message.payload_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_ENVELOPE;
    message.envelope = &envelope;
    feed(eg, &message);
}

static evergram_bot_t *make_bot(void) {
    if (!write_bot_identity()) {
        return NULL;
    }

    const evergram_bot_options_t options = {
        .url = BOT_URL,
        .identity_path = BOT_IDENTITY_PATH,
        .platform = "Test",
    };

    evergram_bot_t *bot = evergram_bot_create(&options);
    if (bot != NULL) {
        evergram_bot_on_message(bot, on_message);
    }
    return bot;
}

static void test_create_loads_identity(void) {
    evergram_bot_t *bot = make_bot();
    CHECK(bot != NULL);
    if (bot == NULL) {
        return;
    }

    CHECK(evergram_bot_client(bot) != NULL);
    CHECK(!evergram_bot_is_online(bot));
    CHECK_EQ_INT(evergram_bot_pending_count(bot), 0);
    CHECK_EQ_INT(evergram_bot_status(bot), EVERGRAM_ERR_NOT_CONNECTED);

    evergram_bot_destroy(bot);
    remove(BOT_IDENTITY_PATH);
}

/* A SEND with no key yet must be held, then delivered when the key arrives. */
static void test_mailbox_holds_until_key_arrives(void) {
    g_messages = 0;
    g_text[0] = '\0';

    evergram_bot_t *bot = make_bot();
    CHECK(bot != NULL);
    if (bot == NULL) {
        return;
    }

    evergram_t *client = evergram_bot_client(bot);

    feed_send(client);
    CHECK_EQ_INT(g_messages, 0); /* nothing delivered: the body is unreadable */
    CHECK_EQ_INT(evergram_bot_pending_count(bot), 1);

    /* The same frame deferred twice must not be queued twice. */
    feed_send(client);
    CHECK_EQ_INT(evergram_bot_pending_count(bot), 1);

    feed_chat_key(client);
    CHECK(evergram_has_chat_key(client, BOT_CHAT_ID));

    /* Delivery happens on the next poll, outside the callback that deferred it. */
    evergram_bot_poll(bot, 0);

    CHECK_EQ_INT(g_messages, 1);
    CHECK_EQ_STR(g_text, VECTOR_MESSAGE_PLAINTEXT);
    CHECK_EQ_INT(evergram_bot_pending_count(bot), 0);

    evergram_bot_destroy(bot);
    remove(BOT_IDENTITY_PATH);
}

static void test_poll_is_safe_offline(void) {
    evergram_bot_t *bot = make_bot();
    CHECK(bot != NULL);
    if (bot == NULL) {
        return;
    }

    /* No connection was started: polling must be a harmless no-op. */
    evergram_status_t status = evergram_bot_poll(bot, 0);
    CHECK(status == EVERGRAM_OK || status == EVERGRAM_ERR_TIMEOUT ||
          status == EVERGRAM_ERR_NOT_CONNECTED);

    evergram_bot_destroy(bot);
    remove(BOT_IDENTITY_PATH);
}

static void test_invalid_options(void) {
    CHECK(evergram_bot_create(NULL) == NULL);

    const evergram_bot_options_t no_url = {.url = NULL};
    CHECK(evergram_bot_create(&no_url) == NULL);

    const evergram_bot_options_t empty_url = {.url = ""};
    CHECK(evergram_bot_create(&empty_url) == NULL);

    evergram_bot_destroy(NULL);
    CHECK(evergram_bot_client(NULL) == NULL);
    CHECK(!evergram_bot_is_online(NULL));
    CHECK_EQ_INT(evergram_bot_pending_count(NULL), 0);
    CHECK_EQ_INT(evergram_bot_reconnect_attempts(NULL), 0);
    evergram_bot_stop(NULL);
}

/* Mirrors the TypeScript SDK's typingDelayMs(): min(2000, max(500, len*35)). */
static void test_typing_delay_curve(void) {
    CHECK_EQ_INT(evergram_typing_delay_ms(0), 500);
    CHECK_EQ_INT(evergram_typing_delay_ms(10), 500);   /* 350 -> floored */
    CHECK_EQ_INT(evergram_typing_delay_ms(20), 700);
    CHECK_EQ_INT(evergram_typing_delay_ms(57), 1995);
    CHECK_EQ_INT(evergram_typing_delay_ms(58), 2000);  /* 2030 -> capped */
    CHECK_EQ_INT(evergram_typing_delay_ms(100000), 2000);
}

/* --- visitor rooms --------------------------------------------------------- */

static int g_rooms;
static char g_room_token[EVERGRAM_ROOM_TOKEN_SIZE];
static char g_room_label[EVERGRAM_VISITOR_LABEL_SIZE];
static int g_visitor_messages;
static int g_visitor_states;
static bool g_last_handle_was_null;
static evergram_visitor_handle_t g_handle;

static void on_visitor_room(evergram_bot_t *bot, const char *room_token,
                            const evergram_visitor_handle_t *handle,
                            const evergram_relay_text_t *first_message) {
    (void)bot;
    (void)first_message;
    g_rooms++;
    snprintf(g_room_token, sizeof(g_room_token), "%s", room_token);
    g_last_handle_was_null = (handle == NULL);
    if (handle != NULL) {
        g_handle = *handle;
        snprintf(g_room_label, sizeof(g_room_label), "%s", handle->visitor_label);
    }
}

static void on_visitor_message(evergram_bot_t *bot, const char *room_token,
                               const evergram_visitor_handle_t *handle,
                               const evergram_relay_text_t *event) {
    (void)bot;
    (void)room_token;
    (void)event;
    g_visitor_messages++;
    g_last_handle_was_null = (handle == NULL);
}

static void on_visitor_state(evergram_bot_t *bot, const char *room_token,
                             const evergram_visitor_handle_t *handle,
                             const evergram_visitor_state_event_t *event) {
    (void)bot;
    (void)room_token;
    (void)handle;
    (void)event;
    g_visitor_states++;
}

/* Reuses the visitor frame builders from the client tests: the bot layer must
 * pass a complete handle to every handler for a room it knows. */
static void feed_visitor_room(evergram_t *eg) {
    Evergram__SealedKeyForDevice sealed = EVERGRAM__SEALED_KEY_FOR_DEVICE__INIT;
    sealed.ciphertext = (char *)VECTOR_SEALED_ROOM_CIPHERTEXT_B64;
    sealed.nonce = (char *)VECTOR_SEALED_ROOM_NONCE_B64;
    sealed.ephemeral_pubkey = (char *)VECTOR_EPHEMERAL_PUBLIC_KEY_B64;

    Evergram__VisitorRoomRequestedEvent__SealedKeyByDeviceEntry entry =
        EVERGRAM__VISITOR_ROOM_REQUESTED_EVENT__SEALED_KEY_BY_DEVICE_ENTRY__INIT;
    entry.key = (char *)BOT_DEVICE_ID;
    entry.value = &sealed;
    Evergram__VisitorRoomRequestedEvent__SealedKeyByDeviceEntry *entries[1] = {&entry};

    Evergram__VisitorRoomRequestedEvent event = EVERGRAM__VISITOR_ROOM_REQUESTED_EVENT__INIT;
    event.room_token = (char *)"bot-room-1";
    event.widget_id = (char *)"bot-widget";
    event.visitor_label = (char *)"web visitor";
    event.origin = (char *)"https://example.com";
    event.n_sealed_key_by_device = 1;
    event.sealed_key_by_device = entries;

    Evergram__ServerMessage message = EVERGRAM__SERVER_MESSAGE__INIT;
    message.visitor_room_requested_event = &event;
    message.payload_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_VISITOR_ROOM_REQUESTED_EVENT;
    feed(eg, &message);
}

static void feed_visitor_text(evergram_t *eg, const char *room_token) {
    Evergram__RelayMessage relay = EVERGRAM__RELAY_MESSAGE__INIT;
    relay.room_token = (char *)room_token;
    relay.has_kind = 1;
    relay.kind = EVERGRAM__RELAY_MESSAGE_KIND__RELAY_TEXT;
    relay.has_payload = 1;
    relay.payload.data = (uint8_t *)VECTOR_RELAY_TEXT_PAYLOAD;
    relay.payload.len = strlen(VECTOR_RELAY_TEXT_PAYLOAD);

    Evergram__ServerMessage message = EVERGRAM__SERVER_MESSAGE__INIT;
    message.relay_message = &relay;
    message.payload_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_RELAY_MESSAGE;
    feed(eg, &message);
}

static void test_visitor_handlers_receive_a_handle(void) {
    g_rooms = 0;
    g_visitor_messages = 0;
    g_visitor_states = 0;
    g_last_handle_was_null = false;
    memset(&g_handle, 0, sizeof(g_handle));
    g_room_token[0] = '\0';
    g_room_label[0] = '\0';

    evergram_bot_t *bot = make_bot();
    CHECK(bot != NULL);
    if (bot == NULL) {
        return;
    }

    evergram_bot_on_visitor_room(bot, on_visitor_room);
    evergram_bot_on_visitor_message(bot, on_visitor_message);
    evergram_bot_on_visitor_state(bot, on_visitor_state);

    evergram_t *client = evergram_bot_client(bot);
    feed_visitor_room(client);

    CHECK_EQ_INT(g_rooms, 1);
    CHECK_EQ_STR(g_room_token, "bot-room-1");
    CHECK(!g_last_handle_was_null);
    CHECK_EQ_STR(g_handle.room_token, "bot-room-1");
    CHECK_EQ_STR(g_handle.widget_id, "bot-widget");
    CHECK_EQ_STR(g_room_label, "web visitor");
    CHECK_EQ_STR(g_handle.origin, "https://example.com");

    feed_visitor_text(client, "bot-room-1");
    CHECK_EQ_INT(g_visitor_messages, 1);
    CHECK(!g_last_handle_was_null);

    /* A frame for a room this client holds no key for is not ours to read:
     * it is ignored outright, not held (a room's key always arrives with the
     * room itself, so there is nothing to wait for). */
    feed_visitor_text(client, "some-other-room");
    CHECK_EQ_INT(g_visitor_messages, 1);
    CHECK_EQ_INT((long long)evergram_bot_pending_count(bot), 0);

    feed_visitor_text(client, "bot-room-1");
    CHECK_EQ_INT(g_visitor_messages, 2);
    CHECK(!g_last_handle_was_null);

    Evergram__RelayMessage end = EVERGRAM__RELAY_MESSAGE__INIT;
    end.room_token = (char *)"bot-room-1";
    end.has_kind = 1;
    end.kind = EVERGRAM__RELAY_MESSAGE_KIND__RELAY_END;
    Evergram__ServerMessage end_message = EVERGRAM__SERVER_MESSAGE__INIT;
    end_message.relay_message = &end;
    end_message.payload_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_RELAY_MESSAGE;
    feed(client, &end_message);
    CHECK_EQ_INT(g_visitor_states, 1);

    /* The room is over: its key is gone, so later frames are ignored. */
    feed_visitor_text(client, "bot-room-1");
    CHECK_EQ_INT(g_visitor_messages, 2);

    /* Sends need a room key; the client reports the missing key rather than
     * pretending to have sent anything. */
    CHECK_EQ_INT(evergram_bot_visitor_reply(bot, &g_handle, "hi"), EVERGRAM_ERR_NO_ROOM_KEY);
    CHECK_EQ_INT(evergram_bot_visitor_reply(bot, NULL, "hi"), EVERGRAM_ERR_INVALID_ARG);
    /* Typing is plaintext, so it only needs a connection, not a key. */
    CHECK_EQ_INT(evergram_bot_visitor_typing(bot, &g_handle, true), EVERGRAM_ERR_NOT_CONNECTED);
    CHECK_EQ_INT(evergram_bot_visitor_end(bot, &g_handle), EVERGRAM_ERR_NOT_CONNECTED);

    evergram_bot_destroy(bot);
    remove(BOT_IDENTITY_PATH);
}

/* The deferred wrappers queue a request decision instead of making it inline,
 * because handlers run inside the transport callback. */
static void test_deferred_request_decisions(void) {
    evergram_bot_t *bot = make_bot();
    CHECK(bot != NULL);
    if (bot == NULL) {
        return;
    }

    const size_t before = evergram_bot_action_count(bot);
    CHECK_EQ_INT(evergram_bot_accept_chat_request(bot, "1:rRequester"), EVERGRAM_OK);
    CHECK_EQ_INT(evergram_bot_decline_chat_request(bot, "1:rRequester"), EVERGRAM_OK);
    CHECK_EQ_INT(evergram_bot_accept_group_invite(bot, "chat-1"), EVERGRAM_OK);
    CHECK_EQ_INT(evergram_bot_decline_group_invite(bot, "chat-1"), EVERGRAM_OK);
    CHECK_EQ_INT((long long)(evergram_bot_action_count(bot) - before), 4);

    CHECK_EQ_INT(evergram_bot_accept_chat_request(NULL, "1:rRequester"),
                 EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(evergram_bot_accept_chat_request(bot, NULL), EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(evergram_bot_decline_group_invite(bot, ""), EVERGRAM_ERR_INVALID_ARG);

    /* A queued decision runs only while connected; offline it stays queued. */
    evergram_bot_poll(bot, 0);
    CHECK(evergram_bot_action_count(bot) >= 4);

    evergram_bot_destroy(bot);
    remove(BOT_IDENTITY_PATH);
}

static const test_case_t TESTS[] = {
    {"bot: create loads the identity", test_create_loads_identity},
    {"bot: mailbox holds until the key arrives", test_mailbox_holds_until_key_arrives},
    {"bot: poll is safe while offline", test_poll_is_safe_offline},
    {"bot: invalid options and NULL safety", test_invalid_options},
    {"bot: typing delay curve", test_typing_delay_curve},
    {"bot: visitor handlers receive a handle", test_visitor_handlers_receive_a_handle},
    {"bot: request decisions are deferred", test_deferred_request_decisions},
};

const test_case_t *bot_tests(size_t *count) {
    *count = sizeof(TESTS) / sizeof(TESTS[0]);
    return TESTS;
}
