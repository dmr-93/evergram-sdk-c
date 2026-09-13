#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "e2ee_vectors.h"
#include "evergram.pb-c.h"
#include "internal.h"
#include "test.h"

/*
 * Parser tests.
 *
 * Two things are covered here that used to be wrong or missing:
 *  - protobuf-c stores oneofs in a union, so a TYPING envelope must never be
 *    read as SEND content (this used to segfault);
 *  - a ChatInfo carrying a key sealed for this device must make a following
 *    SEND decrypt, using vectors produced by tweetnacl itself.
 */

#define TEST_URL "wss://127.0.0.1:1/api/ws"
#define TEST_ADDRESS "rTestBotAddress"
#define TEST_DEVICE_ID "test-device-id"
#define TEST_CHAT_ID "chat-under-test"
#define TEST_IDENTITY_KEY "1:" TEST_ADDRESS

static evergram_t *g_client;
static int g_messages;
static int g_edited;
static int g_deleted;
static int g_typings;
static int g_reactions;
static int g_errors;
static int g_join_requests;
static int g_presence_events;
static int g_profile_updates;
static bool g_text_is_null;
static char g_chat_id[EVERGRAM_CHAT_ID_SIZE];
static char g_sender[EVERGRAM_IDENTITY_SIZE];
static char g_message_id[EVERGRAM_MESSAGE_ID_SIZE];
static char g_text[256];
static char g_emoji[EVERGRAM_EMOJI_SIZE];
static char g_join_chat[EVERGRAM_CHAT_ID_SIZE];
static char g_join_identity[EVERGRAM_IDENTITY_SIZE];
static bool g_last_presence_online;
static char g_last_presence_identity[EVERGRAM_IDENTITY_SIZE];
static char g_last_profile_nickname[EVERGRAM_NICKNAME_SIZE];
static char g_last_profile_identity[EVERGRAM_IDENTITY_SIZE];
static bool g_has_reply;

static void reset_state(void) {
    g_messages = 0;
    g_edited = 0;
    g_deleted = 0;
    g_typings = 0;
    g_reactions = 0;
    g_errors = 0;
    g_join_requests = 0;
    g_presence_events = 0;
    g_profile_updates = 0;
    g_last_presence_online = false;
    g_last_presence_identity[0] = '\0';
    g_last_profile_nickname[0] = '\0';
    g_last_profile_identity[0] = '\0';
    g_join_chat[0] = '\0';
    g_join_identity[0] = '\0';
    g_text_is_null = false;
    g_chat_id[0] = '\0';
    g_sender[0] = '\0';
    g_message_id[0] = '\0';
    g_text[0] = '\0';
    g_emoji[0] = '\0';
    g_has_reply = false;
}

static void on_message(evergram_t *eg, const evergram_message_t *message) {
    (void)eg;
    g_messages++;
    snprintf(g_chat_id, sizeof(g_chat_id), "%s", message->chat_id);
    snprintf(g_sender, sizeof(g_sender), "%s", message->sender);
    snprintf(g_message_id, sizeof(g_message_id), "%s", message->message_id);
    g_text_is_null = message->text == NULL;
    snprintf(g_text, sizeof(g_text), "%s", message->text != NULL ? message->text : "");
    g_has_reply = message->reply_to_message_id != NULL;
}

static void on_message_edited(evergram_t *eg, const evergram_message_edited_t *message) {
    (void)eg;
    g_edited++;
    snprintf(g_message_id, sizeof(g_message_id), "%s", message->message_id);
    g_text_is_null = message->text == NULL;
    snprintf(g_text, sizeof(g_text), "%s", message->text != NULL ? message->text : "");
}

static void on_message_deleted(evergram_t *eg, const evergram_message_deleted_t *message) {
    (void)eg;
    g_deleted++;
    snprintf(g_message_id, sizeof(g_message_id), "%s", message->message_id);
}

static void on_typing(evergram_t *eg, const evergram_typing_event_t *event) {
    (void)eg;
    (void)event;
    g_typings++;
}

static void on_reaction(evergram_t *eg, const evergram_reaction_t *reaction) {
    (void)eg;
    g_reactions++;
    snprintf(g_emoji, sizeof(g_emoji), "%s", reaction->emoji);
}

static void on_error(evergram_t *eg, evergram_status_t status, const char *detail) {
    (void)eg;
    (void)status;
    (void)detail;
    g_errors++;
}

static void on_join_request(evergram_t *eg, const evergram_join_request_t *request) {
    (void)eg;
    g_join_requests++;
    snprintf(g_join_chat, sizeof(g_join_chat), "%s", request->chat_id);
    snprintf(g_join_identity, sizeof(g_join_identity), "%s", request->identity);
}

static void on_presence(evergram_t *eg, const evergram_presence_t *presence) {
    (void)eg;
    g_presence_events++;
    g_last_presence_online = presence->online;
    snprintf(g_last_presence_identity, sizeof(g_last_presence_identity), "%s",
             presence->identity_key);
}

static void on_profile_updated(evergram_t *eg, const evergram_profile_t *profile) {
    (void)eg;
    g_profile_updates++;
    snprintf(g_last_profile_nickname, sizeof(g_last_profile_nickname), "%s", profile->nickname);
    snprintf(g_last_profile_identity, sizeof(g_last_profile_identity), "%s",
             profile->identity_key);
}

/* address NULL generates a random wallet; device_id NULL generates a device. */
static evergram_t *make_client_with(const char *address, const char *device_id,
                                    const char *device_public_key_hex,
                                    const char *device_private_key_hex) {
    evergram_wallet_t wallet;
    evergram_device_t device;
    memset(&wallet, 0, sizeof(wallet));
    memset(&device, 0, sizeof(device));

    if (address != NULL) {
        snprintf(wallet.address, sizeof(wallet.address), "%s", address);
    } else if (evergram_wallet_generate(&wallet) != EVERGRAM_OK) {
        return NULL;
    }

    if (device_id != NULL) {
        snprintf(device.device_id, sizeof(device.device_id), "%s", device_id);
        snprintf(device.public_key_hex, sizeof(device.public_key_hex), "%s",
                 device_public_key_hex != NULL ? device_public_key_hex : "");
        snprintf(device.private_key_hex, sizeof(device.private_key_hex), "%s",
                 device_private_key_hex != NULL ? device_private_key_hex : "");
    } else if (evergram_device_generate(&device) != EVERGRAM_OK) {
        return NULL;
    }

    const evergram_options_t options = {
        .url = TEST_URL,
        .wallet = &wallet,
        .device = &device,
        .platform = "Test",
    };

    evergram_t *client = evergram_create(&options);
    evergram_wallet_wipe(&wallet);
    evergram_device_wipe(&device);
    if (client == NULL) {
        return NULL;
    }

    evergram_on_message(client, on_message);
    evergram_on_message_edited(client, on_message_edited);
    evergram_on_message_deleted(client, on_message_deleted);
    evergram_on_typing(client, on_typing);
    evergram_on_reaction(client, on_reaction);
    evergram_on_error(client, on_error);
    evergram_on_join_request(client, on_join_request);
    evergram_on_presence(client, on_presence);
    evergram_on_profile_updated(client, on_profile_updated);
    return client;
}

/* The client owns no socket until evergram_start(), so it is safe offline.
 * Destroyed at exit so leak checkers see a clean run. */
static void destroy_client(void) {
    evergram_destroy(g_client);
    g_client = NULL;
}

static evergram_t *client(void) {
    if (g_client == NULL) {
        g_client = make_client_with(NULL, NULL, NULL, NULL);
        if (g_client != NULL) {
            atexit(destroy_client);
        }
    }
    return g_client;
}

/* A client whose device key matches the tweetnacl vectors. */
static evergram_t *vector_client(void) {
    return make_client_with(TEST_ADDRESS, TEST_DEVICE_ID, VECTOR_DEVICE_PUBLIC_KEY_HEX,
                            VECTOR_DEVICE_PRIVATE_KEY_HEX);
}

static void feed_to(evergram_t *eg, Evergram__ServerMessage *message) {
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

static void feed(Evergram__ServerMessage *message) {
    feed_to(client(), message);
}

static void fill_envelope(Evergram__Envelope *envelope, const char *type) {
    envelope->type = (char *)type;
    envelope->chat_id = TEST_CHAT_ID;
    envelope->sender = "1:rAlice";
    envelope->has_ts = 1;
    envelope->ts = 1700000000000;
}

/* Builds the ChatInfo the gateway would send, with a key sealed for
 * TEST_DEVICE_ID by the tweetnacl-generated vectors. */
static Evergram__SymKeyEncrypted g_sealed;
static Evergram__AccountSymKeys__DevicesEntry g_device_entry;
static Evergram__AccountSymKeys__DevicesEntry *g_device_entries[1];
static Evergram__AccountSymKeys g_account;
static Evergram__ChatInfo__SymKeyEncryptedEntry g_account_entry;
static Evergram__ChatInfo__SymKeyEncryptedEntry *g_account_entries[1];
static Evergram__ChatInfo g_chat;

static void build_sealed_chat_info(void) {
    evergram__sym_key_encrypted__init(&g_sealed);
    g_sealed.ephemeral_pubkey = (char *)VECTOR_EPHEMERAL_PUBLIC_KEY_B64;
    g_sealed.ciphertext = (char *)VECTOR_SEALED_CIPHERTEXT_B64;
    g_sealed.nonce = (char *)VECTOR_SEALED_NONCE_B64;

    evergram__account_sym_keys__devices_entry__init(&g_device_entry);
    g_device_entry.key = (char *)TEST_DEVICE_ID;
    g_device_entry.value = &g_sealed;
    g_device_entries[0] = &g_device_entry;

    evergram__account_sym_keys__init(&g_account);
    g_account.n_devices = 1;
    g_account.devices = g_device_entries;

    evergram__chat_info__sym_key_encrypted_entry__init(&g_account_entry);
    g_account_entry.key = (char *)TEST_IDENTITY_KEY;
    g_account_entry.value = &g_account;
    g_account_entries[0] = &g_account_entry;

    evergram__chat_info__init(&g_chat);
    g_chat.chat_id = (char *)TEST_CHAT_ID;
    g_chat.type = "one-on-one";
    g_chat.n_sym_key_encrypted = 1;
    g_chat.sym_key_encrypted = g_account_entries;
}

static void test_typing_envelope_does_not_crash(void) {
    reset_state();

    Evergram__TypingContent typing = EVERGRAM__TYPING_CONTENT__INIT;
    typing.has_is_typing = 1;
    typing.is_typing = 1;

    Evergram__Envelope envelope = EVERGRAM__ENVELOPE__INIT;
    fill_envelope(&envelope, "TYPING");
    envelope.typing = &typing;
    envelope.content_case = EVERGRAM__ENVELOPE__CONTENT_TYPING;

    Evergram__ServerMessage message = EVERGRAM__SERVER_MESSAGE__INIT;
    message.envelope = &envelope;
    message.payload_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_ENVELOPE;

    feed(&message);

    CHECK_EQ_INT(g_typings, 1);
    CHECK_EQ_INT(g_messages, 0);
    CHECK_EQ_INT(g_errors, 0);
}

static void test_send_without_key_delivers_no_text(void) {
    reset_state();

    Evergram__SendContent content = EVERGRAM__SEND_CONTENT__INIT;
    content.msg_id = "message-1";
    content.ciphertext = "ciphertext-blob";
    content.nonce = "nonce";
    content.reply_to_msg_id = "message-0";

    Evergram__Envelope envelope = EVERGRAM__ENVELOPE__INIT;
    fill_envelope(&envelope, "SEND");
    envelope.send = &content;
    envelope.content_case = EVERGRAM__ENVELOPE__CONTENT_SEND;

    Evergram__ServerMessage message = EVERGRAM__SERVER_MESSAGE__INIT;
    message.envelope = &envelope;
    message.payload_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_ENVELOPE;

    feed(&message);

    CHECK_EQ_INT(g_messages, 1);
    CHECK_EQ_STR(g_chat_id, TEST_CHAT_ID);
    CHECK_EQ_STR(g_sender, "1:rAlice");
    CHECK_EQ_STR(g_message_id, "message-1");
    CHECK(g_has_reply);
    CHECK(g_text_is_null); /* no key yet: the body stays encrypted */
}

static void test_chat_info_makes_send_decrypt(void) {
    reset_state();

    evergram_t *eg = vector_client();
    CHECK(eg != NULL);
    if (eg == NULL) {
        return;
    }
    CHECK(!evergram_has_chat_key(eg, TEST_CHAT_ID));

    build_sealed_chat_info();
    Evergram__CreateChatResponse response = EVERGRAM__CREATE_CHAT_RESPONSE__INIT;
    response.chat = &g_chat;

    Evergram__ServerMessage chat_message = EVERGRAM__SERVER_MESSAGE__INIT;
    chat_message.payload_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_CREATE_CHAT_RESPONSE;
    chat_message.create_chat_response = &response;
    feed_to(eg, &chat_message);

    /* The client must have opened the sealed key with its own device key. */
    CHECK(evergram_has_chat_key(eg, TEST_CHAT_ID));

    Evergram__SendContent content = EVERGRAM__SEND_CONTENT__INIT;
    content.msg_id = "message-2";
    content.ciphertext = (char *)VECTOR_MESSAGE_CIPHERTEXT_B64;
    content.nonce = (char *)VECTOR_MESSAGE_NONCE_B64;

    Evergram__Envelope envelope = EVERGRAM__ENVELOPE__INIT;
    fill_envelope(&envelope, "SEND");
    envelope.send = &content;
    envelope.content_case = EVERGRAM__ENVELOPE__CONTENT_SEND;

    Evergram__ServerMessage message = EVERGRAM__SERVER_MESSAGE__INIT;
    message.envelope = &envelope;
    message.payload_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_ENVELOPE;
    feed_to(eg, &message);

    CHECK_EQ_INT(g_messages, 1);
    CHECK(!g_text_is_null);
    CHECK_EQ_STR(g_text, VECTOR_MESSAGE_PLAINTEXT);

    evergram_destroy(eg);
}

static void test_reaction_decrypts_emoji(void) {
    reset_state();

    evergram_t *eg = vector_client();
    CHECK(eg != NULL);
    if (eg == NULL) {
        return;
    }

    build_sealed_chat_info();
    Evergram__CreateChatResponse response = EVERGRAM__CREATE_CHAT_RESPONSE__INIT;
    response.chat = &g_chat;

    Evergram__ServerMessage chat_message = EVERGRAM__SERVER_MESSAGE__INIT;
    chat_message.payload_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_CREATE_CHAT_RESPONSE;
    chat_message.create_chat_response = &response;
    feed_to(eg, &chat_message);

    Evergram__ReactContent reaction = EVERGRAM__REACT_CONTENT__INIT;
    reaction.msg_id = "message-3";
    reaction.ciphertext = (char *)VECTOR_MESSAGE_CIPHERTEXT_B64;
    reaction.nonce = (char *)VECTOR_MESSAGE_NONCE_B64;

    Evergram__Envelope envelope = EVERGRAM__ENVELOPE__INIT;
    fill_envelope(&envelope, "REACT");
    envelope.react = &reaction;
    envelope.content_case = EVERGRAM__ENVELOPE__CONTENT_REACT;

    Evergram__ServerMessage message = EVERGRAM__SERVER_MESSAGE__INIT;
    message.envelope = &envelope;
    message.payload_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_ENVELOPE;
    feed_to(eg, &message);

    CHECK_EQ_INT(g_reactions, 1);
    CHECK_EQ_STR(g_emoji, VECTOR_MESSAGE_PLAINTEXT);

    evergram_destroy(eg);
}

static void test_edit_envelope_reports_edited(void) {
    reset_state();

    evergram_t *eg = vector_client();
    CHECK(eg != NULL);
    if (eg == NULL) {
        return;
    }

    build_sealed_chat_info();
    Evergram__CreateChatResponse response = EVERGRAM__CREATE_CHAT_RESPONSE__INIT;
    response.chat = &g_chat;

    Evergram__ServerMessage chat_message = EVERGRAM__SERVER_MESSAGE__INIT;
    chat_message.payload_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_CREATE_CHAT_RESPONSE;
    chat_message.create_chat_response = &response;
    feed_to(eg, &chat_message);

    Evergram__EditContent edit = EVERGRAM__EDIT_CONTENT__INIT;
    edit.msg_id = "message-4";
    edit.ciphertext = (char *)VECTOR_MESSAGE_CIPHERTEXT_B64;
    edit.nonce = (char *)VECTOR_MESSAGE_NONCE_B64;
    edit.has_edited_at = 1;
    edit.edited_at = 1700000001000;
    edit.has_removed = 1;
    edit.removed = 0;

    Evergram__Envelope envelope = EVERGRAM__ENVELOPE__INIT;
    fill_envelope(&envelope, "EDIT");
    envelope.edit = &edit;
    envelope.content_case = EVERGRAM__ENVELOPE__CONTENT_EDIT;

    Evergram__ServerMessage message = EVERGRAM__SERVER_MESSAGE__INIT;
    message.envelope = &envelope;
    message.payload_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_ENVELOPE;
    feed_to(eg, &message);

    CHECK_EQ_INT(g_edited, 1);
    CHECK_EQ_INT(g_deleted, 0);
    CHECK_EQ_STR(g_message_id, "message-4");
    CHECK_EQ_STR(g_text, VECTOR_MESSAGE_PLAINTEXT);

    evergram_destroy(eg);
}

static void test_edit_removed_reports_deleted(void) {
    reset_state();

    Evergram__EditContent edit = EVERGRAM__EDIT_CONTENT__INIT;
    edit.msg_id = "message-5";
    edit.ciphertext = "";
    edit.nonce = "";
    edit.has_edited_at = 1;
    edit.edited_at = 1700000002000;
    edit.has_removed = 1;
    edit.removed = 1;

    Evergram__Envelope envelope = EVERGRAM__ENVELOPE__INIT;
    fill_envelope(&envelope, "EDIT");
    envelope.edit = &edit;
    envelope.content_case = EVERGRAM__ENVELOPE__CONTENT_EDIT;

    Evergram__ServerMessage message = EVERGRAM__SERVER_MESSAGE__INIT;
    message.envelope = &envelope;
    message.payload_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_ENVELOPE;
    feed(&message);

    CHECK_EQ_INT(g_deleted, 1);
    CHECK_EQ_INT(g_edited, 0);
    CHECK_EQ_STR(g_message_id, "message-5");
}

static void test_envelope_without_content_is_ignored(void) {
    reset_state();

    Evergram__Envelope envelope = EVERGRAM__ENVELOPE__INIT;
    fill_envelope(&envelope, "SEND");
    envelope.content_case = EVERGRAM__ENVELOPE__CONTENT__NOT_SET;

    Evergram__ServerMessage message = EVERGRAM__SERVER_MESSAGE__INIT;
    message.envelope = &envelope;
    message.payload_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_ENVELOPE;

    feed(&message);

    CHECK_EQ_INT(g_messages, 0);
    CHECK_EQ_INT(g_typings, 0);
    CHECK_EQ_INT(g_reactions, 0);
    CHECK_EQ_INT(g_errors, 0);
}

static void test_envelope_without_chat_is_ignored(void) {
    reset_state();

    Evergram__SendContent content = EVERGRAM__SEND_CONTENT__INIT;
    content.msg_id = "message-6";
    content.ciphertext = "blob";

    Evergram__Envelope envelope = EVERGRAM__ENVELOPE__INIT;
    envelope.type = "SEND";
    envelope.sender = "1:rAlice";
    envelope.send = &content;
    envelope.content_case = EVERGRAM__ENVELOPE__CONTENT_SEND;

    Evergram__ServerMessage message = EVERGRAM__SERVER_MESSAGE__INIT;
    message.envelope = &envelope;
    message.payload_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_ENVELOPE;

    feed(&message);

    CHECK_EQ_INT(g_messages, 0);
    CHECK_EQ_INT(g_errors, 0);
}

static void test_garbage_reports_protocol_error(void) {
    reset_state();

    const uint8_t garbage[] = {0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0x00, 0x13, 0x37};
    parser_dispatch(client(), garbage, sizeof(garbage));

    CHECK_EQ_INT(g_errors, 1);
}

static void test_null_and_empty_input_are_ignored(void) {
    reset_state();

    parser_dispatch(client(), NULL, 10);
    parser_dispatch(client(), (const uint8_t *)"", 0);

    CHECK_EQ_INT(g_errors, 0);
}

/* A response carrying the matching request id must be kept for the caller. */
static void test_response_resolves_pending_call(void) {
    reset_state();

    evergram_t *eg = client();
    CHECK(eg != NULL);
    if (eg == NULL) {
        return;
    }

    eg->call.pending = true;
    eg->call.resolved = false;
    eg->call.request_id = 7;
    eg->call.expected_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_LEAVE_CHAT_RESPONSE;
    eg->call.response = NULL;

    Evergram__LeaveChatResponse leave = EVERGRAM__LEAVE_CHAT_RESPONSE__INIT;
    leave.chat_id = "chat-under-test";

    Evergram__ServerMessage message = EVERGRAM__SERVER_MESSAGE__INIT;
    message.request_id = 7;
    message.has_request_id = 1;
    message.payload_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_LEAVE_CHAT_RESPONSE;
    message.leave_chat_response = &leave;

    feed(&message);

    CHECK(eg->call.resolved);
    CHECK(eg->call.response != NULL);
    if (eg->call.response != NULL) {
        CHECK(eg->call.response->leave_chat_response != NULL);
        evergram_call_finish(eg);
    }
    CHECK(!eg->call.pending);
}

static void test_response_with_other_request_id_does_not_resolve(void) {
    reset_state();

    evergram_t *eg = client();
    CHECK(eg != NULL);
    if (eg == NULL) {
        return;
    }

    eg->call.pending = true;
    eg->call.resolved = false;
    eg->call.request_id = 7;
    eg->call.expected_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_LEAVE_CHAT_RESPONSE;
    eg->call.response = NULL;

    Evergram__LeaveChatResponse leave = EVERGRAM__LEAVE_CHAT_RESPONSE__INIT;
    leave.chat_id = "chat-under-test";

    Evergram__ServerMessage message = EVERGRAM__SERVER_MESSAGE__INIT;
    message.request_id = 9; /* someone else's response */
    message.has_request_id = 1;
    message.payload_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_LEAVE_CHAT_RESPONSE;
    message.leave_chat_response = &leave;

    feed(&message);

    CHECK(!eg->call.resolved);
    CHECK(eg->call.response == NULL);

    evergram_call_finish(eg);
}

/* A ChatInfo must also populate the local chat store, not just the key ring. */
static void test_chat_info_populates_chat_store(void) {
    reset_state();

    evergram_t *eg = vector_client();
    CHECK(eg != NULL);
    if (eg == NULL) {
        return;
    }
    CHECK(evergram_chat_get(eg, TEST_CHAT_ID) == NULL);

    build_sealed_chat_info();
    Evergram__CreateChatResponse response = EVERGRAM__CREATE_CHAT_RESPONSE__INIT;
    response.chat = &g_chat;

    Evergram__ServerMessage message = EVERGRAM__SERVER_MESSAGE__INIT;
    message.payload_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_CREATE_CHAT_RESPONSE;
    message.create_chat_response = &response;
    feed_to(eg, &message);

    const evergram_chat_info_t *chat = evergram_chat_get(eg, TEST_CHAT_ID);
    CHECK(chat != NULL);
    if (chat != NULL) {
        CHECK_EQ_STR(chat->chat_id, TEST_CHAT_ID);
        CHECK_EQ_STR(chat->type, EVERGRAM_CHAT_TYPE_ONE_ON_ONE);
    }
    CHECK_EQ_INT(evergram_chat_count(eg), 1);
    CHECK(evergram_has_chat_key(eg, TEST_CHAT_ID));

    evergram_destroy(eg);
}

static void test_presence_push_reaches_callback(void) {
    reset_state();

    Evergram__AccountPresence presence = EVERGRAM__ACCOUNT_PRESENCE__INIT;
    presence.identity_key = "1:rAlice";
    presence.has_status = 1;
    presence.status = EVERGRAM__ACCOUNT_PRESENCE__STATUS__ONLINE;
    presence.has_ts = 1;
    presence.ts = 1700000004000;

    Evergram__ServerMessage message = EVERGRAM__SERVER_MESSAGE__INIT;
    message.payload_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_ACCOUNT_PRESENCE;
    message.account_presence = &presence;

    feed(&message);

    CHECK_EQ_INT(g_presence_events, 1);
    CHECK(g_last_presence_online);
    CHECK_EQ_STR(g_last_presence_identity, "1:rAlice");
}

static void test_profile_updated_push_reaches_callback(void) {
    reset_state();

    Evergram__ChainIdentity identity = EVERGRAM__CHAIN_IDENTITY__INIT;
    identity.has_chain_family = 1;
    identity.chain_family = EVERGRAM__CHAIN_FAMILY__XRPL;
    identity.address = "rAlice";

    Evergram__Profile profile = EVERGRAM__PROFILE__INIT;
    profile.identity = &identity;
    profile.nickname = "Alice";

    Evergram__ProfileUpdatedEvent event = EVERGRAM__PROFILE_UPDATED_EVENT__INIT;
    event.profile = &profile;

    Evergram__ServerMessage message = EVERGRAM__SERVER_MESSAGE__INIT;
    message.payload_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_PROFILE_UPDATED;
    message.profile_updated = &event;

    feed(&message);

    CHECK_EQ_INT(g_profile_updates, 1);
    CHECK_EQ_STR(g_last_profile_nickname, "Alice");
    CHECK_EQ_STR(g_last_profile_identity, "1:rAlice");
}

static void test_join_requested_event_reaches_callback(void) {
    reset_state();

    Evergram__JoinRequestedEvent event = EVERGRAM__JOIN_REQUESTED_EVENT__INIT;
    event.chat_id = "group-1";
    event.identity = "1:rCarol";
    event.name = "My Group";
    event.has_ts = 1;
    event.ts = 1700000003000;

    Evergram__ServerMessage message = EVERGRAM__SERVER_MESSAGE__INIT;
    message.payload_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_JOIN_REQUESTED_EVENT;
    message.join_requested_event = &event;

    feed(&message);

    CHECK_EQ_INT(g_join_requests, 1);
    CHECK_EQ_STR(g_join_chat, "group-1");
    CHECK_EQ_STR(g_join_identity, "1:rCarol");
}

/* Regression: proto2 optionals need their presence flag or they are dropped. */
static void test_request_id_is_serialized(void) {
    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    evergram_set_request_id(&message, 42);

    Evergram__QueryChats query;
    evergram__query_chats__init(&query);
    query.cursor = "";
    message.query_chats = &query;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_QUERY_CHATS;

    size_t size = evergram__client_message__get_packed_size(&message);
    CHECK(size > 0);
    if (size == 0) {
        return;
    }

    uint8_t *packed = malloc(size);
    CHECK(packed != NULL);
    if (packed == NULL) {
        return;
    }
    evergram__client_message__pack(&message, packed);

    Evergram__ClientMessage *decoded = evergram__client_message__unpack(NULL, size, packed);
    CHECK(decoded != NULL);
    if (decoded != NULL) {
        CHECK_EQ_INT(decoded->has_request_id, 1);
        CHECK_EQ_INT(decoded->request_id, 42);
        evergram__client_message__free_unpacked(decoded, NULL);
    }

    free(packed);
}

static const test_case_t TESTS[] = {
    {"parser: TYPING envelope does not crash", test_typing_envelope_does_not_crash},
    {"parser: SEND without key delivers no text", test_send_without_key_delivers_no_text},
    {"parser: chat key from ChatInfo decrypts SEND", test_chat_info_makes_send_decrypt},
    {"parser: REACT decrypts the emoji", test_reaction_decrypts_emoji},
    {"parser: EDIT reports the new text", test_edit_envelope_reports_edited},
    {"parser: EDIT removed reports deletion", test_edit_removed_reports_deleted},
    {"parser: envelope without content ignored", test_envelope_without_content_is_ignored},
    {"parser: envelope without chat ignored", test_envelope_without_chat_is_ignored},
    {"parser: garbage reports protocol error", test_garbage_reports_protocol_error},
    {"parser: null and empty input ignored", test_null_and_empty_input_are_ignored},
    {"parser: response resolves the pending call", test_response_resolves_pending_call},
    {"parser: foreign request id does not resolve", test_response_with_other_request_id_does_not_resolve},
    {"parser: ChatInfo populates the chat store", test_chat_info_populates_chat_store},
    {"parser: request id survives packing", test_request_id_is_serialized},
    {"parser: join requested event reaches callback", test_join_requested_event_reaches_callback},
    {"parser: presence push reaches callback", test_presence_push_reaches_callback},
    {"parser: profile updated push reaches callback", test_profile_updated_push_reaches_callback},
};

const test_case_t *parser_tests(size_t *count) {
    *count = sizeof(TESTS) / sizeof(TESTS[0]);
    return TESTS;
}
