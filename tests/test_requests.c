#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "e2ee_vectors.h"
#include "evergram.h"
#include "evergram.pb-c.h"
#include "internal.h"
#include "test.h"

/*
 * Chat requests, group invites and chat-sync parity.
 *
 * A request or invite can arrive live or be replayed by the boot sync, and the
 * client must report each one exactly once either way — that is what keeps a
 * bot from being asked to decide the same thing on every reconnect. Chat sync
 * also carries the local versions forward so the gateway only sends what
 * changed, and reports chats that no longer exist so their keys are dropped.
 */

#define TEST_URL "wss://gateway.test/ws"
#define TEST_CHAT_ID "chat-1"

static evergram_t *g_client;

static int g_requests;
static evergram_chat_request_t g_request;

static int g_invites;
static evergram_group_invite_t g_invite;

static int g_removed;
static char g_removed_chat[EVERGRAM_CHAT_ID_SIZE];

static void reset_state(void) {
    if (g_client != NULL) {
        evergram_destroy(g_client);
        g_client = NULL;
    }
    g_requests = 0;
    memset(&g_request, 0, sizeof(g_request));
    g_invites = 0;
    memset(&g_invite, 0, sizeof(g_invite));
    g_removed = 0;
    g_removed_chat[0] = '\0';
}

static void on_chat_request(evergram_t *eg, const evergram_chat_request_t *request) {
    (void)eg;
    g_requests++;
    g_request = *request;
}

static void on_group_invite(evergram_t *eg, const evergram_group_invite_t *invite) {
    (void)eg;
    g_invites++;
    g_invite = *invite;
}

static void on_chat_removed(evergram_t *eg, const char *chat_id) {
    (void)eg;
    g_removed++;
    snprintf(g_removed_chat, sizeof(g_removed_chat), "%s", chat_id);
}

static void destroy_client(void) {
    evergram_destroy(g_client);
    g_client = NULL;
}

/* Offline client: no socket is opened until evergram_start(). */
static evergram_t *client(void) {
    if (g_client != NULL) {
        return g_client;
    }

    evergram_wallet_t wallet;
    evergram_device_t device;
    memset(&wallet, 0, sizeof(wallet));
    memset(&device, 0, sizeof(device));
    if (evergram_wallet_generate(&wallet) != EVERGRAM_OK ||
        evergram_device_generate(&device) != EVERGRAM_OK) {
        return NULL;
    }

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
    evergram_on_chat_request(g_client, on_chat_request);
    evergram_on_group_invite(g_client, on_group_invite);
    evergram_on_chat_removed(g_client, on_chat_removed);
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

/* --- builders ------------------------------------------------------------- */

static Evergram__Meta g_meta;

static void fill_meta(const char *name) {
    evergram__meta__init(&g_meta);
    g_meta.name = (char *)name;
}

static void feed_chat_request(void) {
    Evergram__PendingChatRequest request = EVERGRAM__PENDING_CHAT_REQUEST__INIT;
    request.from_identity = (char *)"1:rRequester";
    request.meta = &g_meta;
    request.has_requested_at = 1;
    request.requested_at = 1700000000000;

    Evergram__ChatRequestReceivedEvent event = EVERGRAM__CHAT_REQUEST_RECEIVED_EVENT__INIT;
    event.request = &request;

    Evergram__ServerMessage message = EVERGRAM__SERVER_MESSAGE__INIT;
    message.chat_request_received = &event;
    message.payload_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_CHAT_REQUEST_RECEIVED;
    feed(&message);
}

static void feed_group_invite(void) {
    Evergram__PendingGroupInvite invite = EVERGRAM__PENDING_GROUP_INVITE__INIT;
    invite.chat_id = (char *)TEST_CHAT_ID;
    invite.invited_by = (char *)"1:rInviter";
    invite.meta = &g_meta;
    invite.has_invited_at = 1;
    invite.invited_at = 1700000001000;

    Evergram__GroupInviteReceivedEvent event = EVERGRAM__GROUP_INVITE_RECEIVED_EVENT__INIT;
    event.invite = &invite;

    Evergram__ServerMessage message = EVERGRAM__SERVER_MESSAGE__INIT;
    message.group_invite_received = &event;
    message.payload_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_GROUP_INVITE_RECEIVED;
    feed(&message);
}

/* A sync page carrying the pending lists, as the boot sync does. */
static void feed_sync_with_pending(void) {
    Evergram__PendingChatRequest request = EVERGRAM__PENDING_CHAT_REQUEST__INIT;
    request.from_identity = (char *)"1:rRequester";
    request.meta = &g_meta;
    request.has_requested_at = 1;
    request.requested_at = 1700000000000;
    Evergram__PendingChatRequest *requests[1] = {&request};

    Evergram__PendingGroupInvite invite = EVERGRAM__PENDING_GROUP_INVITE__INIT;
    invite.chat_id = (char *)TEST_CHAT_ID;
    invite.invited_by = (char *)"1:rInviter";
    invite.meta = &g_meta;
    invite.has_invited_at = 1;
    invite.invited_at = 1700000001000;
    Evergram__PendingGroupInvite *invites[1] = {&invite};

    Evergram__QueryChatsResponse response = EVERGRAM__QUERY_CHATS_RESPONSE__INIT;
    response.n_pending_chat_requests = 1;
    response.pending_chat_requests = requests;
    response.n_pending_group_invites = 1;
    response.pending_group_invites = invites;

    Evergram__ServerMessage message = EVERGRAM__SERVER_MESSAGE__INIT;
    message.query_chats_response = &response;
    message.payload_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_QUERY_CHATS_RESPONSE;
    feed(&message);
}

/* --- tests ---------------------------------------------------------------- */

static void test_chat_request_reported_once(void) {
    reset_state();
    fill_meta("Requester Name");

    feed_chat_request();
    CHECK_EQ_INT(g_requests, 1);
    CHECK_EQ_STR(g_request.from_identity, "1:rRequester");
    CHECK_EQ_STR(g_request.nickname, "Requester Name");
    CHECK_EQ_INT((long long)g_request.requested_at_ms, 1700000000000LL);
    CHECK(evergram_chat_request_is_pending(client(), "1:rRequester"));
    CHECK_EQ_INT((long long)evergram_pending_chat_request_count(client()), 1);

    /* The same request arriving again is not a second decision to make. */
    feed_chat_request();
    CHECK_EQ_INT(g_requests, 1);

    CHECK(!evergram_chat_request_is_pending(client(), "1:rSomeoneElse"));
}

static void test_group_invite_reported_once(void) {
    reset_state();
    fill_meta("Group Name");

    feed_group_invite();
    CHECK_EQ_INT(g_invites, 1);
    CHECK_EQ_STR(g_invite.chat_id, TEST_CHAT_ID);
    CHECK_EQ_STR(g_invite.invited_by, "1:rInviter");
    CHECK_EQ_STR(g_invite.name, "Group Name");
    CHECK_EQ_INT((long long)g_invite.invited_at_ms, 1700000001000LL);
    CHECK(evergram_group_invite_is_pending(client(), TEST_CHAT_ID));

    feed_group_invite();
    CHECK_EQ_INT(g_invites, 1);
}

/* The boot sync replays what was already waiting, without repeating anything a
 * live event already reported. */
static void test_boot_sync_replays_pending_requests(void) {
    reset_state();
    fill_meta("Requester Name");

    feed_sync_with_pending();
    CHECK_EQ_INT(g_requests, 1);
    CHECK_EQ_INT(g_invites, 1);
    CHECK_EQ_INT((long long)evergram_pending_chat_request_count(client()), 1);
    CHECK_EQ_INT((long long)evergram_pending_group_invite_count(client()), 1);

    /* A second sync page (or a reconnect) must not ask again. */
    feed_sync_with_pending();
    CHECK_EQ_INT(g_requests, 1);
    CHECK_EQ_INT(g_invites, 1);
}

static void test_missing_chat_is_forgotten(void) {
    reset_state();

    /* Seed a chat with a key, as a normal sync would. */
    Evergram__ChatInfo chat = EVERGRAM__CHAT_INFO__INIT;
    chat.chat_id = (char *)TEST_CHAT_ID;
    chat.type = "one-on-one";
    chat.has_chat_version = 1;
    chat.chat_version = 3;
    chat.has_meta_version = 1;
    chat.meta_version = 7;

    Evergram__ChatSyncResult result = EVERGRAM__CHAT_SYNC_RESULT__INIT;
    result.chat_id = (char *)TEST_CHAT_ID;
    result.has_status = 1;
    result.status = EVERGRAM__CHAT_SYNC_RESULT__STATUS__OUTDATED;
    result.chat = &chat;
    Evergram__ChatSyncResult *results[1] = {&result};

    Evergram__QueryChatsResponse response = EVERGRAM__QUERY_CHATS_RESPONSE__INIT;
    response.n_results = 1;
    response.results = results;

    Evergram__ServerMessage message = EVERGRAM__SERVER_MESSAGE__INIT;
    message.query_chats_response = &response;
    message.payload_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_QUERY_CHATS_RESPONSE;
    feed(&message);

    const evergram_chat_info_t *stored = evergram_chat_get(client(), TEST_CHAT_ID);
    CHECK(stored != NULL);
    if (stored != NULL) {
        CHECK_EQ_INT((long long)stored->chat_version, 3LL);
        CHECK_EQ_INT((long long)stored->meta_version, 7LL);
    }

    /* The same chat reported as MISSING drops it and says so, once. */
    result.status = EVERGRAM__CHAT_SYNC_RESULT__STATUS__MISSING;
    result.chat = NULL;
    feed(&message);

    CHECK_EQ_INT(g_removed, 1);
    CHECK_EQ_STR(g_removed_chat, TEST_CHAT_ID);
    CHECK(evergram_chat_get(client(), TEST_CHAT_ID) == NULL);

    /* An unknown chat going missing is not news. */
    feed(&message);
    CHECK_EQ_INT(g_removed, 1);
}

/* The delta maps are built from the local store, so an up-to-date client asks
 * only for what changed. */
static void test_known_versions_reflect_the_store(void) {
    reset_state();

    evergram_chat_info_t record;
    memset(&record, 0, sizeof(record));
    snprintf(record.chat_id, sizeof(record.chat_id), "%s", TEST_CHAT_ID);
    snprintf(record.type, sizeof(record.type), "group");
    record.chat_version = 11;
    record.meta_version = 4;
    CHECK_EQ_INT(chats_upsert(client()->chats, &record), EVERGRAM_OK);

    Evergram__QueryChats query = EVERGRAM__QUERY_CHATS__INIT;
    evergram_known_versions_t scratch;
    CHECK_EQ_INT(evergram_fill_known_versions(client(), &query, &scratch), EVERGRAM_OK);

    CHECK_EQ_INT((long long)query.n_known_versions, 1);
    CHECK_EQ_INT((long long)query.n_known_meta_versions, 1);
    CHECK(query.known_versions != NULL && query.known_meta_versions != NULL);
    if (query.known_versions != NULL) {
        CHECK_EQ_STR(query.known_versions[0]->key, TEST_CHAT_ID);
        CHECK_EQ_INT((long long)query.known_versions[0]->value, 11LL);
        CHECK_EQ_INT((long long)query.known_meta_versions[0]->value, 4LL);
    }

    /* The maps must survive packing, since that is the whole point. */
    Evergram__ClientMessage message = EVERGRAM__CLIENT_MESSAGE__INIT;
    message.query_chats = &query;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_QUERY_CHATS;
    size_t size = evergram__client_message__get_packed_size(&message);
    CHECK(size > 0);

    uint8_t *packed = malloc(size);
    CHECK(packed != NULL);
    if (packed != NULL) {
        evergram__client_message__pack(&message, packed);
        Evergram__ClientMessage *decoded = evergram__client_message__unpack(NULL, size, packed);
        CHECK(decoded != NULL);
        if (decoded != NULL) {
            CHECK_EQ_INT((long long)decoded->query_chats->n_known_versions, 1);
            CHECK_EQ_STR(decoded->query_chats->known_versions[0]->key, TEST_CHAT_ID);
            CHECK_EQ_INT((long long)decoded->query_chats->known_versions[0]->value, 11LL);
            CHECK_EQ_INT((long long)decoded->query_chats->known_meta_versions[0]->value, 4LL);
            evergram__client_message__free_unpacked(decoded, NULL);
        }
        free(packed);
    }

    /* Disposing releases every array and leaves nothing dangling. */
    const Evergram__QueryChats__KnownVersionsEntry *first = query.known_versions[0];
    CHECK(first != NULL);
    evergram_known_versions_dispose(&scratch);
    CHECK(scratch.versions == NULL);
    CHECK(scratch.meta == NULL);
    CHECK(scratch.version_entries == NULL);
    CHECK(scratch.meta_entries == NULL);

    /* A client that knows no chats asks for everything. */
    reset_state();
    Evergram__QueryChats empty = EVERGRAM__QUERY_CHATS__INIT;
    CHECK_EQ_INT(evergram_fill_known_versions(client(), &empty, &scratch), EVERGRAM_OK);
    CHECK_EQ_INT((long long)empty.n_known_versions, 0);
    CHECK_EQ_INT((long long)empty.n_known_meta_versions, 0);
    CHECK(empty.known_versions == NULL);
    evergram_known_versions_dispose(&scratch);
}

static void test_request_and_invite_call_validation(void) {
    reset_state();

    const evergram_chat_info_t *chat = NULL;
    CHECK_EQ_INT(evergram_chat_request_accept(client(), NULL, 0, &chat),
                 EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(evergram_chat_request_accept(client(), "", 0, &chat), EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(evergram_chat_request_decline(client(), NULL, 0), EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(evergram_group_invite_accept(client(), NULL, 0), EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(evergram_group_invite_decline(client(), "", 0), EVERGRAM_ERR_INVALID_ARG);

    /* Offline, the guard fires before anything is sent. */
    CHECK_EQ_INT(evergram_chat_request_accept(client(), "1:rRequester", 0, &chat),
                 EVERGRAM_ERR_NOT_CONNECTED);
    CHECK_EQ_INT(evergram_group_invite_decline(client(), TEST_CHAT_ID, 0),
                 EVERGRAM_ERR_NOT_CONNECTED);
    CHECK_EQ_INT(evergram_sync_chats_page(client(), ""), EVERGRAM_ERR_NOT_CONNECTED);
    CHECK_EQ_INT(evergram_sync_chats(client()), EVERGRAM_ERR_NOT_CONNECTED);
}

/* --- account access ------------------------------------------------------- */

static int g_restricted;
static evergram_reputation_t g_restriction;

static void on_restricted(evergram_t *eg, const evergram_reputation_t *event) {
    (void)eg;
    g_restricted++;
    g_restriction = *event;
}

static void feed_auth_response(bool ok, const Evergram__AccessInfo *access) {
    Evergram__ResponseStatus status = EVERGRAM__RESPONSE_STATUS__INIT;
    status.has_ok = 1; /* proto2: without this the field never reaches the wire */
    status.ok = ok ? 1 : 0;

    Evergram__AuthResponse response = EVERGRAM__AUTH_RESPONSE__INIT;
    response.status = &status;
    response.access = (Evergram__AccessInfo *)access;

    Evergram__ServerMessage message = EVERGRAM__SERVER_MESSAGE__INIT;
    message.auth_response = &response;
    message.payload_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_AUTH_RESPONSE;
    feed(&message);
}

static void test_access_info_from_authentication(void) {
    reset_state();
    g_restricted = 0;
    memset(&g_restriction, 0, sizeof(g_restriction));
    evergram_on_restricted(client(), on_restricted);

    /* Nothing is known before the first successful authentication. */
    CHECK(evergram_access(client()) == NULL);
    CHECK(!evergram_is_restricted(client()));
    CHECK(!evergram_access_has_capability(client(), "anything"));

    char *capabilities[] = {(char *)"chat.create", (char *)"widget.manage"};
    Evergram__AccessInfo access = EVERGRAM__ACCESS_INFO__INIT;
    access.tier = (char *)"pro";
    access.has_is_admin = 1;
    access.is_admin = 0;
    access.has_is_restricted = 1;
    access.is_restricted = 0;
    access.has_max_devices = 1;
    access.max_devices = 3;
    access.has_joined_at = 1;
    access.joined_at = 1700000000000;
    access.invited_by = (char *)"1:rInviter";
    access.n_capabilities = 2;
    access.capabilities = capabilities;

    feed_auth_response(true, &access);

    const evergram_access_t *stored = evergram_access(client());
    CHECK(stored != NULL);
    if (stored != NULL) {
        CHECK_EQ_STR(stored->tier, "pro");
        CHECK(!stored->is_admin);
        CHECK(!stored->is_restricted);
        CHECK(stored->has_max_devices);
        CHECK_EQ_INT((long long)stored->max_devices, 3LL);
        CHECK_EQ_INT((long long)stored->joined_at_ms, 1700000000000LL);
        CHECK_EQ_STR(stored->invited_by, "1:rInviter");
        CHECK_EQ_INT((long long)stored->capability_count, 2LL);
    }
    CHECK(evergram_access_has_capability(client(), "chat.create"));
    CHECK(evergram_access_has_capability(client(), "widget.manage"));
    CHECK(!evergram_access_has_capability(client(), "chat.creat")); /* exact match only */
    CHECK(!evergram_access_has_capability(client(), NULL));

    /* An account with no device limit reports "absent", not zero. */
    Evergram__AccessInfo unlimited = EVERGRAM__ACCESS_INFO__INIT;
    unlimited.tier = (char *)"admin";
    unlimited.has_is_admin = 1;
    unlimited.is_admin = 1;
    feed_auth_response(true, &unlimited);

    stored = evergram_access(client());
    CHECK(stored != NULL);
    if (stored != NULL) {
        CHECK(stored->is_admin);
        CHECK(!stored->has_max_devices);
        CHECK_EQ_INT((long long)stored->max_devices, 0LL);
        CHECK_EQ_INT((long long)stored->capability_count, 0LL);
    }
}

/* Only the transition into "restricted" is reported, and the flag always
 * tracks the latest push. */
static void test_reputation_restriction(void) {
    reset_state();
    g_restricted = 0;
    memset(&g_restriction, 0, sizeof(g_restriction));
    evergram_on_restricted(client(), on_restricted);

    Evergram__ReputationUpdated update = EVERGRAM__REPUTATION_UPDATED__INIT;
    update.identity = (char *)"1:rSpammer";
    update.has_is_restricted = 1;
    update.is_restricted = 1;
    update.has_score = 1;
    update.score = -12;
    update.reason = (char *)"spam";

    Evergram__ServerMessage message = EVERGRAM__SERVER_MESSAGE__INIT;
    message.reputation_updated = &update;
    message.payload_case = EVERGRAM__SERVER_MESSAGE__PAYLOAD_REPUTATION_UPDATED;
    feed(&message);

    CHECK_EQ_INT(g_restricted, 1);
    CHECK(evergram_is_restricted(client()));
    CHECK_EQ_STR(g_restriction.identity, "1:rSpammer");
    CHECK(g_restriction.is_restricted);
    CHECK(g_restriction.has_score);
    CHECK_EQ_INT(g_restriction.score, -12);
    CHECK_EQ_STR(g_restriction.reason, "spam");

    /* A push that does not change the flag is not news. */
    feed(&message);
    CHECK_EQ_INT(g_restricted, 1);

    /* Lifting it clears the flag without firing the transition callback. */
    update.is_restricted = 0;
    feed(&message);
    CHECK_EQ_INT(g_restricted, 1);
    CHECK(!evergram_is_restricted(client()));
}

static const test_case_t TESTS[] = {
    {"requests: a chat request is reported once", test_chat_request_reported_once},
    {"requests: a group invite is reported once", test_group_invite_reported_once},
    {"requests: the boot sync replays pending requests",
     test_boot_sync_replays_pending_requests},
    {"sync: a missing chat is forgotten", test_missing_chat_is_forgotten},
    {"sync: known versions reflect the store", test_known_versions_reflect_the_store},
    {"requests: call validation", test_request_and_invite_call_validation},
    {"access: information from authentication", test_access_info_from_authentication},
    {"access: reputation restriction", test_reputation_restriction},
};

const test_case_t *request_tests(size_t *count) {
    *count = sizeof(TESTS) / sizeof(TESTS[0]);
    return TESTS;
}
