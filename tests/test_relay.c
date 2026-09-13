#include <sodium.h>
#include <string.h>

#include "e2ee_vectors.h"
#include "relay.h"
#include "test.h"

/* The encrypted vectors come from tweetnacl, so passing these proves the relay
 * frames this client emits and accepts are byte-compatible with the reference
 * implementation, not merely self-consistent. */

static void room_key(uint8_t key[E2EE_KEY_BYTES]) {
    CHECK_EQ_INT(sodium_hex2bin(key, E2EE_KEY_BYTES, VECTOR_ROOM_KEY_HEX, 2u * E2EE_KEY_BYTES,
                                NULL, NULL, NULL),
                 0);
}

static void test_parse_text_frame_from_tweetnacl(void) {
    uint8_t key[E2EE_KEY_BYTES];
    evergram_relay_text_t event;
    room_key(key);

    CHECK_EQ_INT(evergram_relay_parse_text(key, VECTOR_RELAY_TEXT_PAYLOAD, &event), EVERGRAM_OK);
    CHECK_EQ_STR(event.msg_id, VECTOR_RELAY_TEXT_MSG_ID);
    CHECK_EQ_STR(event.sender, VECTOR_RELAY_TEXT_SENDER);
    CHECK_EQ_STR(event.text, VECTOR_RELAY_TEXT_MESSAGE);
    CHECK_EQ_INT((long long)event.timestamp_ms, 1700000000000LL);
}

static void test_parse_react_frames(void) {
    uint8_t key[E2EE_KEY_BYTES];
    evergram_relay_react_t event;
    room_key(key);

    CHECK_EQ_INT(evergram_relay_parse_react(key, VECTOR_RELAY_REACT_PAYLOAD, &event), EVERGRAM_OK);
    CHECK_EQ_STR(event.msg_id, "relay-msg-1");
    CHECK(!event.removed);
    CHECK_EQ_STR(event.emoji, "\xf0\x9f\x8e\xb2"); /* the dice emoji */

    /* emoji: null means the sender cleared their reaction. */
    CHECK_EQ_INT(evergram_relay_parse_react(key, VECTOR_RELAY_REACT_CLEARED_PAYLOAD, &event),
                 EVERGRAM_OK);
    CHECK(event.removed);
    CHECK_EQ_STR(event.emoji, "");
}

static void test_text_roundtrip_and_failures(void) {
    uint8_t key[E2EE_KEY_BYTES];
    room_key(key);

    char payload[EVERGRAM_RELAY_PAYLOAD_MAX];
    evergram_relay_text_t sent;
    CHECK_EQ_INT(evergram_relay_build_text(key, "1:rBot", "quote \" and \\ and \xf0\x9f\x8e\xb2",
                                           payload, sizeof(payload), &sent),
                 EVERGRAM_OK);
    CHECK_EQ_INT(strlen(sent.msg_id), 64); /* 32 random bytes, hex */

    evergram_relay_text_t received;
    CHECK_EQ_INT(evergram_relay_parse_text(key, payload, &received), EVERGRAM_OK);
    CHECK_EQ_STR(received.msg_id, sent.msg_id);
    CHECK_EQ_STR(received.sender, "1:rBot");
    CHECK_EQ_STR(received.text, "quote \" and \\ and \xf0\x9f\x8e\xb2");
    CHECK_EQ_STR(received.timestamp_ms != 0 ? "set" : "unset", "set");

    /* A wrong room key must fail closed. */
    uint8_t other_key[E2EE_KEY_BYTES];
    memset(other_key, 0x5A, sizeof(other_key));
    CHECK_EQ_INT(evergram_relay_parse_text(other_key, payload, &received), EVERGRAM_ERR_CRYPTO);

    /* Tampered ciphertext and malformed envelopes are rejected, not guessed at. */
    payload[30] = (payload[30] == 'A') ? 'B' : 'A';
    CHECK_EQ_INT(evergram_relay_parse_text(key, payload, &received), EVERGRAM_ERR_CRYPTO);
    CHECK_EQ_INT(evergram_relay_parse_text(key, "not json", &received), EVERGRAM_ERR_ENCODING);
    CHECK_EQ_INT(evergram_relay_parse_text(key, "{}", &received), EVERGRAM_ERR_ENCODING);
}

static void test_edit_and_remove_roundtrip(void) {
    uint8_t key[E2EE_KEY_BYTES];
    room_key(key);

    char payload[EVERGRAM_RELAY_PAYLOAD_MAX];
    CHECK_EQ_INT(evergram_relay_build_edit(key, "msg-9", "edited text", payload, sizeof(payload)),
                 EVERGRAM_OK);
    evergram_relay_edit_t edit;
    CHECK_EQ_INT(evergram_relay_parse_edit(key, payload, &edit), EVERGRAM_OK);
    CHECK_EQ_STR(edit.msg_id, "msg-9");
    CHECK_EQ_STR(edit.text, "edited text");
    CHECK(edit.edited_at_ms > 0);

    CHECK_EQ_INT(evergram_relay_build_remove(key, "msg-9", payload, sizeof(payload)),
                 EVERGRAM_OK);
    evergram_relay_remove_t removed;
    CHECK_EQ_INT(evergram_relay_parse_remove(key, payload, &removed), EVERGRAM_OK);
    CHECK_EQ_STR(removed.msg_id, "msg-9");
    CHECK(removed.removed_at_ms > 0);
}

static void test_react_build_roundtrip(void) {
    uint8_t key[E2EE_KEY_BYTES];
    room_key(key);

    char payload[EVERGRAM_RELAY_PAYLOAD_MAX];
    evergram_relay_react_t event;

    CHECK_EQ_INT(evergram_relay_build_react(key, "msg-1", "\xe2\x9c\x85", false, payload,
                                            sizeof(payload)),
                 EVERGRAM_OK);
    CHECK_EQ_INT(evergram_relay_parse_react(key, payload, &event), EVERGRAM_OK);
    CHECK(!event.removed);
    CHECK_EQ_STR(event.emoji, "\xe2\x9c\x85");

    CHECK_EQ_INT(evergram_relay_build_react(key, "msg-1", NULL, true, payload, sizeof(payload)),
                 EVERGRAM_OK);
    CHECK_EQ_INT(evergram_relay_parse_react(key, payload, &event), EVERGRAM_OK);
    CHECK(event.removed);
    CHECK_EQ_STR(event.emoji, "");
}

static void test_typing_is_plaintext(void) {
    char payload[128];
    evergram_relay_typing_t event;

    CHECK_EQ_INT(evergram_relay_build_typing(true, NULL, payload, sizeof(payload)), EVERGRAM_OK);
    CHECK_EQ_STR(payload, "{\"isTyping\":true}");
    CHECK_EQ_INT(evergram_relay_parse_typing(payload, &event), EVERGRAM_OK);
    CHECK(event.is_typing);
    CHECK_EQ_STR(event.sender, "");

    /* public_group carries the sender so peers can attribute the signal. */
    CHECK_EQ_INT(evergram_relay_build_typing(false, "Alice", payload, sizeof(payload)),
                 EVERGRAM_OK);
    CHECK_EQ_INT(evergram_relay_parse_typing(payload, &event), EVERGRAM_OK);
    CHECK(!event.is_typing);
    CHECK_EQ_STR(event.sender, "Alice");

    CHECK_EQ_INT(evergram_relay_parse_typing("{}", &event), EVERGRAM_ERR_ENCODING);
    CHECK_EQ_INT(evergram_relay_parse_typing("nonsense", &event), EVERGRAM_ERR_ENCODING);
}

static void test_presence_is_plaintext(void) {
    char payload[256];
    evergram_relay_presence_t event;

    CHECK_EQ_INT(evergram_relay_build_presence("Alice", NULL, payload, sizeof(payload)),
                 EVERGRAM_OK);
    CHECK_EQ_STR(payload, "{\"sender\":\"Alice\"}");
    CHECK_EQ_INT(evergram_relay_parse_presence(payload, &event), EVERGRAM_OK);
    CHECK_EQ_STR(event.sender, "Alice");
    CHECK(!event.has_previous);

    /* A rename announces the previous name so peers replace, not duplicate. */
    CHECK_EQ_INT(evergram_relay_build_presence("Alice2", "Alice", payload, sizeof(payload)),
                 EVERGRAM_OK);
    CHECK_EQ_INT(evergram_relay_parse_presence(payload, &event), EVERGRAM_OK);
    CHECK_EQ_STR(event.sender, "Alice2");
    CHECK(event.has_previous);
    CHECK_EQ_STR(event.previous_sender, "Alice");

    CHECK_EQ_INT(evergram_relay_parse_presence("{\"sender\":\"\"}", &event), EVERGRAM_ERR_ENCODING);
}

static void test_moderation_state(void) {
    evergram_relay_moderation_t state;

    CHECK_EQ_INT(evergram_relay_parse_moderation(
                     "{\"moderated\":true,\"ops\":[\"Alice\"],\"voiced\":[\"Bob\",\"Carol\"]}",
                     &state),
                 EVERGRAM_OK);
    CHECK(state.moderated);
    CHECK_EQ_INT(state.ops_count, 1);
    CHECK_EQ_STR(state.ops[0], "Alice");
    CHECK_EQ_INT(state.voiced_count, 2);
    CHECK_EQ_STR(state.voiced[1], "Carol");
    evergram_relay_moderation_dispose(&state);

    /* Empty rosters are valid. */
    CHECK_EQ_INT(evergram_relay_parse_moderation("{\"moderated\":false,\"ops\":[],\"voiced\":[]}",
                                                 &state),
                 EVERGRAM_OK);
    CHECK_EQ_INT(state.ops_count, 0);
    CHECK_EQ_INT(state.voiced_count, 0);
    evergram_relay_moderation_dispose(&state);

    /* moderated is mandatory; a missing roster key is tolerated. */
    CHECK_EQ_INT(evergram_relay_parse_moderation("{\"ops\":[]}", &state), EVERGRAM_ERR_ENCODING);
    CHECK_EQ_INT(evergram_relay_parse_moderation("{\"moderated\":true}", &state), EVERGRAM_OK);
    CHECK_EQ_INT(state.ops_count, 0);
    evergram_relay_moderation_dispose(&state);
}

static void test_left_and_kicked(void) {
    uint64_t deadline = 0;
    CHECK_EQ_INT(evergram_relay_parse_left("", &deadline), EVERGRAM_OK);
    CHECK_EQ_INT((long long)deadline, 0);
    CHECK_EQ_INT(evergram_relay_parse_left("{\"deadlineAt\":1700000009000}", &deadline),
                 EVERGRAM_OK);
    CHECK_EQ_INT((long long)deadline, 1700000009000LL);
    /* Unparseable payload means "no deadline known", not an error. */
    CHECK_EQ_INT(evergram_relay_parse_left("garbage", &deadline), EVERGRAM_OK);
    CHECK_EQ_INT((long long)deadline, 0);

    evergram_relay_kicked_t kicked;
    CHECK_EQ_INT(evergram_relay_parse_kicked("", &kicked), EVERGRAM_OK);
    CHECK(!kicked.banned);
    CHECK_EQ_INT(evergram_relay_parse_kicked("{\"reason\":\"banned\"}", &kicked), EVERGRAM_OK);
    CHECK(kicked.banned);
    CHECK_EQ_INT(evergram_relay_parse_kicked("{\"reason\":\"kicked\"}", &kicked), EVERGRAM_OK);
    CHECK(!kicked.banned);
    CHECK_EQ_INT(evergram_relay_parse_kicked("garbage", &kicked), EVERGRAM_OK);
    CHECK(!kicked.banned);
}

static void test_kind_mapping(void) {
    CHECK_EQ_INT(evergram_relay_kind_from_wire(0), EVERGRAM_RELAY_KIND_JOINED);
    CHECK_EQ_INT(evergram_relay_kind_from_wire(1), EVERGRAM_RELAY_KIND_TEXT);
    CHECK_EQ_INT(evergram_relay_kind_from_wire(2), EVERGRAM_RELAY_KIND_LEFT);
    CHECK_EQ_INT(evergram_relay_kind_from_wire(13), EVERGRAM_RELAY_KIND_CHANNEL_MODE);
    CHECK_EQ_INT(evergram_relay_kind_from_wire(14), EVERGRAM_RELAY_KIND_UNKNOWN);
    CHECK_EQ_INT(evergram_relay_kind_from_wire(-1), EVERGRAM_RELAY_KIND_UNKNOWN);

    /* Values are the wire values, so the reverse mapping is the identity. */
    for (int wire = 0; wire <= 13; wire++) {
        evergram_relay_kind_t kind = evergram_relay_kind_from_wire(wire);
        CHECK_EQ_INT(evergram_relay_kind_to_wire(kind), wire);
    }
    CHECK_EQ_INT(evergram_relay_kind_to_wire(EVERGRAM_RELAY_KIND_UNKNOWN), -1);
}

static void test_invalid_arguments(void) {
    uint8_t key[E2EE_KEY_BYTES] = {0};
    char payload[EVERGRAM_RELAY_PAYLOAD_MAX];
    evergram_relay_text_t text;

    CHECK_EQ_INT(evergram_relay_build_text(NULL, "s", "t", payload, sizeof(payload), NULL),
                 EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(evergram_relay_parse_text(NULL, VECTOR_RELAY_TEXT_PAYLOAD, &text),
                 EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(evergram_relay_parse_text(key, NULL, &text), EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(evergram_relay_parse_text(key, VECTOR_RELAY_TEXT_PAYLOAD, NULL),
                 EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(evergram_relay_build_typing(true, NULL, payload, 0),
                 EVERGRAM_ERR_BUFFER_TOO_SMALL);
    CHECK_EQ_INT(evergram_relay_kind_to_wire(EVERGRAM_RELAY_KIND_UNKNOWN), -1);

    evergram_relay_moderation_dispose(NULL);
}

static const test_case_t TESTS[] = {
    {"relay: text frame from tweetnacl", test_parse_text_frame_from_tweetnacl},
    {"relay: react frames from tweetnacl", test_parse_react_frames},
    {"relay: text roundtrip and failures", test_text_roundtrip_and_failures},
    {"relay: edit and remove roundtrip", test_edit_and_remove_roundtrip},
    {"relay: react build roundtrip", test_react_build_roundtrip},
    {"relay: typing is plaintext", test_typing_is_plaintext},
    {"relay: presence is plaintext", test_presence_is_plaintext},
    {"relay: moderation state", test_moderation_state},
    {"relay: left and kicked", test_left_and_kicked},
    {"relay: kind mapping", test_kind_mapping},
    {"relay: invalid arguments", test_invalid_arguments},
};

const test_case_t *relay_tests(size_t *count) {
    *count = sizeof(TESTS) / sizeof(TESTS[0]);
    return TESTS;
}
