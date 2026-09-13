#include "test.h"

#include "evergram.h"

static void test_plain_text_is_text(void) {
    CHECK_EQ_INT(evergram_message_content_type(NULL), EVERGRAM_CONTENT_TEXT);
    CHECK_EQ_INT(evergram_message_content_type(""), EVERGRAM_CONTENT_TEXT);
    CHECK_EQ_INT(evergram_message_content_type("hello there"), EVERGRAM_CONTENT_TEXT);
}

static void test_json_envelopes_are_discriminated(void) {
    CHECK_EQ_INT(evergram_message_content_type("{\"type\":\"text\",\"text\":\"hi\"}"),
                 EVERGRAM_CONTENT_TEXT);
    CHECK_EQ_INT(evergram_message_content_type("{\"type\":\"audio\",\"durationMs\":900}"),
                 EVERGRAM_CONTENT_AUDIO);
    CHECK_EQ_INT(evergram_message_content_type("{\"type\":\"payment_request\",\"amount\":\"10\"}"),
                 EVERGRAM_CONTENT_PAYMENT_REQUEST);
    CHECK_EQ_INT(evergram_message_content_type("{\"type\":\"payment_receipt\",\"txHash\":\"AB\"}"),
                 EVERGRAM_CONTENT_PAYMENT_RECEIPT);
    CHECK_EQ_INT(evergram_message_content_type("{\"type\":\"payment_sent\",\"txHash\":\"AB\"}"),
                 EVERGRAM_CONTENT_PAYMENT_SENT);
}

static void test_whitespace_and_field_order(void) {
    CHECK_EQ_INT(evergram_message_content_type("{ \"type\" : \"audio\" }"),
                 EVERGRAM_CONTENT_AUDIO);
    CHECK_EQ_INT(evergram_message_content_type("{\"durationMs\":10,\"type\":\"audio\"}"),
                 EVERGRAM_CONTENT_AUDIO);
}

static void test_unknown_shapes(void) {
    CHECK_EQ_INT(evergram_message_content_type("{\"type\":\"nonsense\"}"),
                 EVERGRAM_CONTENT_UNKNOWN);
    CHECK_EQ_INT(evergram_message_content_type("{\"other\":\"audio\"}"), EVERGRAM_CONTENT_UNKNOWN);
    CHECK_EQ_INT(evergram_message_content_type("{not json"), EVERGRAM_CONTENT_UNKNOWN);
    CHECK_EQ_INT(evergram_message_content_type("{\"type\":42}"), EVERGRAM_CONTENT_UNKNOWN);
}

/* --- structured parsing and builders --------------------------------------- */

static void test_payment_request_round_trip(void) {
    evergram_payment_request_t sent;
    memset(&sent, 0, sizeof(sent));
    CHECK_EQ_INT(evergram_new_request_id(sent.request_id, sizeof(sent.request_id)), EVERGRAM_OK);
    CHECK_EQ_INT((long long)strlen(sent.request_id), 36LL);
    snprintf(sent.amount, sizeof(sent.amount), "10.5");
    snprintf(sent.currency, sizeof(sent.currency), "XAH");
    snprintf(sent.currency_id, sizeof(sent.currency_id), "EVR_XAHAU");
    sent.has_note = true;
    snprintf(sent.note, sizeof(sent.note), "for the group");
    snprintf(sent.to, sizeof(sent.to), "rRequesterAddress");
    snprintf(sent.to_identity_key, sizeof(sent.to_identity_key), "1:rRequesterAddress");

    char payload[EVERGRAM_PAYMENT_CONTENT_SIZE];
    CHECK_EQ_INT(evergram_payment_request_build(&sent, payload, sizeof(payload)), EVERGRAM_OK);
    CHECK_EQ_INT(evergram_message_content_type(payload), EVERGRAM_CONTENT_PAYMENT_REQUEST);

    evergram_content_t parsed;
    CHECK_EQ_INT(evergram_message_content_parse(payload, &parsed), EVERGRAM_OK);
    CHECK_EQ_INT(parsed.type, EVERGRAM_CONTENT_PAYMENT_REQUEST);
    CHECK_EQ_STR(parsed.payment_request.request_id, sent.request_id);
    CHECK_EQ_STR(parsed.payment_request.amount, "10.5");
    CHECK_EQ_STR(parsed.payment_request.currency, "XAH");
    CHECK_EQ_STR(parsed.payment_request.currency_id, "EVR_XAHAU");
    CHECK(parsed.payment_request.has_note);
    CHECK_EQ_STR(parsed.payment_request.note, "for the group");
    CHECK_EQ_STR(parsed.payment_request.to, "rRequesterAddress");
    CHECK_EQ_STR(parsed.payment_request.to_identity_key, "1:rRequesterAddress");
    CHECK(parsed.raw == payload); /* borrowed, never copied */

    /* An omitted note is reported as absent, not as an empty note. */
    sent.has_note = false;
    CHECK_EQ_INT(evergram_payment_request_build(&sent, payload, sizeof(payload)), EVERGRAM_OK);
    CHECK_EQ_INT(evergram_message_content_parse(payload, &parsed), EVERGRAM_OK);
    CHECK(!parsed.payment_request.has_note);
    CHECK_EQ_STR(parsed.payment_request.note, "");
}

/* The reference SDK tolerates a receipt without a currencyId (legacy senders). */
static void test_receipt_defaults_and_fields(void) {
    const char *legacy =
        "{\"type\":\"payment_receipt\",\"requestId\":\"abc\",\"txHash\":\"DEADBEEF\","
        "\"amount\":\"5\",\"currency\":\"XAH\",\"from\":\"rPayer\","
        "\"fromIdentityKey\":\"1:rPayer\"}";

    evergram_content_t parsed;
    CHECK_EQ_INT(evergram_message_content_parse(legacy, &parsed), EVERGRAM_OK);
    CHECK_EQ_INT(parsed.type, EVERGRAM_CONTENT_PAYMENT_RECEIPT);
    CHECK_EQ_STR(parsed.payment_receipt.request_id, "abc");
    CHECK_EQ_STR(parsed.payment_receipt.tx_hash, "DEADBEEF");
    CHECK_EQ_STR(parsed.payment_receipt.amount, "5");
    CHECK_EQ_STR(parsed.payment_receipt.currency, "XAH");
    CHECK_EQ_STR(parsed.payment_receipt.currency_id, "XAH");
    CHECK_EQ_STR(parsed.payment_receipt.from, "rPayer");
    CHECK_EQ_STR(parsed.payment_receipt.from_identity_key, "1:rPayer");

    evergram_payment_receipt_t receipt;
    memset(&receipt, 0, sizeof(receipt));
    snprintf(receipt.request_id, sizeof(receipt.request_id), "%s", "abc");
    snprintf(receipt.tx_hash, sizeof(receipt.tx_hash), "%s", "DEADBEEF");
    snprintf(receipt.amount, sizeof(receipt.amount), "5");
    snprintf(receipt.currency, sizeof(receipt.currency), "XAH");
    snprintf(receipt.from, sizeof(receipt.from), "rPayer");
    snprintf(receipt.from_identity_key, sizeof(receipt.from_identity_key), "1:rPayer");

    char built[EVERGRAM_PAYMENT_CONTENT_SIZE];
    CHECK_EQ_INT(evergram_payment_receipt_build(&receipt, built, sizeof(built)), EVERGRAM_OK);
    CHECK_EQ_INT(evergram_message_content_parse(built, &parsed), EVERGRAM_OK);
    CHECK_EQ_STR(parsed.payment_receipt.request_id, "abc");
    CHECK_EQ_STR(parsed.payment_receipt.tx_hash, "DEADBEEF");
    CHECK_EQ_STR(parsed.payment_receipt.currency_id, "XAH"); /* defaulted, not empty */
}

static void test_payment_sent_round_trip(void) {
    evergram_payment_sent_t sent;
    memset(&sent, 0, sizeof(sent));
    snprintf(sent.id, sizeof(sent.id), "%s", "11111111-2222-4333-8444-555555555555");
    snprintf(sent.tx_hash, sizeof(sent.tx_hash), "%s", "HASH");
    snprintf(sent.amount, sizeof(sent.amount), "%s", "1.25");
    snprintf(sent.currency, sizeof(sent.currency), "%s", "XRP");
    snprintf(sent.currency_id, sizeof(sent.currency_id), "%s", "XRP");
    snprintf(sent.from, sizeof(sent.from), "%s", "rFrom");
    snprintf(sent.from_identity_key, sizeof(sent.from_identity_key), "%s", "1:rFrom");
    snprintf(sent.to, sizeof(sent.to), "%s", "rTo");
    snprintf(sent.to_identity_key, sizeof(sent.to_identity_key), "%s", "1:rTo");

    char built[EVERGRAM_PAYMENT_CONTENT_SIZE];
    CHECK_EQ_INT(evergram_payment_sent_build(&sent, built, sizeof(built)), EVERGRAM_OK);

    evergram_content_t parsed;
    CHECK_EQ_INT(evergram_message_content_parse(built, &parsed), EVERGRAM_OK);
    CHECK_EQ_INT(parsed.type, EVERGRAM_CONTENT_PAYMENT_SENT);
    CHECK_EQ_STR(parsed.payment_sent.id, sent.id);
    CHECK_EQ_STR(parsed.payment_sent.tx_hash, "HASH");
    CHECK_EQ_STR(parsed.payment_sent.to_identity_key, "1:rTo");
    CHECK_EQ_STR(parsed.payment_sent.from_identity_key, "1:rFrom");
    CHECK(!parsed.payment_sent.has_note);
}

static void test_audio_metadata_and_payload(void) {
    char payload[2048];
    CHECK_EQ_INT(evergram_audio_message_build("audio/ogg", 1500, "AAECAwQ=", payload,
                                              sizeof(payload)),
                 EVERGRAM_OK);

    evergram_content_t parsed;
    CHECK_EQ_INT(evergram_message_content_parse(payload, &parsed), EVERGRAM_OK);
    CHECK_EQ_INT(parsed.type, EVERGRAM_CONTENT_AUDIO);
    CHECK_EQ_STR(parsed.audio.mime_type, "audio/ogg");
    CHECK_EQ_INT((long long)parsed.audio.duration_ms, 1500LL);
    /* "AAECAwQ=" is 8 base64 chars, but the '=' means 5 bytes, not 6. */
    CHECK_EQ_INT((long long)parsed.audio.size, 5LL);
    CHECK(parsed.audio.payload_b64 != NULL);
    if (parsed.audio.payload_b64 != NULL) {
        CHECK_EQ_INT(strncmp(parsed.audio.payload_b64, "AAECAwQ=", 8), 0);
    }
}

static void test_parse_validation_and_failures(void) {
    evergram_content_t parsed;

    /* Plain text is borrowed verbatim. */
    CHECK_EQ_INT(evergram_message_content_parse("just words", &parsed), EVERGRAM_OK);
    CHECK_EQ_INT(parsed.type, EVERGRAM_CONTENT_TEXT);
    CHECK_EQ_STR(parsed.text, "just words");

    /* NULL is an empty text body, not an error. */
    CHECK_EQ_INT(evergram_message_content_parse(NULL, &parsed), EVERGRAM_OK);
    CHECK_EQ_INT(parsed.type, EVERGRAM_CONTENT_TEXT);
    CHECK_EQ_STR(parsed.text, "");

    CHECK_EQ_INT(evergram_message_content_parse("{}", NULL), EVERGRAM_ERR_INVALID_ARG);

    /* A body that cannot be read is text, exactly as the reference SDK decides —
     * never a half-parsed receipt that a paywall could act on. */
    CHECK_EQ_INT(evergram_message_content_parse("{\"type\":\"payment_receipt\",broken",
                                                &parsed),
                 EVERGRAM_OK);
    CHECK_EQ_INT(parsed.type, EVERGRAM_CONTENT_TEXT);
    CHECK(parsed.text != NULL);

    /* An unrecognized envelope keeps that distinction, and still offers text. */
    CHECK_EQ_INT(evergram_message_content_parse("{\"type\":\"nonsense\"}", &parsed),
                 EVERGRAM_OK);
    CHECK_EQ_INT(parsed.type, EVERGRAM_CONTENT_UNKNOWN);
    CHECK_EQ_STR(parsed.text, "{\"type\":\"nonsense\"}");

    char small[8];
    evergram_payment_request_t request;
    memset(&request, 0, sizeof(request));
    CHECK_EQ_INT(evergram_new_request_id(request.request_id, sizeof(request.request_id)),
                 EVERGRAM_OK);
    snprintf(request.amount, sizeof(request.amount), "%s", "1");
    snprintf(request.currency, sizeof(request.currency), "%s", "XAH");
    /* A buffer that cannot hold the envelope fails instead of truncating into
     * an unparseable message. */
    CHECK_EQ_INT(evergram_payment_request_build(&request, small, sizeof(small)),
                 EVERGRAM_ERR_BUFFER_TOO_SMALL);
    CHECK_EQ_INT(small[0], '\0');
    CHECK_EQ_INT(evergram_payment_request_build(NULL, small, sizeof(small)),
                 EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(evergram_new_request_id(NULL, 0), EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(evergram_new_request_id(request.request_id, 4), EVERGRAM_ERR_INVALID_ARG);
}

/* Two ids must never collide, and the version/variant nibbles must be the ones
 * a UUID v4 promises (the reference SDK's randomUUID contract). */
static void test_request_ids_are_unique_uuids(void) {
    char first[EVERGRAM_REQUEST_ID_SIZE];
    char second[EVERGRAM_REQUEST_ID_SIZE];
    CHECK_EQ_INT(evergram_new_request_id(first, sizeof(first)), EVERGRAM_OK);
    CHECK_EQ_INT(evergram_new_request_id(second, sizeof(second)), EVERGRAM_OK);
    CHECK(strcmp(first, second) != 0);
    CHECK_EQ_INT(first[8], '-');
    CHECK_EQ_INT(first[13], '-');
    CHECK_EQ_INT(first[18], '-');
    CHECK_EQ_INT(first[23], '-');
    CHECK_EQ_INT(first[14], '4'); /* version 4 */
    CHECK(first[19] == '8' || first[19] == '9' || first[19] == 'a' || first[19] == 'b');
}

static const test_case_t TESTS[] = {
    {"content: plain text", test_plain_text_is_text},
    {"content: json envelopes", test_json_envelopes_are_discriminated},
    {"content: whitespace and field order", test_whitespace_and_field_order},
    {"content: unknown shapes", test_unknown_shapes},
    {"content: payment request round trip", test_payment_request_round_trip},
    {"content: receipt fields and legacy default", test_receipt_defaults_and_fields},
    {"content: payment sent round trip", test_payment_sent_round_trip},
    {"content: audio metadata and payload", test_audio_metadata_and_payload},
    {"content: validation and unreadable bodies", test_parse_validation_and_failures},
    {"content: request ids are unique UUIDs", test_request_ids_are_unique_uuids},
};

const test_case_t *content_tests(size_t *count) {
    *count = sizeof(TESTS) / sizeof(TESTS[0]);
    return TESTS;
}
