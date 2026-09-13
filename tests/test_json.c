#include <string.h>

#include "json.h"
#include "test.h"

static void test_parse_flat_fields(void) {
    json_object_t object;
    CHECK_EQ_INT(json_parse_flat("{\"msgId\":\"abc\",\"ts\":1700000000000,\"isTyping\":true}",
                                 &object),
                 EVERGRAM_OK);
    CHECK_EQ_INT(object.count, 3);
    CHECK_EQ_STR(json_get_string(&object, "msgId"), "abc");

    double ts = 0;
    CHECK(json_get_number(&object, "ts", &ts));
    CHECK_EQ_INT((long long)ts, 1700000000000LL);

    bool typing = false;
    CHECK(json_get_bool(&object, "isTyping", &typing));
    CHECK(typing);

    CHECK(json_get_string(&object, "absent") == NULL);
    CHECK(!json_get_bool(&object, "msgId", NULL));
    json_object_dispose(&object);
}

static void test_empty_object_and_whitespace(void) {
    json_object_t object;
    CHECK_EQ_INT(json_parse_flat("{}", &object), EVERGRAM_OK);
    CHECK_EQ_INT(object.count, 0);
    json_object_dispose(&object);

    CHECK_EQ_INT(json_parse_flat("  {  \"a\" : \"b\"  }  ", &object), EVERGRAM_OK);
    CHECK_EQ_STR(json_get_string(&object, "a"), "b");
    json_object_dispose(&object);
}

static void test_escapes_are_decoded(void) {
    json_object_t object;

    /* Quote, backslash, newline and tab. */
    CHECK_EQ_INT(json_parse_flat("{\"t\":\"a\\\"b\\\\c\\nd\\te\"}", &object), EVERGRAM_OK);
    CHECK_EQ_STR(json_get_string(&object, "t"), "a\"b\\c\nd\te");
    json_object_dispose(&object);

    /* \u00e9 is "é" in UTF-8 (0xC3 0xA9). */
    CHECK_EQ_INT(json_parse_flat("{\"t\":\"caf\\u00e9\"}", &object), EVERGRAM_OK);
    CHECK_EQ_STR(json_get_string(&object, "t"), "caf\xc3\xa9");
    json_object_dispose(&object);

    /* Surrogate pair for U+1F3B2 (dice), the emoji the trivia bot sends. */
    CHECK_EQ_INT(json_parse_flat("{\"t\":\"\\ud83c\\udfb2\"}", &object), EVERGRAM_OK);
    CHECK_EQ_STR(json_get_string(&object, "t"), "\xf0\x9f\x8e\xb2");
    json_object_dispose(&object);
}

static void test_null_and_absent_are_both_absent(void) {
    json_object_t object;
    CHECK_EQ_INT(json_parse_flat("{\"emoji\":null}", &object), EVERGRAM_OK);
    CHECK_EQ_INT(object.count, 1);
    CHECK(json_get_string(&object, "emoji") == NULL);
    json_object_dispose(&object);
}

static void test_malformed_input_is_rejected(void) {
    json_object_t object;

    CHECK_EQ_INT(json_parse_flat("", &object), EVERGRAM_ERR_ENCODING);
    CHECK_EQ_INT(json_parse_flat("nope", &object), EVERGRAM_ERR_ENCODING);
    CHECK_EQ_INT(json_parse_flat("{\"a\":}", &object), EVERGRAM_ERR_ENCODING);
    CHECK_EQ_INT(json_parse_flat("{\"a\":\"b\"", &object), EVERGRAM_ERR_ENCODING);
    CHECK_EQ_INT(json_parse_flat("{\"a\" \"b\"}", &object), EVERGRAM_ERR_ENCODING);
    CHECK_EQ_INT(json_parse_flat("{\"a\":\"b\"}trailing", &object), EVERGRAM_ERR_ENCODING);
    CHECK_EQ_INT(json_parse_flat("{\"a\":\"unterminated}", &object), EVERGRAM_ERR_ENCODING);
    CHECK_EQ_INT(json_parse_flat("{\"a\":{\"nested\":1}}", &object), EVERGRAM_ERR_ENCODING);
    CHECK_EQ_INT(json_parse_flat("{\"a\":[1,2]}", &object), EVERGRAM_ERR_ENCODING);
    CHECK_EQ_INT(json_parse_flat(NULL, &object), EVERGRAM_ERR_INVALID_ARG);
}

static void test_too_many_fields_is_rejected(void) {
    char text[1024];
    size_t written = 0;
    written += (size_t)snprintf(text + written, sizeof(text) - written, "{");

    for (size_t i = 0; i < JSON_MAX_FIELDS + 1u; i++) {
        written += (size_t)snprintf(text + written, sizeof(text) - written, "%s\"k%zu\":1",
                                    i == 0 ? "" : ",", i);
    }
    snprintf(text + written, sizeof(text) - written, "}");

    json_object_t object;
    CHECK_EQ_INT(json_parse_flat(text, &object), EVERGRAM_ERR_ENCODING);
}

static void test_writer_roundtrip(void) {
    char buffer[512];
    json_writer_t writer;
    json_writer_init(&writer, buffer, sizeof(buffer));

    json_writer_begin_object(&writer);
    json_writer_field_string(&writer, "msgId", "abc");
    json_writer_field_string(&writer, "sender", "1:rAlice");
    json_writer_field_string(&writer, "text", "Echo: hi");
    json_writer_field_number(&writer, "ts", 1700000000000.0);
    json_writer_end_object(&writer);
    CHECK(json_writer_ok(&writer));

    json_object_t object;
    CHECK_EQ_INT(json_parse_flat(buffer, &object), EVERGRAM_OK);
    CHECK_EQ_STR(json_get_string(&object, "msgId"), "abc");
    CHECK_EQ_STR(json_get_string(&object, "sender"), "1:rAlice");
    CHECK_EQ_STR(json_get_string(&object, "text"), "Echo: hi");

    double ts = 0;
    CHECK(json_get_number(&object, "ts", &ts));
    CHECK_EQ_INT((long long)ts, 1700000000000LL);
    json_object_dispose(&object);
}

static void test_writer_escapes_and_unicode(void) {
    char buffer[512];
    json_writer_t writer;
    json_writer_init(&writer, buffer, sizeof(buffer));

    json_writer_begin_object(&writer);
    /* Quotes, backslash, newline, tab and an emoji must survive the round trip. */
    json_writer_field_string(&writer, "text", "say \"hi\"\\now\nnew\tline \xf0\x9f\x8e\xb2");
    json_writer_field_bool(&writer, "removed", false);
    json_writer_end_object(&writer);
    CHECK(json_writer_ok(&writer));

    json_object_t object;
    CHECK_EQ_INT(json_parse_flat(buffer, &object), EVERGRAM_OK);
    CHECK_EQ_STR(json_get_string(&object, "text"), "say \"hi\"\\now\nnew\tline \xf0\x9f\x8e\xb2");

    bool removed = true;
    CHECK(json_get_bool(&object, "removed", &removed));
    CHECK(!removed);
    json_object_dispose(&object);
}

static void test_writer_reports_overflow(void) {
    char small[16];
    json_writer_t writer;
    json_writer_init(&writer, small, sizeof(small));

    json_writer_begin_object(&writer);
    json_writer_field_string(&writer, "text", "a value that cannot possibly fit");
    json_writer_end_object(&writer);

    CHECK(!json_writer_ok(&writer));
    /* The buffer stays terminated rather than overrun. */
    CHECK(small[sizeof(small) - 1u] == '\0');
}

static void test_writer_control_characters_are_escaped(void) {
    char buffer[64];
    json_writer_t writer;
    json_writer_init(&writer, buffer, sizeof(buffer));

    json_writer_begin_object(&writer);
    json_writer_field_string(&writer, "t", "a\x01z");
    json_writer_end_object(&writer);
    CHECK(json_writer_ok(&writer));
    CHECK_EQ_STR(buffer, "{\"t\":\"a\\u0001z\"}");

    json_object_t object;
    CHECK_EQ_INT(json_parse_flat(buffer, &object), EVERGRAM_OK);
    CHECK_EQ_STR(json_get_string(&object, "t"), "a\x01z");
    json_object_dispose(&object);
}

static const test_case_t TESTS[] = {
    {"json: flat fields", test_parse_flat_fields},
    {"json: empty object and whitespace", test_empty_object_and_whitespace},
    {"json: escapes are decoded", test_escapes_are_decoded},
    {"json: null is absent", test_null_and_absent_are_both_absent},
    {"json: malformed input rejected", test_malformed_input_is_rejected},
    {"json: too many fields rejected", test_too_many_fields_is_rejected},
    {"json: writer round trip", test_writer_roundtrip},
    {"json: writer escapes and unicode", test_writer_escapes_and_unicode},
    {"json: writer reports overflow", test_writer_reports_overflow},
    {"json: control characters escaped", test_writer_control_characters_are_escaped},
};

const test_case_t *json_tests(size_t *count) {
    *count = sizeof(TESTS) / sizeof(TESTS[0]);
    return TESTS;
}
