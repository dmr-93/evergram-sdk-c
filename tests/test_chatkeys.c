#include <string.h>

#include "chatkeys.h"
#include "test.h"

static void fill(uint8_t key[E2EE_KEY_BYTES], uint8_t value) {
    memset(key, value, E2EE_KEY_BYTES);
}

static void test_set_and_get(void) {
    chatkeys_t *keys = chatkeys_create();
    CHECK(keys != NULL);

    uint8_t key[E2EE_KEY_BYTES];
    fill(key, 0x11);
    CHECK_EQ_INT(chatkeys_set(keys, "chat-a", key), EVERGRAM_OK);

    CHECK(chatkeys_has(keys, "chat-a"));
    CHECK(!chatkeys_has(keys, "chat-b"));
    CHECK(chatkeys_get(keys, "chat-b") == NULL);
    CHECK_EQ_INT(chatkeys_count(keys), 1);

    const uint8_t *found = chatkeys_get(keys, "chat-a");
    CHECK(found != NULL);
    if (found != NULL) {
        CHECK_EQ_INT(memcmp(found, key, E2EE_KEY_BYTES), 0);
    }

    chatkeys_destroy(keys);
}

static void test_set_replaces_existing(void) {
    chatkeys_t *keys = chatkeys_create();
    CHECK(keys != NULL);

    uint8_t first[E2EE_KEY_BYTES];
    uint8_t second[E2EE_KEY_BYTES];
    fill(first, 0x22);
    fill(second, 0x33);

    CHECK_EQ_INT(chatkeys_set(keys, "chat-a", first), EVERGRAM_OK);
    CHECK_EQ_INT(chatkeys_set(keys, "chat-a", second), EVERGRAM_OK);
    CHECK_EQ_INT(chatkeys_count(keys), 1);

    const uint8_t *found = chatkeys_get(keys, "chat-a");
    CHECK(found != NULL);
    if (found != NULL) {
        CHECK_EQ_INT(memcmp(found, second, E2EE_KEY_BYTES), 0);
    }

    chatkeys_destroy(keys);
}

static void test_remove_keeps_others(void) {
    chatkeys_t *keys = chatkeys_create();
    CHECK(keys != NULL);

    uint8_t key[E2EE_KEY_BYTES];
    fill(key, 0x44);
    CHECK_EQ_INT(chatkeys_set(keys, "one", key), EVERGRAM_OK);
    CHECK_EQ_INT(chatkeys_set(keys, "two", key), EVERGRAM_OK);
    CHECK_EQ_INT(chatkeys_set(keys, "three", key), EVERGRAM_OK);

    chatkeys_remove(keys, "two");
    CHECK_EQ_INT(chatkeys_count(keys), 2);
    CHECK(!chatkeys_has(keys, "two"));
    CHECK(chatkeys_has(keys, "one"));
    CHECK(chatkeys_has(keys, "three"));

    chatkeys_remove(keys, "absent");
    CHECK_EQ_INT(chatkeys_count(keys), 2);

    chatkeys_destroy(keys);
}

static void test_grows_beyond_initial_capacity(void) {
    enum { COUNT = 100 };
    chatkeys_t *keys = chatkeys_create();
    CHECK(keys != NULL);

    for (int i = 0; i < COUNT; i++) {
        char chat_id[32];
        snprintf(chat_id, sizeof(chat_id), "chat-%d", i);
        uint8_t key[E2EE_KEY_BYTES];
        fill(key, (uint8_t)i);
        CHECK_EQ_INT(chatkeys_set(keys, chat_id, key), EVERGRAM_OK);
    }
    CHECK_EQ_INT(chatkeys_count(keys), COUNT);

    for (int i = 0; i < COUNT; i++) {
        char chat_id[32];
        snprintf(chat_id, sizeof(chat_id), "chat-%d", i);
        const uint8_t *found = chatkeys_get(keys, chat_id);
        CHECK(found != NULL);
        if (found != NULL) {
            CHECK_EQ_INT(found[0], (uint8_t)i);
        }
    }

    chatkeys_destroy(keys);
}

static void test_invalid_arguments(void) {
    uint8_t key[E2EE_KEY_BYTES] = {0};
    chatkeys_t *keys = chatkeys_create();
    CHECK(keys != NULL);

    CHECK_EQ_INT(chatkeys_set(NULL, "a", key), EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(chatkeys_set(keys, NULL, key), EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(chatkeys_set(keys, "", key), EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(chatkeys_set(keys, "a", NULL), EVERGRAM_ERR_INVALID_ARG);

    chatkeys_destroy(keys);

    /* NULL-safe teardown and queries */
    chatkeys_destroy(NULL);
    CHECK(chatkeys_get(NULL, "a") == NULL);
    CHECK(!chatkeys_has(NULL, "a"));
    CHECK_EQ_INT(chatkeys_count(NULL), 0);
    chatkeys_remove(NULL, "a");
}

static const test_case_t TESTS[] = {
    {"chatkeys: set and get", test_set_and_get},
    {"chatkeys: set replaces existing", test_set_replaces_existing},
    {"chatkeys: remove keeps others", test_remove_keeps_others},
    {"chatkeys: grows beyond initial capacity", test_grows_beyond_initial_capacity},
    {"chatkeys: invalid arguments and NULL safety", test_invalid_arguments},
};

const test_case_t *chatkeys_tests(size_t *count) {
    *count = sizeof(TESTS) / sizeof(TESTS[0]);
    return TESTS;
}
