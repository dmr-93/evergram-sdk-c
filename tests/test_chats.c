#include <stdio.h>
#include <string.h>

#include "chats.h"
#include "test.h"

static void fill_record(evergram_chat_info_t *record, const char *chat_id, const char *type,
                        const char *const *participants, size_t count) {
    memset(record, 0, sizeof(*record));
    snprintf(record->chat_id, sizeof(record->chat_id), "%s", chat_id);
    snprintf(record->type, sizeof(record->type), "%s", type);
    snprintf(record->created_by, sizeof(record->created_by), "%s", "1:rCreator");
    record->chat_version = 3;
    record->participant_count = count;
    record->participants = (char **)participants;
}

static void test_upsert_and_find(void) {
    chats_t *chats = chats_create();
    CHECK(chats != NULL);

    const char *participants[] = {"1:rAlice", "1:rBob"};
    evergram_chat_info_t record;
    fill_record(&record, "chat-1", EVERGRAM_CHAT_TYPE_GROUP, participants, 2);

    CHECK_EQ_INT(chats_upsert(chats, &record), EVERGRAM_OK);
    CHECK_EQ_INT(chats_count(chats), 1);

    const evergram_chat_info_t *found = chats_find(chats, "chat-1");
    CHECK(found != NULL);
    if (found != NULL) {
        CHECK_EQ_STR(found->chat_id, "chat-1");
        CHECK_EQ_STR(found->type, EVERGRAM_CHAT_TYPE_GROUP);
        CHECK_EQ_STR(found->created_by, "1:rCreator");
        CHECK_EQ_INT(found->chat_version, 3);
        CHECK_EQ_INT(found->participant_count, 2);
        CHECK_EQ_STR(found->participants[0], "1:rAlice");
        CHECK_EQ_STR(found->participants[1], "1:rBob");
    }
    CHECK(chats_find(chats, "absent") == NULL);

    chats_destroy(chats);
}

static void test_upsert_replaces_participants(void) {
    chats_t *chats = chats_create();
    CHECK(chats != NULL);

    const char *first[] = {"1:rAlice", "1:rBob"};
    evergram_chat_info_t record;
    fill_record(&record, "chat-1", EVERGRAM_CHAT_TYPE_GROUP, first, 2);
    CHECK_EQ_INT(chats_upsert(chats, &record), EVERGRAM_OK);

    const char *second[] = {"1:rCarol"};
    fill_record(&record, "chat-1", EVERGRAM_CHAT_TYPE_GROUP, second, 1);
    CHECK_EQ_INT(chats_upsert(chats, &record), EVERGRAM_OK);

    /* Still one entry, with the new participant list, not a merge. */
    CHECK_EQ_INT(chats_count(chats), 1);
    const evergram_chat_info_t *found = chats_find(chats, "chat-1");
    CHECK(found != NULL);
    if (found != NULL) {
        CHECK_EQ_INT(found->participant_count, 1);
        CHECK_EQ_STR(found->participants[0], "1:rCarol");
    }

    chats_destroy(chats);
}

static void test_has_participant(void) {
    chats_t *chats = chats_create();
    CHECK(chats != NULL);

    const char *participants[] = {"1:rAlice"};
    evergram_chat_info_t record;
    fill_record(&record, "chat-1", EVERGRAM_CHAT_TYPE_ONE_ON_ONE, participants, 1);
    CHECK_EQ_INT(chats_upsert(chats, &record), EVERGRAM_OK);

    const evergram_chat_info_t *found = chats_find(chats, "chat-1");
    CHECK(found != NULL);
    CHECK(chats_has_participant(found, "1:rAlice"));
    CHECK(!chats_has_participant(found, "1:rBob"));
    CHECK(!chats_has_participant(NULL, "1:rAlice"));

    chats_destroy(chats);
}

static void test_remove_keeps_others(void) {
    chats_t *chats = chats_create();
    CHECK(chats != NULL);

    const char *participants[] = {"1:rAlice"};
    evergram_chat_info_t record;

    fill_record(&record, "one", EVERGRAM_CHAT_TYPE_ONE_ON_ONE, participants, 1);
    CHECK_EQ_INT(chats_upsert(chats, &record), EVERGRAM_OK);
    fill_record(&record, "two", EVERGRAM_CHAT_TYPE_ONE_ON_ONE, participants, 1);
    CHECK_EQ_INT(chats_upsert(chats, &record), EVERGRAM_OK);
    fill_record(&record, "three", EVERGRAM_CHAT_TYPE_ONE_ON_ONE, participants, 1);
    CHECK_EQ_INT(chats_upsert(chats, &record), EVERGRAM_OK);

    chats_remove(chats, "two");
    CHECK_EQ_INT(chats_count(chats), 2);
    CHECK(chats_find(chats, "two") == NULL);
    CHECK(chats_find(chats, "one") != NULL);
    CHECK(chats_find(chats, "three") != NULL);

    chats_remove(chats, "absent");
    CHECK_EQ_INT(chats_count(chats), 2);

    chats_destroy(chats);
}

static void test_iteration_order_and_growth(void) {
    enum { COUNT = 64 };
    chats_t *chats = chats_create();
    CHECK(chats != NULL);

    const char *participants[] = {"1:rAlice"};
    for (int i = 0; i < COUNT; i++) {
        char chat_id[32];
        snprintf(chat_id, sizeof(chat_id), "chat-%d", i);
        evergram_chat_info_t record;
        fill_record(&record, chat_id, EVERGRAM_CHAT_TYPE_GROUP, participants, 1);
        CHECK_EQ_INT(chats_upsert(chats, &record), EVERGRAM_OK);
    }
    CHECK_EQ_INT(chats_count(chats), COUNT);

    for (int i = 0; i < COUNT; i++) {
        const evergram_chat_info_t *entry = chats_at(chats, (size_t)i);
        CHECK(entry != NULL);
        if (entry != NULL) {
            char expected[32];
            snprintf(expected, sizeof(expected), "chat-%d", i);
            CHECK_EQ_STR(entry->chat_id, expected);
        }
    }
    CHECK(chats_at(chats, COUNT) == NULL);

    chats_destroy(chats);
}

static void test_invalid_arguments(void) {
    uint8_t dummy = 0;
    (void)dummy;

    chats_t *chats = chats_create();
    CHECK(chats != NULL);

    evergram_chat_info_t empty;
    memset(&empty, 0, sizeof(empty));

    CHECK_EQ_INT(chats_upsert(NULL, &empty), EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(chats_upsert(chats, NULL), EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(chats_upsert(chats, &empty), EVERGRAM_ERR_INVALID_ARG);

    chats_destroy(chats);
    chats_destroy(NULL);

    CHECK(chats_find(NULL, "x") == NULL);
    CHECK(chats_at(NULL, 0) == NULL);
    CHECK_EQ_INT(chats_count(NULL), 0);
    chats_remove(NULL, "x");
}

static const test_case_t TESTS[] = {
    {"chats: upsert and find", test_upsert_and_find},
    {"chats: upsert replaces participants", test_upsert_replaces_participants},
    {"chats: has_participant", test_has_participant},
    {"chats: remove keeps others", test_remove_keeps_others},
    {"chats: iteration order and growth", test_iteration_order_and_growth},
    {"chats: invalid arguments and NULL safety", test_invalid_arguments},
};

const test_case_t *chats_tests(size_t *count) {
    *count = sizeof(TESTS) / sizeof(TESTS[0]);
    return TESTS;
}
