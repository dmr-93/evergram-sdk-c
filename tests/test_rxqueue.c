#include <string.h>

#include "rxqueue.h"
#include "test.h"

static void test_single_frame(void) {
    rxqueue_t *queue = rxqueue_create(0);
    CHECK(queue != NULL);

    const uint8_t payload[] = {1, 2, 3};
    CHECK_EQ_INT(rxqueue_push(queue, payload, sizeof(payload)), EVERGRAM_OK);
    CHECK(!rxqueue_has_frame(queue));

    CHECK_EQ_INT(rxqueue_end_frame(queue), EVERGRAM_OK);
    CHECK(rxqueue_has_frame(queue));

    size_t len = 0;
    const uint8_t *frame = rxqueue_frame(queue, &len);
    CHECK(frame != NULL);
    CHECK_EQ_INT(len, sizeof(payload));
    CHECK_EQ_INT(memcmp(frame, payload, sizeof(payload)), 0);

    rxqueue_pop(queue);
    CHECK(!rxqueue_has_frame(queue));
    rxqueue_destroy(queue);
}

static void test_fragmented_frame_is_reassembled(void) {
    rxqueue_t *queue = rxqueue_create(0);
    CHECK(queue != NULL);

    CHECK_EQ_INT(rxqueue_push(queue, "ab", 2), EVERGRAM_OK);
    CHECK(!rxqueue_has_frame(queue));
    CHECK_EQ_INT(rxqueue_push(queue, "cd", 2), EVERGRAM_OK);
    CHECK_EQ_INT(rxqueue_end_frame(queue), EVERGRAM_OK);

    size_t len = 0;
    const uint8_t *frame = rxqueue_frame(queue, &len);
    CHECK_EQ_INT(len, 4);
    CHECK_EQ_INT(memcmp(frame, "abcd", 4), 0);

    rxqueue_destroy(queue);
}

static void test_two_frames_stay_separate(void) {
    rxqueue_t *queue = rxqueue_create(0);
    CHECK(queue != NULL);

    CHECK_EQ_INT(rxqueue_push(queue, "one", 3), EVERGRAM_OK);
    CHECK_EQ_INT(rxqueue_end_frame(queue), EVERGRAM_OK);
    CHECK_EQ_INT(rxqueue_push(queue, "two", 3), EVERGRAM_OK);
    CHECK_EQ_INT(rxqueue_end_frame(queue), EVERGRAM_OK);

    CHECK_EQ_INT(rxqueue_frame_count(queue), 2);

    size_t len = 0;
    const uint8_t *frame = rxqueue_frame(queue, &len);
    CHECK_EQ_INT(len, 3);
    CHECK_EQ_INT(memcmp(frame, "one", 3), 0);

    rxqueue_pop(queue);
    frame = rxqueue_frame(queue, &len);
    CHECK_EQ_INT(len, 3);
    CHECK_EQ_INT(memcmp(frame, "two", 3), 0);

    rxqueue_pop(queue);
    CHECK(!rxqueue_has_frame(queue));
    rxqueue_destroy(queue);
}

static void test_empty_frame_ignored(void) {
    rxqueue_t *queue = rxqueue_create(0);
    CHECK(queue != NULL);

    CHECK_EQ_INT(rxqueue_end_frame(queue), EVERGRAM_OK);
    CHECK(!rxqueue_has_frame(queue));

    CHECK_EQ_INT(rxqueue_push(queue, "x", 1), EVERGRAM_OK);
    CHECK_EQ_INT(rxqueue_end_frame(queue), EVERGRAM_OK);
    CHECK_EQ_INT(rxqueue_end_frame(queue), EVERGRAM_OK); /* no bytes since the last boundary */
    CHECK_EQ_INT(rxqueue_frame_count(queue), 1);

    rxqueue_destroy(queue);
}

static void test_pop_without_frame_is_safe(void) {
    rxqueue_t *queue = rxqueue_create(0);
    CHECK(queue != NULL);

    rxqueue_pop(queue);
    CHECK(!rxqueue_has_frame(queue));
    CHECK(rxqueue_frame(queue, NULL) == NULL);

    rxqueue_destroy(queue);
}

static void test_clear_drops_everything(void) {
    rxqueue_t *queue = rxqueue_create(0);
    CHECK(queue != NULL);

    CHECK_EQ_INT(rxqueue_push(queue, "abc", 3), EVERGRAM_OK);
    CHECK_EQ_INT(rxqueue_end_frame(queue), EVERGRAM_OK);
    rxqueue_clear(queue);
    CHECK(!rxqueue_has_frame(queue));

    CHECK_EQ_INT(rxqueue_push(queue, "de", 2), EVERGRAM_OK);
    CHECK_EQ_INT(rxqueue_end_frame(queue), EVERGRAM_OK);
    size_t len = 0;
    const uint8_t *frame = rxqueue_frame(queue, &len);
    CHECK_EQ_INT(len, 2);
    CHECK_EQ_INT(memcmp(frame, "de", 2), 0);

    rxqueue_destroy(queue);
}

static void test_many_frames_keep_order(void) {
    enum { FRAME_COUNT = 1000, FRAME_SIZE = 8 };

    rxqueue_t *queue = rxqueue_create(0);
    CHECK(queue != NULL);

    for (int i = 0; i < FRAME_COUNT; i++) {
        uint8_t payload[FRAME_SIZE];
        memset(payload, i & 0xFF, sizeof(payload));
        CHECK_EQ_INT(rxqueue_push(queue, payload, sizeof(payload)), EVERGRAM_OK);
        CHECK_EQ_INT(rxqueue_end_frame(queue), EVERGRAM_OK);
    }
    CHECK_EQ_INT(rxqueue_frame_count(queue), FRAME_COUNT);

    for (int i = 0; i < FRAME_COUNT; i++) {
        size_t len = 0;
        const uint8_t *frame = rxqueue_frame(queue, &len);
        CHECK(frame != NULL);
        CHECK_EQ_INT(len, FRAME_SIZE);
        if (frame != NULL) {
            CHECK_EQ_INT(frame[0], i & 0xFF);
        }
        rxqueue_pop(queue);
    }
    CHECK(!rxqueue_has_frame(queue));

    rxqueue_destroy(queue);
}

static const test_case_t TESTS[] = {
    {"rxqueue: single frame", test_single_frame},
    {"rxqueue: fragmented frame reassembled", test_fragmented_frame_is_reassembled},
    {"rxqueue: two frames stay separate", test_two_frames_stay_separate},
    {"rxqueue: empty frame ignored", test_empty_frame_ignored},
    {"rxqueue: pop without frame is safe", test_pop_without_frame_is_safe},
    {"rxqueue: clear drops everything", test_clear_drops_everything},
    {"rxqueue: many frames keep order", test_many_frames_keep_order},
};

const test_case_t *rxqueue_tests(size_t *count) {
    *count = sizeof(TESTS) / sizeof(TESTS[0]);
    return TESTS;
}
