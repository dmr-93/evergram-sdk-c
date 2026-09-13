#include "backoff.h"
#include "test.h"

/* The curve is a pure function, so the delays are asserted exactly. */
static void test_doubles_each_attempt(void) {
    CHECK_EQ_INT(evergram_backoff_base_ms(1, 1000, 30000), 1000);
    CHECK_EQ_INT(evergram_backoff_base_ms(2, 1000, 30000), 2000);
    CHECK_EQ_INT(evergram_backoff_base_ms(3, 1000, 30000), 4000);
    CHECK_EQ_INT(evergram_backoff_base_ms(4, 1000, 30000), 8000);
    CHECK_EQ_INT(evergram_backoff_base_ms(5, 1000, 30000), 16000);
}

static void test_caps_at_the_ceiling(void) {
    CHECK_EQ_INT(evergram_backoff_base_ms(6, 1000, 30000), 30000);
    CHECK_EQ_INT(evergram_backoff_base_ms(7, 1000, 30000), 30000);
    CHECK_EQ_INT(evergram_backoff_base_ms(64, 1000, 30000), 30000);
}

static void test_attempt_zero_is_the_base(void) {
    CHECK_EQ_INT(evergram_backoff_base_ms(0, 1000, 30000), 1000);
}

static void test_cap_below_base_is_respected(void) {
    CHECK_EQ_INT(evergram_backoff_base_ms(1, 5000, 1000), 1000);
}

static void test_jitter_stays_within_bounds(void) {
    for (unsigned attempt = 1; attempt <= 8; attempt++) {
        uint32_t base = evergram_backoff_base_ms(attempt, EVERGRAM_BACKOFF_BASE_MS,
                                                 EVERGRAM_BACKOFF_CAP_MS);
        for (int draw = 0; draw < 50; draw++) {
            uint32_t delay = evergram_backoff_delay_ms(attempt, EVERGRAM_BACKOFF_BASE_MS,
                                                       EVERGRAM_BACKOFF_CAP_MS,
                                                       EVERGRAM_BACKOFF_JITTER_MS);
            CHECK(delay >= base);
            CHECK(delay <= EVERGRAM_BACKOFF_CAP_MS);
        }
    }
}

static const test_case_t TESTS[] = {
    {"backoff: doubles on each attempt", test_doubles_each_attempt},
    {"backoff: caps at the ceiling", test_caps_at_the_ceiling},
    {"backoff: attempt zero is the base", test_attempt_zero_is_the_base},
    {"backoff: cap below base wins", test_cap_below_base_is_respected},
    {"backoff: jitter stays within bounds", test_jitter_stays_within_bounds},
};

const test_case_t *backoff_tests(size_t *count) {
    *count = sizeof(TESTS) / sizeof(TESTS[0]);
    return TESTS;
}
