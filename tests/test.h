#ifndef EVERGRAM_TEST_H
#define EVERGRAM_TEST_H

#include <stddef.h>
#include <stdio.h>
#include <string.h>

typedef void (*test_fn_t)(void);

typedef struct {
    const char *name;
    test_fn_t fn;
} test_case_t;

extern int g_checks;
extern int g_failures;

void test_fail(const char *file, int line, const char *expression, const char *detail);

#define CHECK(expression)                                                                          \
    do {                                                                                           \
        g_checks++;                                                                                \
        if (!(expression)) {                                                                       \
            test_fail(__FILE__, __LINE__, #expression, NULL);                                      \
        }                                                                                          \
    } while (0)

#define CHECK_EQ_INT(actual, expected)                                                             \
    do {                                                                                           \
        long long actual_ = (long long)(actual);                                                   \
        long long expected_ = (long long)(expected);                                               \
        g_checks++;                                                                                \
        if (actual_ != expected_) {                                                                \
            char detail_[96];                                                                      \
            snprintf(detail_, sizeof(detail_), "%lld != %lld", actual_, expected_);                \
            test_fail(__FILE__, __LINE__, #actual, detail_);                                       \
        }                                                                                          \
    } while (0)

#define CHECK_EQ_STR(actual, expected)                                                             \
    do {                                                                                           \
        const char *actual_ = (actual);                                                            \
        const char *expected_ = (expected);                                                        \
        g_checks++;                                                                                \
        if (actual_ == NULL || strcmp(actual_, expected_) != 0) {                                  \
            char detail_[256];                                                                     \
            snprintf(detail_, sizeof(detail_), "\"%.100s\" != \"%.100s\"",                         \
                     actual_ != NULL ? actual_ : "(null)", expected_);                             \
            test_fail(__FILE__, __LINE__, #actual, detail_);                                       \
        }                                                                                          \
    } while (0)

#endif /* EVERGRAM_TEST_H */
