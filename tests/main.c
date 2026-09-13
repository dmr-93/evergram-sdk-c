#include "test.h"

int g_checks = 0;
int g_failures = 0;

void test_fail(const char *file, int line, const char *expression, const char *detail) {
    g_failures++;
    fprintf(stderr, "    FAIL %s:%d: %s", file, line, expression);
    if (detail != NULL) {
        fprintf(stderr, " -> %s", detail);
    }
    fputc('\n', stderr);
}

const test_case_t *base58_tests(size_t *count);
const test_case_t *rxqueue_tests(size_t *count);
const test_case_t *xrpl_tests(size_t *count);
const test_case_t *identity_tests(size_t *count);
const test_case_t *parser_tests(size_t *count);
const test_case_t *e2ee_tests(size_t *count);
const test_case_t *chatkeys_tests(size_t *count);
const test_case_t *chats_tests(size_t *count);
const test_case_t *backoff_tests(size_t *count);
const test_case_t *bot_tests(size_t *count);
const test_case_t *content_tests(size_t *count);
const test_case_t *json_tests(size_t *count);
const test_case_t *relay_tests(size_t *count);
const test_case_t *visitor_tests(size_t *count);
const test_case_t *request_tests(size_t *count);
const test_case_t *interop_tests(size_t *count);
const test_case_t *widget_tests(size_t *count);
const test_case_t *purchase_tests(size_t *count);
const test_case_t *xahau_tx_tests(size_t *count);
#ifdef EVERGRAM_HAVE_CURL
/* The HTTP helper lives with the examples and needs libcurl, so this suite is
 * compiled only where the library is available. */
const test_case_t *webhook_tests(size_t *count);
#endif

int main(void) {
    const test_case_t *(*suites[])(size_t *) = {
        base58_tests, rxqueue_tests,   xrpl_tests,   identity_tests, parser_tests,
        e2ee_tests,   chatkeys_tests,  chats_tests,  backoff_tests, bot_tests,
        content_tests, json_tests,    relay_tests,  visitor_tests, request_tests,
        interop_tests, widget_tests, purchase_tests, xahau_tx_tests,
#ifdef EVERGRAM_HAVE_CURL
        webhook_tests,
#endif
    };
    const size_t suite_count = sizeof(suites) / sizeof(suites[0]);

    int failed_cases = 0;
    int total_cases = 0;

    for (size_t s = 0; s < suite_count; s++) {
        size_t count = 0;
        const test_case_t *tests = suites[s](&count);

        for (size_t i = 0; i < count; i++) {
            int failures_before = g_failures;
            tests[i].fn();
            total_cases++;

            if (g_failures == failures_before) {
                printf("[ ok ] %s\n", tests[i].name);
            } else {
                printf("[fail] %s\n", tests[i].name);
                failed_cases++;
            }
        }
    }

    printf("\n%d cases, %d checks, %d failures\n", total_cases, g_checks, g_failures);
    return failed_cases == 0 ? 0 : 1;
}
