#ifndef EVERGRAM_EXAMPLE_SHARED_H
#define EVERGRAM_EXAMPLE_SHARED_H

#include <evergram.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * Plumbing shared by the example bots, mirroring examples/_shared/ in the
 * TypeScript SDK: where the gateway lives, where the identity is stored, how
 * Ctrl+C is handled, and the pump loop.
 *
 * The identity file is created on first run, so re-running an example reuses
 * the same wallet and device instead of orphaning chat history under a new
 * identity.
 */

static volatile sig_atomic_t example_running = 1;

static inline void example_handle_signal(int number) {
    (void)number;
    example_running = 0;
}

static inline const char *example_gateway_url(void) {
    const char *url = getenv("EVERGRAM_GATEWAY_URL");
    return (url != NULL && url[0] != '\0') ? url : "ws://localhost:9000/api/ws";
}

static inline const char *example_identity_path(void) {
    const char *path = getenv("EVERGRAM_IDENTITY_FILE");
    return (path != NULL && path[0] != '\0') ? path : "identity.json";
}

static inline void example_log_error(const char *prefix, evergram_status_t status,
                                     const char *detail) {
    fprintf(stderr, "%s %s%s%s\n", prefix, evergram_status_str(status), detail != NULL ? ": " : "",
            detail != NULL ? detail : "");
}

/* Connects and pumps until Ctrl+C. Returns a process exit code. */
static inline int example_run(evergram_bot_t *bot) {
    signal(SIGINT, example_handle_signal);
    signal(SIGTERM, example_handle_signal);

    evergram_status_t status = evergram_bot_start(bot);
    if (status != EVERGRAM_OK) {
        example_log_error("[fatal]", status, "cannot connect");
        return 1;
    }

    while (example_running) {
        status = evergram_bot_poll(bot, 100);
        if (status != EVERGRAM_OK && status != EVERGRAM_ERR_TIMEOUT &&
            status != EVERGRAM_ERR_NOT_CONNECTED) {
            example_log_error("[fatal]", status, "poll failed");
            return 1;
        }
    }
    return 0;
}

#endif /* EVERGRAM_EXAMPLE_SHARED_H */
