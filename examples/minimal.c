/*
 * Smallest useful consumer: connects, logs events, and optionally sends one
 * message after authentication.
 *
 * Build (shared library):
 *   cc -std=c17 -I include examples/minimal.c -L build/lib -levergram \
 *      -Wl,-rpath,'$ORIGIN/../lib' -o minimal
 *
 * Build (static library):
 *   cc -std=c17 -I include examples/minimal.c build/lib/libevergram.a \
 *      -lsodium -lwebsockets -lprotobuf-c -lssl -lcrypto -o minimal
 *
 * Run:
 *   ./minimal wss://staging.evergram.app/api/ws identity.json
 *   ./minimal wss://staging.evergram.app/api/ws identity.json <chat_id> "hello"
 */

#include <evergram.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define POLL_INTERVAL_MS 100

static volatile sig_atomic_t g_running = 1;

static void on_signal(int number) {
    (void)number;
    g_running = 0;
}

typedef struct {
    evergram_wallet_t wallet;
    evergram_device_t device;
    const char *chat_id; /* NULL when the program only listens */
    const char *text;
    int message_sent;
} app_t;

static void on_connected(evergram_t *eg) {
    app_t *app = evergram_user_data(eg);
    printf("online as %s\n", app->wallet.address);

    if (app->chat_id != NULL && !app->message_sent) {
        evergram_status_t status = evergram_send(eg, app->chat_id, app->text);
        printf("send: %s\n", evergram_status_str(status));
        app->message_sent = 1;
    }
}

static void on_message(evergram_t *eg, const evergram_message_t *message) {
    (void)eg;
    printf("message chat=%s from=%s text=%s\n", message->chat_id, message->sender,
           message->text != NULL ? message->text : "");
}

static void on_error(evergram_t *eg, evergram_status_t status, const char *detail) {
    (void)eg;
    fprintf(stderr, "error: %s (%s)\n", evergram_status_str(status), detail != NULL ? detail : "");
}

static void on_disconnected(evergram_t *eg) {
    (void)eg;
    printf("disconnected\n");
}

int main(int argc, char **argv) {
    if (argc != 3 && argc != 5) {
        fprintf(stderr, "usage: %s <url> <identity.json> [chat_id text]\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *level = getenv("EVERGRAM_LOG");
    if (level != NULL) {
        evergram_log_set_level(evergram_log_level_from_name(level));
    }

    app_t app;
    memset(&app, 0, sizeof(app));
    app.chat_id = argc == 5 ? argv[3] : NULL;
    app.text = argc == 5 ? argv[4] : NULL;

    evergram_status_t status = evergram_identity_load(argv[2], &app.wallet, &app.device);
    if (status != EVERGRAM_OK) {
        fprintf(stderr, "cannot load identity %s: %s\n", argv[2], evergram_status_str(status));
        return EXIT_FAILURE;
    }

    const evergram_options_t options = {
        .url = argv[1],
        .wallet = &app.wallet,
        .device = &app.device,
        .platform = "Terminal",
        .user_data = &app,
    };

    evergram_t *client = evergram_create(&options);
    if (client == NULL) {
        fprintf(stderr, "cannot create client\n");
        return EXIT_FAILURE;
    }

    evergram_on_connected(client, on_connected);
    evergram_on_message(client, on_message);
    evergram_on_error(client, on_error);
    evergram_on_disconnected(client, on_disconnected);

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    status = evergram_start(client);
    if (status != EVERGRAM_OK) {
        fprintf(stderr, "cannot connect: %s\n", evergram_status_str(status));
        evergram_destroy(client);
        return EXIT_FAILURE;
    }

    while (g_running) {
        status = evergram_poll(client, POLL_INTERVAL_MS);
        if (status != EVERGRAM_OK && status != EVERGRAM_ERR_TIMEOUT) {
            fprintf(stderr, "poll failed: %s\n", evergram_status_str(status));
            break;
        }
    }

    evergram_destroy(client);
    evergram_wallet_wipe(&app.wallet);
    evergram_device_wipe(&app.device);
    return EXIT_SUCCESS;
}
