/*
 * webhook-bridge — forwards every decrypted message to an external HTTP
 * endpoint: the bridge between Evergram and systems outside the protocol (a
 * support queue, a logging pipeline, a Slack relay).
 *
 * Port of examples/webhook-bridge/index.ts. The webhook receives plaintext, so
 * whatever runs at WEBHOOK_URL must be trusted with the same content this bot
 * can read.
 *
 * Environment:
 *   EVERGRAM_GATEWAY_URL   gateway endpoint   (default ws://localhost:9000/api/ws)
 *   EVERGRAM_IDENTITY_FILE identity path      (default identity.json)
 *   WEBHOOK_URL            endpoint to POST to (required)
 *   WEBHOOK_TIMEOUT_MS     per-request budget  (default 10000)
 *
 * Delivery is queued, not performed inside the message handler: handlers run
 * inside the socket callback, and a blocking HTTP request there would stall the
 * connection. The queue is drained from the poll loop, which is also where a
 * slow endpoint is allowed to cost latency. It is bounded, and an overflow is
 * reported rather than silently dropping the oldest delivery.
 *
 * The body mirrors the TypeScript example's, with one honest difference: the
 * reference sends its parsed `content` object, while this port sends the
 * `contentType` discriminator it computed. Everything else (chatId, chatName,
 * sender, text, messageId, ts) matches.
 */

#include "../_shared/example.h"
#include "../_shared/http_post.h"

#include <string.h>

#define QUEUE_MAX 256
#define BODY_MAX 16384

typedef struct {
    char *body; /* owned */
} delivery_t;

typedef struct {
    delivery_t queue[QUEUE_MAX];
    size_t head;
    size_t count;
    const char *url;
    long timeout_ms;
    unsigned delivered;
    unsigned failed;
} app_t;

static app_t *app_of(evergram_bot_t *bot) {
    return evergram_bot_user_data(bot);
}

/* --- queue ---------------------------------------------------------------- */

/* Drops the oldest pending delivery when the queue is full: a bridge that fell
 * this far behind is better off reporting it than growing without bound. */
static void enqueue(app_t *app, const char *body) {
    if (app->count == QUEUE_MAX) {
        fprintf(stderr, "[webhook-bridge] queue full, dropping the oldest delivery\n");
        free(app->queue[app->head].body);
        app->queue[app->head].body = NULL;
        app->head = (app->head + 1u) % QUEUE_MAX;
        app->count--;
    }

    size_t slot = (app->head + app->count) % QUEUE_MAX;
    app->queue[slot].body = malloc(strlen(body) + 1u);
    if (app->queue[slot].body == NULL) {
        return;
    }
    memcpy(app->queue[slot].body, body, strlen(body) + 1u);
    app->count++;
}

/* One delivery per round, outside any callback. */
static bool deliver_one(app_t *app) {
    if (app->count == 0) {
        return false;
    }

    char *body = app->queue[app->head].body;
    app->queue[app->head].body = NULL;
    app->head = (app->head + 1u) % QUEUE_MAX;
    app->count--;

    char error[256];
    error[0] = '\0';
    int status = example_http_post_json(app->url, body, app->timeout_ms, error, sizeof(error));
    if (status >= 200 && status < 300) {
        app->delivered++;
    } else if (status >= 0) {
        app->failed++;
        fprintf(stderr, "[webhook-bridge] webhook returned %d\n", status);
    } else {
        app->failed++;
        fprintf(stderr, "[webhook-bridge] webhook delivery failed: %s\n",
                error[0] != '\0' ? error : "unknown reason");
    }

    free(body);
    return true;
}

/* --- JSON body ------------------------------------------------------------ */

/* Escapes a string for JSON. Truncation is impossible here: the caller sizes the
 * buffer for the worst case, and `*used` is always advanced by what fits. */
static void append_escaped(char *out, size_t out_size, size_t *used, const char *text) {
    for (const char *cursor = text; *cursor != '\0' && *used + 7u < out_size; cursor++) {
        unsigned char c = (unsigned char)*cursor;
        switch (c) {
        case '"':
            out[(*used)++] = '\\';
            out[(*used)++] = '"';
            break;
        case '\\':
            out[(*used)++] = '\\';
            out[(*used)++] = '\\';
            break;
        case '\n':
            out[(*used)++] = '\\';
            out[(*used)++] = 'n';
            break;
        case '\r':
            out[(*used)++] = '\\';
            out[(*used)++] = 'r';
            break;
        case '\t':
            out[(*used)++] = '\\';
            out[(*used)++] = 't';
            break;
        default:
            if (c < 0x20) {
                static const char digits[] = "0123456789abcdef";
                out[(*used)++] = '\\';
                out[(*used)++] = 'u';
                out[(*used)++] = '0';
                out[(*used)++] = '0';
                out[(*used)++] = digits[c >> 4];
                out[(*used)++] = digits[c & 0x0f];
            } else {
                out[(*used)++] = (char)c;
            }
            break;
        }
    }
}

static void append_field(char *out, size_t out_size, size_t *used, const char *key,
                         const char *value) {
    int written = snprintf(out + *used, out_size - *used, "\"%s\":\"", key);
    if (written < 0 || (size_t)written >= out_size - *used) {
        return;
    }
    *used += (size_t)written;
    append_escaped(out, out_size, used, value);
    if (*used + 1u < out_size) {
        out[(*used)++] = '"';
    }
    out[*used] = '\0';
}

static const char *content_type_name(evergram_content_type_t type) {
    switch (type) {
    case EVERGRAM_CONTENT_TEXT:
        return "text";
    case EVERGRAM_CONTENT_AUDIO:
        return "audio";
    case EVERGRAM_CONTENT_PAYMENT_REQUEST:
        return "payment_request";
    case EVERGRAM_CONTENT_PAYMENT_RECEIPT:
        return "payment_receipt";
    case EVERGRAM_CONTENT_PAYMENT_SENT:
        return "payment_sent";
    case EVERGRAM_CONTENT_UNKNOWN:
    default:
        return "unknown";
    }
}

static void build_body(char *out, size_t out_size, const evergram_message_t *message,
                       const evergram_chat_info_t *chat, const char *content_type_name_value) {
    size_t used = 0;
    out[0] = '\0';

    int written = snprintf(out, out_size, "{");
    if (written < 0) {
        return;
    }
    used = (size_t)written;

    append_field(out, out_size, &used, "chatId", message->chat_id);
    if (used + 1u < out_size) {
        out[used++] = ',';
        out[used] = '\0';
    }
    append_field(out, out_size, &used, "chatName",
                 chat != NULL && chat->name[0] != '\0' ? chat->name : "");
    if (used + 1u < out_size) {
        out[used++] = ',';
        out[used] = '\0';
    }
    append_field(out, out_size, &used, "sender", message->sender);
    if (used + 1u < out_size) {
        out[used++] = ',';
        out[used] = '\0';
    }
    append_field(out, out_size, &used, "messageId", message->message_id);
    if (used + 1u < out_size) {
        out[used++] = ',';
        out[used] = '\0';
    }
    append_field(out, out_size, &used, "text", message->text);
    if (used + 1u < out_size) {
        out[used++] = ',';
        out[used] = '\0';
    }
    append_field(out, out_size, &used, "contentType", content_type_name_value);

    written = snprintf(out + used, out_size - used, ",\"ts\":%llu}",
                       (unsigned long long)message->timestamp_ms);
    if (written < 0 || (size_t)written >= out_size - used) {
        out[used] = '\0';
    }
}

/* --- handlers ------------------------------------------------------------- */

static void on_message(evergram_t *eg, const evergram_message_t *message) {
    evergram_bot_t *bot = evergram_bot_from_client(eg);
    app_t *app = app_of(bot);
    if (app == NULL || message == NULL || message->text == NULL) {
        return;
    }

    /* The body is built from borrowed strings, so it is copied into the queue
     * before the callback returns. */
    char body[BODY_MAX];
    build_body(body, sizeof(body), message, evergram_chat_get(eg, message->chat_id),
               content_type_name(evergram_message_content_type(message->text)));
    enqueue(app, body);
}

static void on_error(evergram_t *eg, evergram_status_t status, const char *detail) {
    (void)eg;
    example_log_error("[webhook-bridge]", status, detail);
}

int main(void) {
    app_t app;
    memset(&app, 0, sizeof(app));

    app.url = getenv("WEBHOOK_URL");
    if (app.url == NULL || app.url[0] == '\0') {
        fprintf(stderr, "[webhook-bridge] WEBHOOK_URL env var is required\n");
        return EXIT_FAILURE;
    }

    const char *timeout = getenv("WEBHOOK_TIMEOUT_MS");
    app.timeout_ms = (timeout != NULL && timeout[0] != '\0') ? strtol(timeout, NULL, 10) : 10000;

    const char *level = getenv("EVERGRAM_LOG");
    if (level != NULL) {
        evergram_log_set_level(evergram_log_level_from_name(level));
    }

    const evergram_bot_options_t options = {
        .url = example_gateway_url(),
        .identity_path = example_identity_path(),
        .platform = "Terminal",
        .user_data = &app,
    };

    evergram_bot_t *bot = evergram_bot_create(&options);
    if (bot == NULL) {
        fprintf(stderr, "[webhook-bridge] cannot create the bot\n");
        return EXIT_FAILURE;
    }

    evergram_bot_on_message(bot, on_message);
    evergram_bot_on_error(bot, on_error);

    signal(SIGINT, example_handle_signal);
    signal(SIGTERM, example_handle_signal);

    evergram_status_t status = evergram_bot_start(bot);
    if (status != EVERGRAM_OK) {
        example_log_error("[webhook-bridge]", status, "cannot connect");
        evergram_bot_destroy(bot);
        return EXIT_FAILURE;
    }

    printf("[webhook-bridge] online as %s, forwarding to %s\n",
           evergram_identity_key(evergram_bot_client(bot)), app.url);

    while (example_running) {
        status = evergram_bot_poll(bot, 100);
        if (status != EVERGRAM_OK && status != EVERGRAM_ERR_TIMEOUT &&
            status != EVERGRAM_ERR_NOT_CONNECTED) {
            example_log_error("[webhook-bridge]", status, "poll failed");
            break;
        }
        deliver_one(&app);
    }

    /* One last attempt at whatever is still queued. */
    while (deliver_one(&app)) {
    }

    printf("[webhook-bridge] delivered %u, failed %u\n", app.delivered, app.failed);
    for (size_t i = 0; i < app.count; i++) {
        free(app.queue[(app.head + i) % QUEUE_MAX].body);
    }
    evergram_bot_destroy(bot);
    return EXIT_SUCCESS;
}
