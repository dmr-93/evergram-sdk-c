/*
 * widget-visitor-bot — the owner side of the embeddable widget.
 *
 * Port of examples/widget-visitor-bot/index.ts. It echoes whatever an
 * anonymous widget visitor sends. By protocol design the visitor is not
 * authenticated with this SDK, so the visitor role is played by the web widget
 * (open {EVERGRAM_WEBAPP_URL}/widget/{widget_id}); this bot is the owner that
 * receives the room and replies.
 *
 * A room lives only while both sockets do: the gateway keeps no record of it.
 * This example therefore persists the rooms it has seen, so a restart can
 * re-claim them within the gateway's reconnect grace window instead of losing
 * the conversation. Rooms are dropped once they are over.
 *
 * Environment:
 *   EVERGRAM_GATEWAY_URL   gateway endpoint        (default ws://localhost:9000/api/ws)
 *   EVERGRAM_IDENTITY_FILE identity path           (default identity.json)
 *   EVERGRAM_SESSIONS_FILE persisted rooms         (default visitor-sessions.txt)
 *   WIDGET_ID              printed as a hint for the widget URL
 */

#include "../_shared/example.h"

#include <string.h>

/*
 * Persisted room, one per line:
 *   room_token|key_hex|widget_id|visitor_label|origin
 * Fields are escaped as %HH, so a '|' inside a label cannot break the format.
 */
#define SESSIONS_MAX 32
#define LINE_MAX 2048

typedef struct {
    evergram_visitor_handle_t handle;
    uint8_t key[EVERGRAM_SYM_KEY_SIZE];
    bool has_key;
} session_t;

typedef struct {
    session_t sessions[SESSIONS_MAX];
    size_t count;
    const char *path;
} app_t;

static app_t *app_of(evergram_bot_t *bot) {
    return evergram_bot_user_data(bot);
}

static session_t *find_session(app_t *app, const char *room_token) {
    for (size_t i = 0; i < app->count; i++) {
        if (strcmp(app->sessions[i].handle.room_token, room_token) == 0) {
            return &app->sessions[i];
        }
    }
    return NULL;
}

static void forget_session(app_t *app, const char *room_token) {
    for (size_t i = 0; i < app->count; i++) {
        if (strcmp(app->sessions[i].handle.room_token, room_token) == 0) {
            app->sessions[i] = app->sessions[app->count - 1u];
            app->count--;
            return;
        }
    }
}

/* --- persistence ---------------------------------------------------------- */

static void hex_encode(const uint8_t *bytes, size_t len, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2u * i] = digits[bytes[i] >> 4];
        out[2u * i + 1u] = digits[bytes[i] & 0x0f];
    }
    out[2u * len] = '\0';
}

static bool hex_decode(const char *hex, uint8_t *out, size_t len) {
    if (strlen(hex) != 2u * len) {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned value = 0;
        for (int nibble = 0; nibble < 2; nibble++) {
            char c = hex[2u * i + (size_t)nibble];
            unsigned digit;
            if (c >= '0' && c <= '9') {
                digit = (unsigned)(c - '0');
            } else if (c >= 'a' && c <= 'f') {
                digit = (unsigned)(c - 'a') + 10u;
            } else {
                return false;
            }
            value = (value << 4) | digit;
        }
        out[i] = (uint8_t)value;
    }
    return true;
}

/* Escapes '|', '%' and newlines so one room stays on one line. */
static void escape(const char *field, char *out, size_t out_size) {
    size_t used = 0;
    for (const char *cursor = field; *cursor != '\0' && used + 4u < out_size; cursor++) {
        unsigned char c = (unsigned char)*cursor;
        if (c == '|' || c == '%' || c == '\n' || c == '\r') {
            static const char digits[] = "0123456789ABCDEF";
            out[used++] = '%';
            out[used++] = digits[c >> 4];
            out[used++] = digits[c & 0x0f];
        } else {
            out[used++] = (char)c;
        }
    }
    out[used] = '\0';
}

/* Reads two uppercase hex digits. A malformed escape stays literal text. */
static bool hex_pair(const char *text, unsigned *value_out) {
    unsigned value = 0;
    for (int nibble = 0; nibble < 2; nibble++) {
        char c = text[nibble];
        unsigned digit;
        if (c >= '0' && c <= '9') {
            digit = (unsigned)(c - '0');
        } else if (c >= 'A' && c <= 'F') {
            digit = (unsigned)(c - 'A') + 10u;
        } else {
            return false;
        }
        value = (value << 4) | digit;
    }
    *value_out = value;
    return true;
}

static void unescape(const char *field, char *out, size_t out_size) {
    size_t used = 0;
    for (const char *cursor = field; *cursor != '\0' && used + 1u < out_size; cursor++) {
        unsigned value = 0;
        if (cursor[0] == '%' && hex_pair(cursor + 1, &value)) {
            out[used++] = (char)value;
            cursor += 2;
            continue;
        }
        out[used++] = *cursor;
    }
    out[used] = '\0';
}

static void save_sessions(const app_t *app) {
    FILE *file = fopen(app->path, "w");
    if (file == NULL) {
        fprintf(stderr, "[visitor-bot] cannot write %s\n", app->path);
        return;
    }

    for (size_t i = 0; i < app->count; i++) {
        char key_hex[2u * EVERGRAM_SYM_KEY_SIZE + 1u];
        char token[4u * EVERGRAM_ROOM_TOKEN_SIZE];
        char widget[4u * EVERGRAM_WIDGET_ID_SIZE];
        char label[4u * EVERGRAM_VISITOR_LABEL_SIZE];
        char origin[4u * EVERGRAM_VISITOR_ORIGIN_SIZE];

        if (!app->sessions[i].has_key) {
            continue;
        }
        hex_encode(app->sessions[i].key, EVERGRAM_SYM_KEY_SIZE, key_hex);
        escape(app->sessions[i].handle.room_token, token, sizeof(token));
        escape(app->sessions[i].handle.widget_id, widget, sizeof(widget));
        escape(app->sessions[i].handle.visitor_label, label, sizeof(label));
        escape(app->sessions[i].handle.origin, origin, sizeof(origin));
        fprintf(file, "%s|%s|%s|%s|%s\n", token, key_hex, widget, label, origin);
    }
    fclose(file);
}

/* Re-arms every room saved by a previous run. Must run before the first poll,
 * because the joiner slot is re-claimed as soon as the client authenticates. */
static void load_sessions(evergram_bot_t *bot, app_t *app) {
    FILE *file = fopen(app->path, "r");
    if (file == NULL) {
        return;
    }

    char line[LINE_MAX];
    while (fgets(line, sizeof(line), file) != NULL && app->count < SESSIONS_MAX) {
        line[strcspn(line, "\r\n")] = '\0';
        char *token = line;
        char *key_hex = strchr(token, '|');
        if (key_hex == NULL) {
            continue;
        }
        *key_hex++ = '\0';
        char *widget = strchr(key_hex, '|');
        char *label = widget != NULL ? strchr(widget + 1, '|') : NULL;
        char *origin = label != NULL ? strchr(label + 1, '|') : NULL;
        if (widget == NULL || label == NULL || origin == NULL) {
            continue;
        }
        *widget++ = '\0';
        *label++ = '\0';
        *origin++ = '\0';

        session_t *session = &app->sessions[app->count];
        memset(session, 0, sizeof(*session));
        unescape(token, session->handle.room_token, sizeof(session->handle.room_token));
        unescape(widget, session->handle.widget_id, sizeof(session->handle.widget_id));
        unescape(label, session->handle.visitor_label, sizeof(session->handle.visitor_label));
        unescape(origin, session->handle.origin, sizeof(session->handle.origin));
        if (!hex_decode(key_hex, session->key, EVERGRAM_SYM_KEY_SIZE)) {
            continue;
        }
        session->has_key = true;

        evergram_status_t status =
            evergram_bot_visitor_register(bot, session->handle.room_token, session->key,
                                          &session->handle);
        if (status != EVERGRAM_OK) {
            example_log_error("[visitor-bot]", status, "cannot re-arm a saved room");
            continue;
        }
        app->count++;
        printf("[visitor-bot] re-armed room %s (widget %s)\n", session->handle.room_token,
               session->handle.widget_id);
    }
    fclose(file);
}

/* --- handlers ------------------------------------------------------------- */

static void on_visitor_room(evergram_bot_t *bot, const char *room_token,
                            const evergram_visitor_handle_t *handle,
                            const evergram_relay_text_t *first_message) {
    app_t *app = app_of(bot);
    if (app == NULL || handle == NULL) {
        return;
    }

    session_t *session = find_session(app, room_token);
    if (session == NULL && app->count < SESSIONS_MAX) {
        session = &app->sessions[app->count++];
        memset(session, 0, sizeof(*session));
    }
    if (session == NULL) {
        fprintf(stderr, "[visitor-bot] too many rooms, ignoring %s\n", room_token);
        return;
    }

    session->handle = *handle;
    if (evergram_visitor_room_key(evergram_bot_client(bot), room_token, session->key) ==
        EVERGRAM_OK) {
        session->has_key = true;
        save_sessions(app);
    }

    printf("[visitor-bot] room %s opened by \"%s\" from %s\n", room_token,
           handle->visitor_label, handle->origin);

    if (first_message != NULL && first_message->text[0] != '\0') {
        printf("[visitor-bot] %s -> %s\n", handle->visitor_label, first_message->text);
        evergram_status_t status = evergram_bot_visitor_reply_with_typing(
            bot, handle, "Echo: %s", first_message->text);
        if (status != EVERGRAM_OK) {
            example_log_error("[visitor-bot]", status, "cannot reply");
        }
    }
}

static void on_visitor_message(evergram_bot_t *bot, const char *room_token,
                               const evergram_visitor_handle_t *handle,
                               const evergram_relay_text_t *event) {
    if (handle == NULL) {
        /* The room is over or was claimed by another device. */
        printf("[visitor-bot] room %s is no longer ours, dropping a message\n", room_token);
        return;
    }

    printf("[visitor-bot] %s -> %s\n", handle->visitor_label, event->text);
    evergram_status_t status =
        evergram_bot_visitor_reply_with_typing(bot, handle, "Echo: %s", event->text);
    if (status != EVERGRAM_OK) {
        example_log_error("[visitor-bot]", status, "cannot reply");
    }
}

static void on_visitor_state(evergram_bot_t *bot, const char *room_token,
                             const evergram_visitor_handle_t *handle,
                             const evergram_visitor_state_event_t *event) {
    app_t *app = app_of(bot);
    if (app == NULL || event == NULL) {
        return;
    }
    (void)handle;

    switch (event->state) {
    case EVERGRAM_VISITOR_STATE_CONNECTED:
        printf("[visitor-bot] room %s connected\n", room_token);
        break;
    case EVERGRAM_VISITOR_STATE_PEER_LEFT:
        printf("[visitor-bot] visitor left room %s (reclaimable until %llu)\n", room_token,
               (unsigned long long)event->deadline_ms);
        break;
    case EVERGRAM_VISITOR_STATE_ENDED:
        printf("[visitor-bot] room %s ended\n", room_token);
        forget_session(app, room_token);
        save_sessions(app);
        break;
    case EVERGRAM_VISITOR_STATE_CLAIMED_ELSEWHERE:
        printf("[visitor-bot] room %s was claimed by another device\n", room_token);
        forget_session(app, room_token);
        save_sessions(app);
        break;
    case EVERGRAM_VISITOR_STATE_KICKED:
        printf("[visitor-bot] removed from room %s (%s)\n", room_token, event->reason);
        forget_session(app, room_token);
        save_sessions(app);
        break;
    }
}

static void on_visitor_timed_out(evergram_bot_t *bot, const char *room_token) {
    app_t *app = app_of(bot);
    printf("[visitor-bot] room %s was never claimed\n", room_token);
    if (app != NULL) {
        forget_session(app, room_token);
        save_sessions(app);
    }
}

static void on_error(evergram_t *eg, evergram_status_t status, const char *detail) {
    (void)eg;
    example_log_error("[visitor-bot]", status, detail);
}

int main(void) {
    app_t app;
    memset(&app, 0, sizeof(app));

    const char *sessions = getenv("EVERGRAM_SESSIONS_FILE");
    app.path = (sessions != NULL && sessions[0] != '\0') ? sessions : "visitor-sessions.txt";

    const char *level = getenv("EVERGRAM_LOG");
    if (level != NULL) {
        evergram_log_set_level(evergram_log_level_from_name(level));
    }

    const evergram_bot_options_t options = {
        .url = example_gateway_url(),
        .identity_path = example_identity_path(),
        .name = "VisitorEchoBot",
        .platform = "Terminal",
        .user_data = &app,
    };

    evergram_bot_t *bot = evergram_bot_create(&options);
    if (bot == NULL) {
        fprintf(stderr, "[visitor-bot] cannot create the bot\n");
        return EXIT_FAILURE;
    }

    evergram_bot_on_visitor_room(bot, on_visitor_room);
    evergram_bot_on_visitor_message(bot, on_visitor_message);
    evergram_bot_on_visitor_state(bot, on_visitor_state);
    evergram_bot_on_visitor_timed_out(bot, on_visitor_timed_out);
    evergram_bot_on_error(bot, on_error);

    load_sessions(bot, &app);

    const char *widget_id = getenv("WIDGET_ID");
    const char *webapp = getenv("EVERGRAM_WEBAPP_URL");
    if (widget_id != NULL) {
        printf("[visitor-bot] open %s/widget/%s to act as the visitor\n",
               webapp != NULL ? webapp : "http://localhost:3000", widget_id);
    }
    printf("[visitor-bot] listening on %s as %s\n", example_gateway_url(),
           evergram_identity_key(evergram_bot_client(bot)));

    int code = example_run(bot);
    evergram_bot_destroy(bot);
    return code;
}
