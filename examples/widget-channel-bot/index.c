/*
 * widget-channel-bot — a bot inside a widget's public_group channel.
 *
 * Port of examples/widget-channel-bot/index.ts. Unlike widget-visitor-bot,
 * which reacts to 1:1 rooms as visitors open them, a channel is joined
 * explicitly with evergram_visitor_subscribe_channel() and is shared by every
 * visitor connected to the widget. The bot is auto-opped by the gateway, so it
 * can moderate, and it answers a small slash-command surface:
 *
 *   /kick <name>   /ban <name>     /unban <name>
 *   /op <name>     /deop <name>    /voice <name>   /devoice <name>
 *   /mod           /unmod
 *
 * Anything else is echoed.
 *
 * Environment:
 *   EVERGRAM_GATEWAY_URL   gateway endpoint    (default ws://localhost:9000/api/ws)
 *   EVERGRAM_IDENTITY_FILE identity path       (default identity.json)
 *   EVERGRAM_WIDGET_ID     widget to join      (default: the first live one)
 *   EVERGRAM_CHANNEL_KEY   64 hex chars        (default: the widget's stored key)
 *   EVERGRAM_NICKNAME      roster name         (default "Widget Group Bot")
 *
 * Like the TypeScript example, this one finds its own widget: it lists the
 * widgets this identity owns and, if the chosen one is not already a
 * public_group channel, switches it to one with a freshly generated channel
 * key. The environment variables are a shortcut for running against a specific
 * widget, not a requirement.
 */

#include "../_shared/example.h"

#include <string.h>

typedef struct {
    /* A moderation request is a synchronous call, which a callback must not
     * start (it would re-enter the socket loop), so a command from a handler is
     * queued here and executed from the loop, outside any callback. */
    bool pending;
    evergram_visitor_handle_t handle;
    evergram_moderation_action_t action;
    char target[EVERGRAM_NICKNAME_SIZE];
    bool report_failure;

    evergram_visitor_handle_t channel;
    bool has_channel;
    bool subscribe_requested;
    char widget_id[EVERGRAM_WIDGET_ID_SIZE];
    char key[EVERGRAM_CHANNEL_KEY_SIZE];
    const char *channel_key; /* from the environment, when given */
    const char *widget_name;
    const char *nickname;
} app_t;

static app_t *app_of(evergram_bot_t *bot) {
    return evergram_bot_user_data(bot);
}

static void print_roster(const char *room_token) {
    printf("[channel-bot] room %s\n", room_token);
}

/* --- finding the widget --------------------------------------------------- */

/*
 * Picks the widget to join and makes sure it is a public_group channel with a
 * key, mirroring the settings page's own "generate a key the first time you
 * switch to Public Channel" behaviour.
 */
static bool resolve_widget(evergram_bot_t *bot, app_t *app) {
    evergram_t *client = evergram_bot_client(bot);
    static evergram_widget_t widgets[32];
    size_t count = 0;

    evergram_status_t status = evergram_widget_list(client, 35000, widgets, 32, &count);
    if (status != EVERGRAM_OK) {
        example_log_error("[channel-bot]", status, "cannot list widgets");
        return false;
    }

    evergram_widget_t *chosen = NULL;
    for (size_t i = 0; i < count; i++) {
        if (widgets[i].deleted) {
            continue;
        }
        if (app->widget_id[0] != '\0' &&
            strcmp(widgets[i].widget_id, app->widget_id) != 0) {
            continue;
        }
        chosen = &widgets[i];
        break;
    }
    if (chosen == NULL) {
        fprintf(stderr,
                "[channel-bot] no usable widget found. Create one at the web app, or pass "
                "EVERGRAM_WIDGET_ID.\n");
        return false;
    }
    app->widget_name = chosen->name;
    /* Both are bounded arrays of the same size, so this copy cannot truncate. */
    memcpy(app->widget_id, chosen->widget_id, sizeof(app->widget_id));
    app->widget_id[sizeof(app->widget_id) - 1u] = '\0';

    /* Reuse the stored key when the widget is already a channel. */
    if (app->channel_key != NULL && strlen(app->channel_key) == 2u * EVERGRAM_SYM_KEY_SIZE) {
        /* Length checked above, so the copy is exact and cannot truncate. */
        memcpy(app->key, app->channel_key, EVERGRAM_CHANNEL_KEY_SIZE);
        return true;
    }
    if (chosen->has_config && chosen->config.has_mode &&
        strcmp(chosen->config.mode, EVERGRAM_WIDGET_MODE_PUBLIC_GROUP) == 0 &&
        chosen->config.has_channel_key &&
        strlen(chosen->config.channel_key) == 2u * EVERGRAM_SYM_KEY_SIZE) {
        memcpy(app->key, chosen->config.channel_key, EVERGRAM_CHANNEL_KEY_SIZE);
        return true;
    }

    if (evergram_random_bytes((uint8_t *)app->key, EVERGRAM_SYM_KEY_SIZE) != EVERGRAM_OK) {
        return false;
    }
    /* The bytes above are raw; the key travels as hex. */
    {
        static const char digits[] = "0123456789abcdef";
        for (size_t i = EVERGRAM_SYM_KEY_SIZE; i-- > 0;) {
            uint8_t byte = (uint8_t)app->key[i];
            app->key[2u * i] = digits[byte >> 4];
            app->key[2u * i + 1u] = digits[byte & 0x0f];
        }
        app->key[2u * EVERGRAM_SYM_KEY_SIZE] = '\0';
    }

    evergram_widget_config_t config = chosen->has_config ? chosen->config
                                                        : (evergram_widget_config_t){0};
    config.has_mode = true;
    snprintf(config.mode, sizeof(config.mode), "%s", EVERGRAM_WIDGET_MODE_PUBLIC_GROUP);
    config.has_channel_key = true;
    memcpy(config.channel_key, app->key, sizeof(config.channel_key));

    status = evergram_widget_set_config(client, chosen->widget_id, &config, 35000);
    if (status != EVERGRAM_OK) {
        example_log_error("[channel-bot]", status, "cannot switch the widget to public_group");
        return false;
    }
    printf("[channel-bot] widget \"%s\" switched to public_group with a fresh channel key\n",
           chosen->name);
    return true;
}

/* --- joining -------------------------------------------------------------- */

static bool subscribe(evergram_bot_t *bot, app_t *app) {
    evergram_visitor_room_t room;
    evergram_status_t status = evergram_visitor_subscribe_channel(
        evergram_bot_client(bot), app->widget_id, app->key, 10000, &room);
    if (status != EVERGRAM_OK) {
        example_log_error("[channel-bot]", status, "cannot subscribe to the channel");
        return false;
    }

    app->channel = (evergram_visitor_handle_t){0};
    snprintf(app->channel.room_token, sizeof(app->channel.room_token), "%s", room.room_token);
    snprintf(app->channel.widget_id, sizeof(app->channel.widget_id), "%s", app->widget_id);
    printf("[channel-bot] joined the channel for \"%s\"\n",
           app->widget_name != NULL ? app->widget_name : app->widget_id);
    app->has_channel = true;
    app->subscribe_requested = false;
    print_roster(room.room_token);

    /* Announcing is what puts this bot on the channel roster; the gateway
     * auto-ops it, but the roster only knows names that were announced. */
    status = evergram_visitor_announce_presence(evergram_bot_client(bot), room.room_token,
                                                app->nickname, NULL);
    if (status != EVERGRAM_OK) {
        example_log_error("[channel-bot]", status, "cannot announce presence");
        return false;
    }
    return true;
}

/* --- handlers ------------------------------------------------------------- */

static void on_connected(evergram_t *eg) {
    evergram_bot_t *bot = evergram_bot_from_client(eg);
    app_t *app = app_of(bot);
    if (app == NULL) {
        return;
    }

    /* A channel subscription is not a slot the client re-claims on its own
     * (only a fresh subscribe rejoins a channel), so a reconnect schedules one
     * instead of calling it here: subscribing blocks, and this is a callback. */
    app->has_channel = false;
    app->subscribe_requested = true;
}

static void on_visitor_message(evergram_bot_t *bot, const char *room_token,
                               const evergram_visitor_handle_t *handle,
                               const evergram_relay_text_t *event) {
    app_t *app = app_of(bot);
    if (app == NULL || handle == NULL) {
        printf("[channel-bot] message for room %s is no longer ours\n", room_token);
        return;
    }

    printf("[channel-bot] %s -> %s\n", event->sender[0] != '\0' ? event->sender : "(unknown)",
           event->text);

    /* Splits "<command> <target>" without allocating. */
    char command[32] = {0};
    char target[EVERGRAM_NICKNAME_SIZE] = {0};
    const char *cursor = event->text;
    while (*cursor == ' ') {
        cursor++;
    }
    size_t used = 0;
    while (*cursor != '\0' && *cursor != ' ' && used + 1u < sizeof(command)) {
        command[used++] = *cursor++;
    }
    while (*cursor == ' ') {
        cursor++;
    }
    used = 0;
    while (*cursor != '\0' && used + 1u < sizeof(target)) {
        target[used++] = *cursor++;
    }

    static const struct {
        const char *name;
        evergram_moderation_action_t action;
        bool needs_target;
    } commands[] = {
        {"/kick", EVERGRAM_MODERATION_KICK, true},
        {"/ban", EVERGRAM_MODERATION_BAN, true},
        {"/unban", EVERGRAM_MODERATION_UNBAN, true},
        {"/op", EVERGRAM_MODERATION_GRANT_OP, true},
        {"/deop", EVERGRAM_MODERATION_REVOKE_OP, true},
        {"/voice", EVERGRAM_MODERATION_GRANT_VOICE, true},
        {"/devoice", EVERGRAM_MODERATION_REVOKE_VOICE, true},
        {"/mod", EVERGRAM_MODERATION_SET_MODERATED, false},
        {"/unmod", EVERGRAM_MODERATION_UNSET_MODERATED, false},
    };

    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
        if (strcmp(command, commands[i].name) != 0) {
            continue;
        }
        if (commands[i].needs_target && target[0] == '\0') {
            evergram_bot_visitor_reply_with_typing(bot, handle, "Usage: %s <name>",
                                                   commands[i].name);
            return;
        }

        /* Queued, not executed: see the comment on app_t.pending. */
        app->pending = true;
        app->handle = *handle;
        app->action = commands[i].action;
        app->report_failure = commands[i].needs_target;
        snprintf(app->target, sizeof(app->target), "%s", target);
        return;
    }

    evergram_status_t status = evergram_bot_visitor_reply_with_typing(bot, handle, "Echo: %s",
                                                                      event->text);
    if (status != EVERGRAM_OK) {
        example_log_error("[channel-bot]", status, "cannot reply");
    }
}

static void on_visitor_presence(evergram_t *eg, const char *room_token,
                                const evergram_relay_presence_t *event, bool joined) {
    (void)eg;
    (void)room_token;
    if (joined) {
        if (event->has_previous) {
            printf("[channel-bot] %s is now %s\n", event->previous_sender, event->sender);
        } else {
            printf("[channel-bot] %s joined the channel\n", event->sender);
        }
    } else {
        printf("[channel-bot] %s left the channel\n", event->sender);
    }
}

static void on_visitor_moderation(evergram_t *eg, const char *room_token,
                                  const evergram_relay_moderation_t *state) {
    (void)eg;
    (void)room_token;
    printf("[channel-bot] mode: moderated=%s ops=[", state->moderated ? "true" : "false");
    for (size_t i = 0; i < state->ops_count; i++) {
        printf("%s%s", i > 0 ? ", " : "", state->ops[i] != NULL ? state->ops[i] : "");
    }
    printf("] voiced=[");
    for (size_t i = 0; i < state->voiced_count; i++) {
        printf("%s%s", i > 0 ? ", " : "", state->voiced[i] != NULL ? state->voiced[i] : "");
    }
    printf("]\n");
}

static void on_visitor_state(evergram_bot_t *bot, const char *room_token,
                             const evergram_visitor_handle_t *handle,
                             const evergram_visitor_state_event_t *event) {
    app_t *app = app_of(bot);
    (void)handle;
    if (app == NULL || event == NULL) {
        return;
    }

    switch (event->state) {
    case EVERGRAM_VISITOR_STATE_KICKED:
        printf("[channel-bot] this bot was %s; subscription ended\n", event->reason);
        app->has_channel = false;
        break;
    case EVERGRAM_VISITOR_STATE_ENDED:
    case EVERGRAM_VISITOR_STATE_CLAIMED_ELSEWHERE:
        printf("[channel-bot] subscription to %s ended\n", room_token);
        app->has_channel = false;
        break;
    case EVERGRAM_VISITOR_STATE_PEER_LEFT:
        break; /* a 1:1 concept; a channel does not use it */
    case EVERGRAM_VISITOR_STATE_CONNECTED:
        printf("[channel-bot] channel %s is open\n", room_token);
        break;
    }
}

static void on_error(evergram_t *eg, evergram_status_t status, const char *detail) {
    (void)eg;
    example_log_error("[channel-bot]", status, detail);
}

/* --- loop ----------------------------------------------------------------- */

/* Runs one queued moderation outside any callback, reporting a refusal. */
static void run_pending(evergram_bot_t *bot, app_t *app) {
    if (!app->pending) {
        return;
    }
    app->pending = false;

    evergram_status_t status = evergram_visitor_moderate_channel(
        evergram_bot_client(bot), app->handle.room_token, app->action,
        app->target[0] != '\0' ? app->target : NULL, 10000);
    if (status != EVERGRAM_OK && app->report_failure) {
        evergram_bot_visitor_reply_with_typing(
            bot, &app->handle,
            "Couldn't %s %s. Are they in the channel and are you an op?", app->target,
            evergram_status_str(status));
    }
}

int main(void) {
    app_t app;
    memset(&app, 0, sizeof(app));

    const char *widget_id = getenv("EVERGRAM_WIDGET_ID");
    if (widget_id != NULL && widget_id[0] != '\0') {
        snprintf(app.widget_id, sizeof(app.widget_id), "%s", widget_id);
    }
    app.channel_key = getenv("EVERGRAM_CHANNEL_KEY");
    app.nickname = getenv("EVERGRAM_NICKNAME");
    if (app.nickname == NULL || app.nickname[0] == '\0') {
        app.nickname = "Widget Group Bot";
    }

    const char *level = getenv("EVERGRAM_LOG");
    if (level != NULL) {
        evergram_log_set_level(evergram_log_level_from_name(level));
    }

    const evergram_bot_options_t options = {
        .url = example_gateway_url(),
        .identity_path = example_identity_path(),
        .name = app.nickname,
        .platform = "Terminal",
        .user_data = &app,
    };

    evergram_bot_t *bot = evergram_bot_create(&options);
    if (bot == NULL) {
        fprintf(stderr, "[channel-bot] cannot create the bot\n");
        return EXIT_FAILURE;
    }

    evergram_bot_on_connected(bot, on_connected);
    evergram_bot_on_visitor_message(bot, on_visitor_message);
    evergram_bot_on_visitor_state(bot, on_visitor_state);
    evergram_bot_on_error(bot, on_error);
    evergram_on_visitor_presence(evergram_bot_client(bot), on_visitor_presence);
    evergram_on_visitor_moderation(evergram_bot_client(bot), on_visitor_moderation);

    signal(SIGINT, example_handle_signal);
    signal(SIGTERM, example_handle_signal);

    evergram_status_t status = evergram_bot_start(bot);
    if (status != EVERGRAM_OK) {
        example_log_error("[channel-bot]", status, "cannot connect");
        evergram_bot_destroy(bot);
        return EXIT_FAILURE;
    }

    printf("[channel-bot] listening on %s as %s\n", example_gateway_url(),
           evergram_identity_key(evergram_bot_client(bot)));

    while (example_running) {
        status = evergram_bot_poll(bot, 100);
        if (status != EVERGRAM_OK && status != EVERGRAM_ERR_TIMEOUT &&
            status != EVERGRAM_ERR_NOT_CONNECTED) {
            example_log_error("[channel-bot]", status, "poll failed");
            evergram_bot_destroy(bot);
            return EXIT_FAILURE;
        }

        if (app.subscribe_requested && evergram_bot_is_online(bot)) {
            /* Resolved once, then re-used on every reconnect (the room token
             * changes, the widget and key do not). */
            if (app.widget_id[0] == '\0' || app.key[0] == '\0') {
                if (!resolve_widget(bot, &app)) {
                    app.subscribe_requested = false;
                    break;
                }
            }
            if (!subscribe(bot, &app)) {
                app.subscribe_requested = false;
            }
        }
        run_pending(bot, &app);
    }

    evergram_bot_destroy(bot);
    return EXIT_SUCCESS;
}
