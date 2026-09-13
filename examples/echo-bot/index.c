/*
 * echo-bot — the basics: identity bootstrap, listen, reply.
 *
 * Port of examples/echo-bot/index.ts. Run with:
 *   EVERGRAM_GATEWAY_URL=wss://staging.evergram.app/api/ws \
 *     ./build/bin/echo-bot
 */

#include "../_shared/example.h"

static void on_connected(evergram_t *eg) {
    printf("[echo-bot] online as %s\n", evergram_identity_key(eg));
}

static void on_disconnected(evergram_t *eg) {
    evergram_bot_t *bot = evergram_bot_from_client(eg);
    printf("[echo-bot] disconnected (reconnect attempt %u)\n",
           evergram_bot_reconnect_attempts(bot));
}

static void on_error(evergram_t *eg, evergram_status_t status, const char *detail) {
    (void)eg;
    example_log_error("[echo-bot] error:", status, detail);
}

static void on_message(evergram_t *eg, const evergram_message_t *message) {
    /* Nothing to echo when the body could not be decrypted. */
    if (message->text == NULL || message->text[0] == '\0') {
        return;
    }

    /* Skip audio and payment envelopes: echoing them back makes no sense. */
    if (evergram_message_content_type(message->text) != EVERGRAM_CONTENT_TEXT) {
        printf("[echo-bot] skipping a non-text message from %s\n", message->sender);
        return;
    }

    printf("[echo-bot] %s -> %s\n", message->sender, message->text);

    evergram_bot_t *bot = evergram_bot_from_client(eg);
    evergram_status_t status = evergram_bot_reply_with_typing(bot, message, "Echo: %s",
                                                              message->text);
    if (status != EVERGRAM_OK) {
        example_log_error("[echo-bot] reply failed:", status, NULL);
    }
}

int main(void) {
    const evergram_bot_options_t options = {
        .url = example_gateway_url(),
        .identity_path = example_identity_path(),
        .name = "EchoBot :)",
        .platform = "Terminal",
    };

    evergram_bot_t *bot = evergram_bot_create(&options);
    if (bot == NULL) {
        fprintf(stderr, "[echo-bot] cannot create the bot\n");
        return 1;
    }

    evergram_bot_on_connected(bot, on_connected);
    evergram_bot_on_disconnected(bot, on_disconnected);
    evergram_bot_on_error(bot, on_error);
    evergram_bot_on_message(bot, on_message);

    printf("[echo-bot] gateway: %s\n", options.url);
    printf("[echo-bot] identity: %s\n", options.identity_path);

    int exit_code = example_run(bot);

    evergram_bot_destroy(bot);
    return exit_code;
}
