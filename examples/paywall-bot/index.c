/*
 * paywall-bot — gates membership in a group behind a payment handshake.
 *
 * Port of examples/paywall-bot/index.ts. DM the bot, it quotes a price, you
 * reply with a receipt, it adds you to PAYWALL_CHAT_ID and says so.
 *
 * IMPORTANT: payment_request/payment_receipt are a client-side message
 * convention only. Nothing in the gateway or the contract verifies a receipt's
 * txHash — it is exactly as trustworthy as any other field in a message a peer
 * chose to send. A production paywall must verify the hash against the XRPL or
 * Xahau ledger for the right amount, currency and destination before granting
 * access. This example demonstrates the message plumbing, not verification.
 *
 * Like moderation-bot, it needs admin or moderator rights on the gated chat.
 *
 * Environment:
 *   EVERGRAM_GATEWAY_URL   gateway endpoint   (default ws://localhost:9000/api/ws)
 *   EVERGRAM_IDENTITY_FILE identity path      (default identity.json)
 *   PAYWALL_CHAT_ID        the gated group    (required)
 *   PAYWALL_AMOUNT         price to quote     (default 5)
 *   PAYWALL_CURRENCY       display ticker    (default XAH)
 *   PAYWALL_CURRENCY_ID    currency id       (default XAH)
 */

#include "../_shared/example.h"

#include <string.h>

#define MAX_PAYERS 64

typedef struct {
    char identity[EVERGRAM_IDENTITY_SIZE];
} payer_t;

typedef struct {
    /* Identities whose receipt was accepted. */
    payer_t verified[MAX_PAYERS];
    size_t verified_count;

    /* Identity -> the requestId this bot is currently waiting on. */
    struct {
        char identity[EVERGRAM_IDENTITY_SIZE];
        char request_id[EVERGRAM_REQUEST_ID_SIZE];
    } pending[MAX_PAYERS];
    size_t pending_count;

    char gated_chat[EVERGRAM_CHAT_ID_SIZE];
    const char *amount;
    const char *currency;
    const char *currency_id;
} app_t;

static app_t *app_of(evergram_bot_t *bot) {
    return evergram_bot_user_data(bot);
}

static bool list_has(const payer_t *list, size_t count, const char *identity) {
    for (size_t i = 0; i < count; i++) {
        if (strcmp(list[i].identity, identity) == 0) {
            return true;
        }
    }
    return false;
}

static bool remember_payer(app_t *app, const char *identity) {
    if (list_has(app->verified, app->verified_count, identity)) {
        return true;
    }
    if (app->verified_count == MAX_PAYERS) {
        return false;
    }
    snprintf(app->verified[app->verified_count].identity,
             sizeof(app->verified[app->verified_count].identity), "%s", identity);
    app->verified_count++;
    return true;
}

static const char *pending_request_id(const app_t *app, const char *identity) {
    for (size_t i = 0; i < app->pending_count; i++) {
        if (strcmp(app->pending[i].identity, identity) == 0) {
            return app->pending[i].request_id;
        }
    }
    return NULL;
}

/* Registers the outstanding request before sending, so two messages arriving
 * back to back cannot mint two ids and clobber each other. */
static void remember_pending(app_t *app, const char *identity, const char *request_id) {
    for (size_t i = 0; i < app->pending_count; i++) {
        if (strcmp(app->pending[i].identity, identity) == 0) {
            snprintf(app->pending[i].request_id, sizeof(app->pending[i].request_id), "%s",
                     request_id);
            return;
        }
    }
    if (app->pending_count == MAX_PAYERS) {
        return;
    }
    snprintf(app->pending[app->pending_count].identity,
             sizeof(app->pending[app->pending_count].identity), "%s", identity);
    snprintf(app->pending[app->pending_count].request_id,
             sizeof(app->pending[app->pending_count].request_id), "%s", request_id);
    app->pending_count++;
}

static void forget_pending(app_t *app, const char *identity) {
    for (size_t i = 0; i < app->pending_count; i++) {
        if (strcmp(app->pending[i].identity, identity) == 0) {
            app->pending[i] = app->pending[app->pending_count - 1u];
            app->pending_count--;
            return;
        }
    }
}

/* Quotes the price. Sending is a plain send, so this is safe from a handler. */
static void send_payment_request(evergram_bot_t *bot, app_t *app, const char *chat_id,
                                 const char *sender) {
    evergram_payment_request_t request;
    memset(&request, 0, sizeof(request));
    if (evergram_new_request_id(request.request_id, sizeof(request.request_id)) != EVERGRAM_OK) {
        return;
    }
    snprintf(request.amount, sizeof(request.amount), "%s", app->amount);
    snprintf(request.currency, sizeof(request.currency), "%s", app->currency);
    snprintf(request.currency_id, sizeof(request.currency_id), "%s", app->currency_id);
    snprintf(request.to, sizeof(request.to), "%s", evergram_address(evergram_bot_client(bot)));
    snprintf(request.to_identity_key, sizeof(request.to_identity_key), "%s",
             evergram_identity_key(evergram_bot_client(bot)));

    char payload[EVERGRAM_PAYMENT_CONTENT_SIZE];
    if (evergram_payment_request_build(&request, payload, sizeof(payload)) != EVERGRAM_OK) {
        fprintf(stderr, "[paywall-bot] cannot build the payment request\n");
        return;
    }

    remember_pending(app, sender, request.request_id);
    evergram_status_t status = evergram_send(evergram_bot_client(bot), chat_id, payload);
    if (status != EVERGRAM_OK) {
        example_log_error("[paywall-bot]", status, "cannot send the payment request");
        return;
    }
    printf("[paywall-bot] quoted %s %s to %s (request %s)\n", app->amount, app->currency, sender,
           request.request_id);
}

/* --- message handling ----------------------------------------------------- */

static void handle_receipt(evergram_bot_t *bot, app_t *app, const evergram_message_t *message,
                           const evergram_payment_receipt_t *receipt) {
    const char *sender = message->sender;

    if (list_has(app->verified, app->verified_count, sender)) {
        evergram_bot_reply_with_typing(bot, message, "You're already in, no need to pay again.");
        return;
    }

    bool looks_right = strcmp(receipt->amount, app->amount) == 0 &&
                       strcmp(receipt->currency, app->currency) == 0 &&
                       strcmp(receipt->currency_id, app->currency_id) == 0 &&
                       strcmp(receipt->from_identity_key, sender) == 0;

    /* A strict requestId match is preferred; the loose match covers a bot that
     * restarted since quoting the price and no longer remembers the id. */
    const char *expected = pending_request_id(app, sender);
    bool matches = (expected != NULL && strcmp(receipt->request_id, expected) == 0) ||
                   (expected == NULL && looks_right);
    if (!matches) {
        evergram_bot_reply_with_typing(
            bot, message, "That payment doesn't match an outstanding request. DM me to get a fresh one.");
        return;
    }

    if (!remember_payer(app, sender)) {
        fprintf(stderr, "[paywall-bot] payer table full, cannot record %s\n", sender);
    }
    forget_pending(app, sender);

    /* Queued, not called: granting access is a synchronous request, and this is
     * a handler. The bot layer runs it from evergram_bot_poll(). */
    evergram_status_t status = evergram_bot_add_participant(bot, app->gated_chat, sender);
    if (status != EVERGRAM_OK) {
        example_log_error("[paywall-bot]", status, "cannot grant access");
        return;
    }
    evergram_bot_reply_with_typing(bot, message, "Payment received, you're in!");
}

/* The bot layer forwards client callbacks, so the handler receives the client
 * and recovers the bot from it. */
static void on_message(evergram_t *eg, const evergram_message_t *message) {
    evergram_bot_t *bot = evergram_bot_from_client(eg);
    app_t *app = app_of(bot);
    if (app == NULL || message == NULL) {
        return;
    }

    /* Only react to direct messages, not to chatter inside the gated group. */
    if (strcmp(message->chat_id, app->gated_chat) == 0 || message->text == NULL) {
        return;
    }

    /* Anything that is not a recognizable envelope parses as text, so the only
     * way this fails is a missing output pointer. */
    evergram_content_t content;
    if (evergram_message_content_parse(message->text, &content) != EVERGRAM_OK) {
        return;
    }

    if (content.type == EVERGRAM_CONTENT_PAYMENT_RECEIPT) {
        handle_receipt(bot, app, message, &content.payment_receipt);
        return;
    }

    const char *sender = message->sender;
    if (list_has(app->verified, app->verified_count, sender)) {
        evergram_bot_reply_with_typing(bot, message, "You're already in the group, nothing more to do.");
        return;
    }

    if (pending_request_id(app, sender) != NULL) {
        evergram_bot_reply_with_typing(bot, message, "Still waiting on payment of %s %s. Send the receipt when you're done.",
                                       app->amount, app->currency);
        return;
    }

    send_payment_request(bot, app, message->chat_id, sender);
}

static void on_error(evergram_t *eg, evergram_status_t status, const char *detail) {
    (void)eg;
    example_log_error("[paywall-bot]", status, detail);
}

int main(void) {
    app_t app;
    memset(&app, 0, sizeof(app));

    const char *chat_id = getenv("PAYWALL_CHAT_ID");
    if (chat_id == NULL || chat_id[0] == '\0') {
        fprintf(stderr, "[paywall-bot] PAYWALL_CHAT_ID env var is required\n");
        return EXIT_FAILURE;
    }
    snprintf(app.gated_chat, sizeof(app.gated_chat), "%s", chat_id);
    app.amount = getenv("PAYWALL_AMOUNT");
    app.currency = getenv("PAYWALL_CURRENCY");
    app.currency_id = getenv("PAYWALL_CURRENCY_ID");
    if (app.amount == NULL || app.amount[0] == '\0') {
        app.amount = "5";
    }
    if (app.currency == NULL || app.currency[0] == '\0') {
        app.currency = "XAH";
    }
    if (app.currency_id == NULL || app.currency_id[0] == '\0') {
        app.currency_id = "XAH";
    }

    const char *level = getenv("EVERGRAM_LOG");
    if (level != NULL) {
        evergram_log_set_level(evergram_log_level_from_name(level));
    }

    const evergram_bot_options_t options = {
        .url = example_gateway_url(),
        .identity_path = example_identity_path(),
        .name = "PaywallBot",
        .platform = "Terminal",
        .user_data = &app,
    };

    evergram_bot_t *bot = evergram_bot_create(&options);
    if (bot == NULL) {
        fprintf(stderr, "[paywall-bot] cannot create the bot\n");
        return EXIT_FAILURE;
    }

    evergram_bot_on_message(bot, on_message);
    evergram_bot_on_error(bot, on_error);

    printf("[paywall-bot] gating %s at %s %s\n", app.gated_chat, app.amount, app.currency);
    int code = example_run(bot);
    evergram_bot_destroy(bot);
    return code;
}
