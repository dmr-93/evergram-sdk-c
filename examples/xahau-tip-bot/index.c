/*
 * xahau-tip-bot — tips XAH to people in chat.
 *
 * Port of examples/xahau-tip-bot/index.ts. Commands:
 *   !tip <amount> [XAH]              tip the author of the message you replied to
 *   !tip @<identityKey> <amount>     tip a mentioned identity
 *   !tip <address> <amount>          tip a raw ledger address
 *   !balance                         show how much this bot can still tip
 *   !help                            this list
 *
 * IMPORTANT: the bot's chat identity and its funding wallet are the same key —
 * the seed in the identity file signs both. Losing that file loses the funds,
 * and every !tip is a real, immediate payment with no confirmation step.
 *
 * Environment:
 *   EVERGRAM_GATEWAY_URL   gateway endpoint   (default ws://localhost:9000/api/ws)
 *   EVERGRAM_IDENTITY_FILE identity path      (default identity.json)
 *   XAHAU_RPC_URL          ledger endpoint    (default ws://localhost:16003)
 *   TIPBOT_MAX_TIP         cap per tip, in XAH (default: no cap)
 *   TIPBOT_TIPS_FILE       idempotency log    (default xahau-tips.txt)
 *
 * Ledger calls block, so they never run inside a message handler: commands are
 * queued and served one per poll round. The idempotency log is what makes a
 * redelivered message harmless — without it, the mailbox replaying a !tip after
 * a restart would pay twice.
 */

#include "../_shared/example.h"
#include "commands.h"
#include "xahau_rpc.h"
#include "xahau_tx.h"

#include <stdarg.h>
#include <string.h>

#define QUEUE_MAX 32
#define TRACKED_MESSAGES 256
#define IDEMPOTENCY_MAX 2000
#define REPLY_MAX 1024
#define AMOUNT_MAX 64

typedef struct {
    char chat_id[EVERGRAM_CHAT_ID_SIZE];
    char sender[EVERGRAM_IDENTITY_SIZE];
    char message_id[EVERGRAM_MESSAGE_ID_SIZE];
    char reply_to[EVERGRAM_MESSAGE_ID_SIZE];
    char text[512];
} command_t;

typedef struct {
    char message_id[EVERGRAM_MESSAGE_ID_SIZE];
    char sender[EVERGRAM_IDENTITY_SIZE];
} tracked_t;

typedef struct {
    char message_id[EVERGRAM_MESSAGE_ID_SIZE];
    char tx_hash[XAHAU_HASH_HEX_SIZE];
} processed_t;

typedef struct {
    command_t queue[QUEUE_MAX];
    size_t queue_head;
    size_t queue_count;

    /* msgId -> sender, so "!tip 5" can find the author of the replied-to message. */
    tracked_t tracked[TRACKED_MESSAGES];
    size_t tracked_count;

    processed_t processed[IDEMPOTENCY_MAX];
    size_t processed_count;

    xahau_rpc_t *rpc;
    /* The identity's keypair, kept here because it signs ledger transactions as
     * well as chat authentication. */
    evergram_wallet_t wallet;
    const char *rpc_url;
    const char *tips_path;
    char max_tip_drops[AMOUNT_MAX]; /* empty = no cap */
    unsigned tipped;
} app_t;

static app_t *app_of(evergram_bot_t *bot) {
    return evergram_bot_user_data(bot);
}

/* --- small helpers -------------------------------------------------------- */

static void format_drops(const char *drops, char *out, size_t out_size) {
    /* Drops to XAH with six decimals, without floating point. */
    unsigned long long value = strtoull(drops, NULL, 10);
    snprintf(out, out_size, "%llu.%06llu", value / 1000000ull, value % 1000000ull);
}

static void track_message(app_t *app, const char *message_id, const char *sender) {
    if (message_id[0] == '\0') {
        return;
    }
    for (size_t i = 0; i < app->tracked_count; i++) {
        if (strcmp(app->tracked[i].message_id, message_id) == 0) {
            snprintf(app->tracked[i].sender, sizeof(app->tracked[i].sender), "%s", sender);
            return;
        }
    }
    if (app->tracked_count == TRACKED_MESSAGES) {
        /* Oldest out, like the reference SDK's bounded map. */
        memmove(&app->tracked[0], &app->tracked[1],
                (TRACKED_MESSAGES - 1u) * sizeof(app->tracked[0]));
        app->tracked_count--;
    }
    snprintf(app->tracked[app->tracked_count].message_id,
             sizeof(app->tracked[app->tracked_count].message_id), "%s", message_id);
    snprintf(app->tracked[app->tracked_count].sender,
             sizeof(app->tracked[app->tracked_count].sender), "%s", sender);
    app->tracked_count++;
}

static const char *sender_of(app_t *app, const char *message_id) {
    if (message_id[0] == '\0') {
        return NULL;
    }
    for (size_t i = 0; i < app->tracked_count; i++) {
        if (strcmp(app->tracked[i].message_id, message_id) == 0) {
            return app->tracked[i].sender;
        }
    }
    return NULL;
}

static bool already_processed(app_t *app, const char *message_id) {
    for (size_t i = 0; i < app->processed_count; i++) {
        if (strcmp(app->processed[i].message_id, message_id) == 0) {
            return true;
        }
    }
    return false;
}

/* Read-modify-write, like the reference example: fine for a personal tip bot,
 * not a pattern for high volume. */
static void load_processed(app_t *app) {
    FILE *file = fopen(app->tips_path, "r");
    if (file == NULL) {
        return;
    }
    char line[512];
    while (fgets(line, sizeof(line), file) != NULL && app->processed_count < IDEMPOTENCY_MAX) {
        line[strcspn(line, "\r\n")] = '\0';
        char *separator = strchr(line, '|');
        if (separator == NULL) {
            continue;
        }
        *separator++ = '\0';

        /* A line longer than either field is corrupt input, not something to
         * silently shorten: skip it and let the entry be reprocessed. */
        processed_t *entry = &app->processed[app->processed_count];
        if (strlen(line) >= sizeof(entry->message_id) ||
            strlen(separator) >= sizeof(entry->tx_hash)) {
            fprintf(stderr, "[xahau-tip-bot] ignoring a malformed line in %s\n", app->tips_path);
            continue;
        }
        memcpy(entry->message_id, line, strlen(line) + 1u);
        memcpy(entry->tx_hash, separator, strlen(separator) + 1u);
        app->processed_count++;
    }
    fclose(file);
}

static void record_processed(app_t *app, const char *message_id, const char *tx_hash) {
    if (app->processed_count == IDEMPOTENCY_MAX) {
        /* Drop the oldest rather than grow the file forever. */
        memmove(&app->processed[0], &app->processed[1],
                (IDEMPOTENCY_MAX - 1u) * sizeof(app->processed[0]));
        app->processed_count--;
    }
    snprintf(app->processed[app->processed_count].message_id,
             sizeof(app->processed[app->processed_count].message_id), "%s", message_id);
    snprintf(app->processed[app->processed_count].tx_hash,
             sizeof(app->processed[app->processed_count].tx_hash), "%s", tx_hash);
    app->processed_count++;

    FILE *file = fopen(app->tips_path, "a");
    if (file == NULL) {
        fprintf(stderr, "[xahau-tip-bot] cannot append to %s\n", app->tips_path);
        return;
    }
    fprintf(file, "%s|%s\n", message_id, tx_hash);
    fclose(file);
}

/* --- replies -------------------------------------------------------------- */

/* A reply needs only the chat, so a message is reconstructed from the queue. */
static void reply(evergram_bot_t *bot, const command_t *command, const char *format, ...) {
    char text[REPLY_MAX];
    va_list args;
    va_start(args, format);
    vsnprintf(text, sizeof(text), format, args);
    va_end(args);

    evergram_message_t target;
    memset(&target, 0, sizeof(target));
    snprintf(target.chat_id, sizeof(target.chat_id), "%s", command->chat_id);
    snprintf(target.message_id, sizeof(target.message_id), "%s", command->message_id);
    snprintf(target.sender, sizeof(target.sender), "%s", command->sender);

    evergram_status_t status = evergram_bot_reply_with_typing(bot, &target, "%s", text);
    if (status != EVERGRAM_OK) {
        example_log_error("[xahau-tip-bot]", status, "cannot reply");
    }
}

/* --- commands ------------------------------------------------------------- */

static evergram_status_t ensure_rpc(app_t *app) {
    if (app->rpc != NULL) {
        return EVERGRAM_OK;
    }
    app->rpc = xahau_rpc_create(app->rpc_url, 15000);
    if (app->rpc == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    return EVERGRAM_OK;
}

static void handle_help(evergram_bot_t *bot, const command_t *command) {
    reply(bot, command,
          "Commands:\n"
          "!tip <amount> [XAH] — tip the author of the message you replied to\n"
          "!tip @<identityKey> <amount> [XAH]\n"
          "!tip <address> <amount> [XAH]\n"
          "!balance — how much this bot can still tip");
}

static void handle_balance(evergram_bot_t *bot, app_t *app, const command_t *command) {
    if (ensure_rpc(app) != EVERGRAM_OK) {
        reply(bot, command, "The ledger is not reachable right now.");
        return;
    }

    xahau_account_t account;
    evergram_status_t status = xahau_rpc_account_info(app->rpc, evergram_address(
                                                                     evergram_bot_client(bot)),
                                                      &account);
    if (status == EVERGRAM_ERR_STATE) {
        /* No ledger entry yet: funded below the reserve, or never funded. */
        reply(bot, command, "This bot's wallet has not received any XAH yet.");
        return;
    }
    if (status != EVERGRAM_OK) {
        example_log_error("[xahau-tip-bot]", status, xahau_rpc_last_error(app->rpc));
        reply(bot, command, "The ledger did not answer.");
        return;
    }

    xahau_reserves_t reserves;
    uint64_t spendable = account.balance_drops;
    if (xahau_rpc_reserves(app->rpc, &reserves) == EVERGRAM_OK) {
        uint64_t reserved = reserves.reserve_base_drops +
                            account.owner_count * reserves.reserve_inc_drops;
        spendable = account.balance_drops > reserved ? account.balance_drops - reserved : 0;
    }

    char balance[AMOUNT_MAX];
    char balance_xah[AMOUNT_MAX];
    snprintf(balance, sizeof(balance), "%llu", (unsigned long long)spendable);
    format_drops(balance, balance_xah, sizeof(balance_xah));
    reply(bot, command, "Available to tip: %s XAH", balance_xah);
}

static void handle_tip(evergram_bot_t *bot, app_t *app, const command_t *command) {
    const char *reply_sender = sender_of(app, command->reply_to);
    tip_command_t tip;
    char error[256];
    if (tip_parse(command->text, reply_sender, &tip, error, sizeof(error)) != EVERGRAM_OK) {
        reply(bot, command, "%s", error);
        return;
    }

    if (strcmp(tip.currency, "XAH") != 0) {
        reply(bot, command, "Only XAH tips are supported.");
        return;
    }

    char address[EVERGRAM_ADDRESS_SIZE];
    if (tip.target_kind == TIP_TARGET_ADDRESS) {
        snprintf(address, sizeof(address), "%s", tip.address);
    } else if (!tip_address_from_identity(tip.identity_key, address, sizeof(address))) {
        reply(bot, command, "That identity cannot receive XAH.");
        return;
    }

    char drops[AMOUNT_MAX];
    if (tip_amount_to_drops(tip.amount, drops, sizeof(drops)) != EVERGRAM_OK) {
        reply(bot, command, "That amount is not valid.");
        return;
    }
    if (app->max_tip_drops[0] != '\0' &&
        strtoull(drops, NULL, 10) > strtoull(app->max_tip_drops, NULL, 10)) {
        char limit[AMOUNT_MAX];
        format_drops(app->max_tip_drops, limit, sizeof(limit));
        reply(bot, command, "That is over this bot's per-tip limit of %s XAH.", limit);
        return;
    }

    /* A message this bot already paid for is never paid again: the mailbox can
     * redeliver it after a restart, and a payment is not idempotent by itself. */
    if (already_processed(app, command->message_id)) {
        reply(bot, command, "That tip was already sent.");
        return;
    }

    if (ensure_rpc(app) != EVERGRAM_OK) {
        reply(bot, command, "The ledger is not reachable right now.");
        return;
    }

    evergram_t *client = evergram_bot_client(bot);
    xahau_account_t account;
    evergram_status_t status = xahau_rpc_account_info(app->rpc, evergram_address(client), &account);
    if (status == EVERGRAM_ERR_STATE) {
        reply(bot, command, "This bot's wallet has not received any XAH yet.");
        return;
    }
    if (status != EVERGRAM_OK) {
        example_log_error("[xahau-tip-bot]", status, xahau_rpc_last_error(app->rpc));
        reply(bot, command, "The ledger did not answer.");
        return;
    }

    xahau_network_t network;
    if (xahau_rpc_network(app->rpc, &network) != EVERGRAM_OK) {
        reply(bot, command, "The ledger did not report its state.");
        return;
    }

    xahau_payment_t payment;
    memset(&payment, 0, sizeof(payment));
    payment.account = evergram_address(client);
    payment.destination = address;
    payment.amount_drops = drops;
    payment.fee_drops = "12";
    payment.sequence = account.sequence;
    payment.last_ledger_sequence = network.ledger_index + 5;
    payment.has_network_id = network.network_id > 1024u;
    payment.network_id = network.network_id;

    char blob[XAHAU_BLOB_MAX];
    char hash[XAHAU_HASH_HEX_SIZE];
    /* The bot's chat identity and its funding key are the same keypair, so the
     * identity file is also the wallet that signs ledger transactions. */
    evergram_wallet_t wallet = app->wallet;
    status = xahau_sign_payment(wallet.private_key_hex, &payment, NULL, 0, blob, sizeof(blob),
                                hash, sizeof(hash));
    if (status != EVERGRAM_OK) {
        reply(bot, command, "Could not build the payment.");
        return;
    }

    char engine_result[64];
    status = xahau_rpc_submit(app->rpc, blob, engine_result, sizeof(engine_result));
    if (status != EVERGRAM_OK) {
        example_log_error("[xahau-tip-bot]", status, xahau_rpc_last_error(app->rpc));
        reply(bot, command, "The ledger refused the payment.");
        return;
    }

    /* Recorded before announcing: a crash after this point must not pay twice,
     * and the hash is the only thing a user can use to look the payment up. */
    record_processed(app, command->message_id, hash);
    app->tipped++;

    char amount_xah[AMOUNT_MAX];
    format_drops(drops, amount_xah, sizeof(amount_xah));
    reply(bot, command, "Sent %s XAH (%s). Tx: %s", amount_xah, engine_result, hash);
}

/* --- queue ---------------------------------------------------------------- */

static void enqueue(app_t *app, const evergram_message_t *message) {
    if (app->queue_count == QUEUE_MAX) {
        fprintf(stderr, "[xahau-tip-bot] command queue full, ignoring a command\n");
        return;
    }
    size_t slot = (app->queue_head + app->queue_count) % QUEUE_MAX;
    command_t *command = &app->queue[slot];
    memset(command, 0, sizeof(*command));
    snprintf(command->chat_id, sizeof(command->chat_id), "%s", message->chat_id);
    snprintf(command->sender, sizeof(command->sender), "%s", message->sender);
    snprintf(command->message_id, sizeof(command->message_id), "%s", message->message_id);
    snprintf(command->reply_to, sizeof(command->reply_to), "%s",
             message->reply_to_message_id != NULL ? message->reply_to_message_id : "");
    snprintf(command->text, sizeof(command->text), "%s",
             message->text != NULL ? message->text : "");
    app->queue_count++;
}

/* One command per round, outside any callback. */
static void run_one(evergram_bot_t *bot, app_t *app) {
    if (app->queue_count == 0) {
        return;
    }
    command_t command = app->queue[app->queue_head];
    app->queue_head = (app->queue_head + 1u) % QUEUE_MAX;
    app->queue_count--;

    if (strncmp(command.text, "!tip", 4) == 0) {
        handle_tip(bot, app, &command);
    } else if (strncmp(command.text, "!balance", 8) == 0) {
        handle_balance(bot, app, &command);
    } else if (strncmp(command.text, "!help", 5) == 0) {
        handle_help(bot, &command);
    }
}

/* --- handlers ------------------------------------------------------------- */

static void on_message(evergram_t *eg, const evergram_message_t *message) {
    evergram_bot_t *bot = evergram_bot_from_client(eg);
    app_t *app = app_of(bot);
    if (app == NULL || message == NULL || message->text == NULL) {
        return;
    }

    /* Every message is remembered, so a later reply-to-tip can find its author. */
    track_message(app, message->message_id, message->sender);

    if (message->text[0] == '!') {
        enqueue(app, message);
    }
}

static void on_error(evergram_t *eg, evergram_status_t status, const char *detail) {
    (void)eg;
    example_log_error("[xahau-tip-bot]", status, detail);
}

int main(void) {
    app_t app;
    memset(&app, 0, sizeof(app));

    app.rpc_url = getenv("XAHAU_RPC_URL");
    if (app.rpc_url == NULL || app.rpc_url[0] == '\0') {
        app.rpc_url = "ws://localhost:16003";
    }
    app.tips_path = getenv("TIPBOT_TIPS_FILE");
    if (app.tips_path == NULL || app.tips_path[0] == '\0') {
        app.tips_path = "xahau-tips.txt";
    }

    const char *max_tip = getenv("TIPBOT_MAX_TIP");
    if (max_tip != NULL && max_tip[0] != '\0') {
        if (tip_amount_to_drops(max_tip, app.max_tip_drops, sizeof(app.max_tip_drops)) !=
            EVERGRAM_OK) {
            fprintf(stderr, "[xahau-tip-bot] TIPBOT_MAX_TIP is not a valid amount\n");
            return EXIT_FAILURE;
        }
    }

    const char *level = getenv("EVERGRAM_LOG");
    if (level != NULL) {
        evergram_log_set_level(evergram_log_level_from_name(level));
    }

    load_processed(&app);

    const evergram_bot_options_t options = {
        .url = example_gateway_url(),
        .identity_path = example_identity_path(),
        .name = "XahauTipBot",
        .platform = "Terminal",
        .user_data = &app,
    };

    evergram_bot_t *bot = evergram_bot_create(&options);
    if (bot == NULL) {
        fprintf(stderr, "[xahau-tip-bot] cannot create the bot\n");
        return EXIT_FAILURE;
    }

    evergram_bot_on_message(bot, on_message);
    evergram_bot_on_error(bot, on_error);

    signal(SIGINT, example_handle_signal);
    signal(SIGTERM, example_handle_signal);

    evergram_status_t status = evergram_bot_start(bot);
    if (status != EVERGRAM_OK) {
        example_log_error("[xahau-tip-bot]", status, "cannot connect");
        evergram_bot_destroy(bot);
        return EXIT_FAILURE;
    }

    /* Loaded after start(), because that is when the bot has made sure the file
     * exists (generating one on first run). */
    evergram_device_t device;
    memset(&device, 0, sizeof(device));
    if (evergram_identity_load(example_identity_path(), &app.wallet, &device) != EVERGRAM_OK) {
        fprintf(stderr, "[xahau-tip-bot] cannot read the identity; tips would have no key\n");
        evergram_bot_destroy(bot);
        return EXIT_FAILURE;
    }
    evergram_device_wipe(&device);

    printf("[xahau-tip-bot] online as %s (funding address %s), ledger %s\n",
           evergram_identity_key(evergram_bot_client(bot)), evergram_address(evergram_bot_client(bot)),
           app.rpc_url);
    printf("[xahau-tip-bot] %zu previous tips loaded from %s\n", app.processed_count,
           app.tips_path);

    while (example_running) {
        status = evergram_bot_poll(bot, 100);
        if (status != EVERGRAM_OK && status != EVERGRAM_ERR_TIMEOUT &&
            status != EVERGRAM_ERR_NOT_CONNECTED) {
            example_log_error("[xahau-tip-bot]", status, "poll failed");
            break;
        }
        run_one(bot, &app);
    }

    printf("[xahau-tip-bot] sent %u tip(s) this run\n", app.tipped);
    xahau_rpc_destroy(app.rpc);
    evergram_wallet_wipe(&app.wallet);
    evergram_bot_destroy(bot);
    return EXIT_SUCCESS;
}
