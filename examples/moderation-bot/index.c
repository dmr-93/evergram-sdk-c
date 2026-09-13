/*
 * moderation-bot — group management: auto-approving join requests by rule.
 *
 * Port of examples/moderation-bot/index.ts. Two comma-separated environment
 * variables drive the policy:
 *   MODERATION_ALLOWLIST  identity keys allowed to auto-join
 *   MODERATION_PROMOTE    subset to promote to moderator after joining
 *
 * Note: this bot needs admin rights on the chats it manages. A freshly
 * generated wallet starts in the contract's default tier, which does not have
 * that capability — grant beta access first, or run it against a group an
 * already-privileged account created and added this bot to.
 */

#include "../_shared/example.h"

#include <string.h>

#define MAX_RULES 64
#define IDENTITY_MAX EVERGRAM_IDENTITY_SIZE

typedef struct {
    char entries[MAX_RULES][IDENTITY_MAX];
    size_t count;
} rule_set_t;

/* Parses a comma-separated list of identity keys, trimming spaces. */
static void load_rules(rule_set_t *rules, const char *value) {
    rules->count = 0;
    if (value == NULL) {
        return;
    }

    const char *cursor = value;
    while (*cursor != '\0' && rules->count < MAX_RULES) {
        while (*cursor == ' ' || *cursor == ',') {
            cursor++;
        }
        if (*cursor == '\0') {
            break;
        }

        size_t len = 0;
        while (cursor[len] != '\0' && cursor[len] != ',' && len + 1u < IDENTITY_MAX) {
            len++;
        }

        size_t end = len;
        while (end > 0 && cursor[end - 1] == ' ') {
            end--;
        }

        memcpy(rules->entries[rules->count], cursor, end);
        rules->entries[rules->count][end] = '\0';
        if (end > 0) {
            rules->count++;
        }

        cursor += len;
    }
}

static bool rule_contains(const rule_set_t *rules, const char *identity) {
    for (size_t i = 0; i < rules->count; i++) {
        if (strcmp(rules->entries[i], identity) == 0) {
            return true;
        }
    }
    return false;
}

static rule_set_t g_allowlist;
static rule_set_t g_promote;

static void on_connected(evergram_t *eg) {
    printf("[moderation-bot] online as %s\n", evergram_identity_key(eg));
}

static void on_disconnected(evergram_t *eg) {
    evergram_bot_t *bot = evergram_bot_from_client(eg);
    printf("[moderation-bot] disconnected (reconnect attempt %u)\n",
           evergram_bot_reconnect_attempts(bot));
}

static void on_error(evergram_t *eg, evergram_status_t status, const char *detail) {
    (void)eg;
    example_log_error("[moderation-bot] error:", status, detail);
}

static void on_join_request(evergram_t *eg, const evergram_join_request_t *request) {
    evergram_bot_t *bot = evergram_bot_from_client(eg);

    if (!rule_contains(&g_allowlist, request->identity)) {
        printf("[moderation-bot] %s is not on the allowlist, denying join for chat %s\n",
               request->identity, request->chat_id);
        evergram_bot_deny_join(bot, request->chat_id, request->identity);
        /* Demo of the RPC, not a recommended policy: flagging every
         * non-allowlisted request would spam reports for an ordinary public
         * chat. A real bot would gate this behind a repeat-offender count. */
        evergram_bot_report_user(bot, request->identity, "join request denied: not on allowlist");
        return;
    }

    printf("[moderation-bot] approving %s for chat %s\n", request->identity, request->chat_id);
    evergram_bot_approve_join(bot, request->chat_id, request->identity);

    /* Queued, so it runs after the approval has completed and the chat key is
     * in place. Sending it inline would fail with chat key unknown. */
    char welcome[256];
    snprintf(welcome, sizeof(welcome), "Welcome, %s!", request->identity);
    evergram_bot_send_later(bot, request->chat_id, welcome);

    if (rule_contains(&g_promote, request->identity)) {
        printf("[moderation-bot] promoting %s to moderator in chat %s\n", request->identity,
               request->chat_id);
        /* Also queued: updateChatRoles runs after the approval. */
        evergram_bot_promote_moderator(bot, request->chat_id, request->identity);
    }
}

int main(void) {
    load_rules(&g_allowlist, getenv("MODERATION_ALLOWLIST"));
    load_rules(&g_promote, getenv("MODERATION_PROMOTE"));

    printf("[moderation-bot] allowlist: %zu identity(ies), promote: %zu\n", g_allowlist.count,
           g_promote.count);

    const evergram_bot_options_t options = {
        .url = example_gateway_url(),
        .identity_path = example_identity_path(),
        .platform = "Terminal",
    };

    evergram_bot_t *bot = evergram_bot_create(&options);
    if (bot == NULL) {
        fprintf(stderr, "[moderation-bot] cannot create the bot\n");
        return 1;
    }

    evergram_bot_on_connected(bot, on_connected);
    evergram_bot_on_disconnected(bot, on_disconnected);
    evergram_bot_on_error(bot, on_error);
    evergram_bot_on_join_request(bot, on_join_request);

    int exit_code = example_run(bot);

    evergram_bot_destroy(bot);
    return exit_code;
}
