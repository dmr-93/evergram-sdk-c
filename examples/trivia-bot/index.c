/*
 * trivia-bot — IRC-style trivia: one round per chat, first correct answer wins
 * the point, in-memory scoreboard for the session.
 *
 * Port of examples/trivia-bot/index.ts. Commands:
 *   !trivia  ask a new question
 *   !skip    reveal the answer and skip the current question
 *   !score   show this chat's scoreboard
 *   !help    show the command list
 *
 * The TypeScript version schedules the round timeout with setTimeout; here the
 * poll loop checks deadlines instead, so no timers or threads are needed.
 */

#include "../_shared/example.h"
#include "questions.h"

#include <sodium.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#define ROUND_TIMEOUT_MS 30000u
#define ANSWER_MAX 128
#define MAX_ROUNDS 64
#define MAX_SCORES 512
#define SCOREBOARD_MAX 1024
#define MESSAGE_MAX 2048

#define HELP_TEXT                                          \
    "!trivia: ask a new question\n"                        \
    "!skip: reveal the answer and skip the current question\n" \
    "!score: show this chat's scoreboard\n"                \
    "!help: show this message"

typedef struct {
    bool active;
    char chat_id[EVERGRAM_CHAT_ID_SIZE];
    char answer[ANSWER_MAX];     /* normalized, for matching */
    char raw_answer[ANSWER_MAX]; /* original casing, for the reveal */
    uint64_t deadline_ms;
} round_t;

typedef struct {
    bool used;
    char chat_id[EVERGRAM_CHAT_ID_SIZE];
    char identity[EVERGRAM_IDENTITY_SIZE];
    int points;
} score_t;

static round_t g_rounds[MAX_ROUNDS];
static score_t g_scores[MAX_SCORES];

static uint64_t now_ms(void) {
    struct timespec now;
    if (timespec_get(&now, TIME_UTC) == 0) {
        return 0;
    }
    return (uint64_t)now.tv_sec * 1000u + (uint64_t)(now.tv_nsec / 1000000);
}

/* Lowercase and drop everything that is not [a-z0-9], so "multi-signing" and
 * "multi signing" match. ASCII only: NFD diacritic folding is not ported. */
static void normalize(const char *text, char *out, size_t out_size) {
    size_t written = 0;
    for (size_t i = 0; text[i] != '\0' && written + 1u < out_size; i++) {
        unsigned char c = (unsigned char)text[i];
        if (c >= 'A' && c <= 'Z') {
            c = (unsigned char)(c - 'A' + 'a');
        }
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
            out[written] = (char)c;
            written++;
        }
    }
    out[written] = '\0';
}

static round_t *find_round(const char *chat_id) {
    for (size_t i = 0; i < MAX_ROUNDS; i++) {
        if (g_rounds[i].active && strcmp(g_rounds[i].chat_id, chat_id) == 0) {
            return &g_rounds[i];
        }
    }
    return NULL;
}

static round_t *start_round(const char *chat_id, const trivia_question_t *question) {
    for (size_t i = 0; i < MAX_ROUNDS; i++) {
        if (g_rounds[i].active) {
            continue;
        }

        round_t *round = &g_rounds[i];
        memset(round, 0, sizeof(*round));
        round->active = true;
        snprintf(round->chat_id, sizeof(round->chat_id), "%s", chat_id);
        normalize(question->answer, round->answer, sizeof(round->answer));
        snprintf(round->raw_answer, sizeof(round->raw_answer), "%s", question->answer);
        round->deadline_ms = now_ms() + ROUND_TIMEOUT_MS;
        return round;
    }
    return NULL;
}

static round_t *end_round(const char *chat_id) {
    round_t *round = find_round(chat_id);
    if (round != NULL) {
        round->active = false;
    }
    return round;
}

static int award_point(const char *chat_id, const char *identity) {
    for (size_t i = 0; i < MAX_SCORES; i++) {
        if (g_scores[i].used && strcmp(g_scores[i].chat_id, chat_id) == 0 &&
            strcmp(g_scores[i].identity, identity) == 0) {
            g_scores[i].points++;
            return g_scores[i].points;
        }
    }

    for (size_t i = 0; i < MAX_SCORES; i++) {
        if (g_scores[i].used) {
            continue;
        }
        g_scores[i].used = true;
        snprintf(g_scores[i].chat_id, sizeof(g_scores[i].chat_id), "%s", chat_id);
        snprintf(g_scores[i].identity, sizeof(g_scores[i].identity), "%s", identity);
        g_scores[i].points = 1;
        return 1;
    }
    return 0;
}

/* Top ten scores for a chat, highest first. */
static void render_scoreboard(const char *chat_id, char *out, size_t out_size) {
    const score_t *top[10];
    size_t count = 0;

    for (size_t i = 0; i < MAX_SCORES; i++) {
        if (!g_scores[i].used || strcmp(g_scores[i].chat_id, chat_id) != 0) {
            continue;
        }
        if (count < 10) {
            top[count++] = &g_scores[i];
            continue;
        }
        /* Replace the current worst when this one scores higher. */
        size_t worst = 0;
        for (size_t j = 1; j < 10; j++) {
            if (top[j]->points < top[worst]->points) {
                worst = j;
            }
        }
        if (g_scores[i].points > top[worst]->points) {
            top[worst] = &g_scores[i];
        }
    }

    for (size_t i = 0; i < count; i++) {
        for (size_t j = i + 1; j < count; j++) {
            if (top[j]->points > top[i]->points) {
                const score_t *swap = top[i];
                top[i] = top[j];
                top[j] = swap;
            }
        }
    }

    out[0] = '\0';
    if (count == 0) {
        snprintf(out, out_size, "No one has scored yet.");
        return;
    }

    size_t written = 0;
    for (size_t i = 0; i < count && written + 1u < out_size; i++) {
        int added = snprintf(out + written, out_size - written, "%zu. @%s: %d\n", i + 1,
                             top[i]->identity, top[i]->points);
        if (added < 0) {
            break;
        }
        written += (size_t)added;
        if (written >= out_size) {
            out[out_size - 1u] = '\0';
            break;
        }
    }
}

static void reply(evergram_t *eg, const evergram_message_t *message, const char *format, ...) {
    char text[MESSAGE_MAX];
    va_list args;
    va_start(args, format);
    int length = vsnprintf(text, sizeof(text), format, args);
    va_end(args);

    if (length < 0) {
        return;
    }

    evergram_bot_t *bot = evergram_bot_from_client(eg);
    evergram_status_t status = evergram_bot_reply_with_typing(bot, message, "%s", text);
    if (status != EVERGRAM_OK) {
        example_log_error("[trivia-bot] reply failed:", status, NULL);
    }
}

static void on_message(evergram_t *eg, const evergram_message_t *message) {
    if (message->text == NULL || message->text[0] == '\0') {
        return;
    }
    if (evergram_message_content_type(message->text) != EVERGRAM_CONTENT_TEXT) {
        return;
    }

    const char *text = message->text;
    char normalized[MESSAGE_MAX + 1];
    normalize(text, normalized, sizeof(normalized));

    if (strcmp(normalized, "help") == 0) {
        reply(eg, message, "%s", HELP_TEXT);
        return;
    }

    if (strcmp(normalized, "trivia") == 0) {
        if (find_round(message->chat_id) != NULL) {
            reply(eg, message, "There's already a question open! Answer it, or use !skip.");
            return;
        }

        const trivia_question_t *question = &TRIVIA_QUESTIONS[randombytes_uniform(
            (uint32_t)TRIVIA_QUESTION_COUNT)];
        if (start_round(message->chat_id, question) == NULL) {
            reply(eg, message, "Too many open rounds right now, try again later.");
            return;
        }
        reply(eg, message, "🎲 %s (%us to answer)", question->question, ROUND_TIMEOUT_MS / 1000u);
        return;
    }

    if (strcmp(normalized, "skip") == 0) {
        round_t *round = find_round(message->chat_id);
        if (round == NULL) {
            reply(eg, message, "No question is open right now. Ask one with !trivia.");
            return;
        }
        char answer[ANSWER_MAX];
        snprintf(answer, sizeof(answer), "%s", round->raw_answer);
        end_round(message->chat_id);
        reply(eg, message, "⏭️ Skipped. The answer was: %s", answer);
        return;
    }

    if (strcmp(normalized, "score") == 0) {
        char board[SCOREBOARD_MAX];
        render_scoreboard(message->chat_id, board, sizeof(board));
        reply(eg, message, "🏆 Scoreboard:\n%s", board);
        return;
    }

    round_t *round = find_round(message->chat_id);
    if (round == NULL) {
        return; /* plain chat, no open question */
    }

    if (strcmp(normalized, round->answer) == 0) {
        end_round(message->chat_id);
        int points = award_point(message->chat_id, message->sender);
        reply(eg, message, "✅ Correct, @%s! You now have %d point(s). Ask for another with !trivia.",
              message->sender, points);
    }
}

/* Reveals the answer for rounds whose deadline passed. */
static void expire_rounds(evergram_bot_t *bot) {
    evergram_t *client = evergram_bot_client(bot);
    uint64_t now = now_ms();

    for (size_t i = 0; i < MAX_ROUNDS; i++) {
        if (!g_rounds[i].active || now < g_rounds[i].deadline_ms) {
            continue;
        }

        char reveal[MESSAGE_MAX];
        snprintf(reveal, sizeof(reveal), "⏰ Time's up! The answer was: %s", g_rounds[i].raw_answer);
        g_rounds[i].active = false;

        evergram_send_typing(client, g_rounds[i].chat_id, true);
        evergram_status_t status = evergram_send(client, g_rounds[i].chat_id, reveal);
        if (status != EVERGRAM_OK) {
            example_log_error("[trivia-bot] reveal failed:", status, NULL);
        }
    }
}

static void on_connected(evergram_t *eg) {
    printf("[trivia-bot] online as %s\n", evergram_identity_key(eg));
}

static void on_disconnected(evergram_t *eg) {
    evergram_bot_t *bot = evergram_bot_from_client(eg);
    printf("[trivia-bot] disconnected (reconnect attempt %u)\n",
           evergram_bot_reconnect_attempts(bot));
}

static void on_error(evergram_t *eg, evergram_status_t status, const char *detail) {
    (void)eg;
    example_log_error("[trivia-bot] error:", status, detail);
}

int main(void) {
    printf("[trivia-bot] gateway: %s\n", example_gateway_url());
    printf("[trivia-bot] %zu questions loaded\n", (size_t)TRIVIA_QUESTION_COUNT);

    const evergram_bot_options_t options = {
        .url = example_gateway_url(),
        .identity_path = example_identity_path(),
        .name = "TriviaBot",
        .platform = "Terminal",
    };

    evergram_bot_t *bot = evergram_bot_create(&options);
    if (bot == NULL) {
        fprintf(stderr, "[trivia-bot] cannot create the bot\n");
        return 1;
    }

    evergram_bot_on_connected(bot, on_connected);
    evergram_bot_on_disconnected(bot, on_disconnected);
    evergram_bot_on_error(bot, on_error);
    evergram_bot_on_message(bot, on_message);

    signal(SIGINT, example_handle_signal);
    signal(SIGTERM, example_handle_signal);

    if (evergram_bot_start(bot) != EVERGRAM_OK) {
        fprintf(stderr, "[trivia-bot] cannot connect\n");
        evergram_bot_destroy(bot);
        return 1;
    }

    while (example_running) {
        evergram_bot_poll(bot, 100);
        expire_rounds(bot);
    }

    evergram_bot_destroy(bot);
    return 0;
}
