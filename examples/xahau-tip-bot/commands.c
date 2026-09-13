#include "commands.h"

#include <stdio.h>
#include <string.h>

/* XAH has six decimal places, like XRP: 1 drop = 0.000001. */
#define TIP_MAX_DECIMALS 6

static void set_error(char *error, size_t error_size, const char *message) {
    if (error != NULL && error_size > 0) {
        snprintf(error, error_size, "%s", message);
    }
}

/* A classic XRPL address: "r", base58 characters, 25-34 long. Validating the
 * checksum needs the ledger's alphabet, so this is the same shape check the
 * reference example gets from isValidClassicAddress(). */
static bool looks_like_address(const char *text) {
    static const char alphabet[] = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
    size_t length = strlen(text);
    if (length < 25 || length > 34 || text[0] != 'r') {
        return false;
    }
    for (size_t i = 1; i < length; i++) {
        if (strchr(alphabet, text[i]) == NULL) {
            return false;
        }
        /* strchr also matches the terminator, which is not a valid character. */
        if (text[i] == '\0') {
            return false;
        }
    }
    return true;
}

/* Digits only, positive, at most six decimal places. */
static bool validate_amount(const char *raw, char *error, size_t error_size) {
    if (raw == NULL || raw[0] == '\0') {
        set_error(error, error_size, "Invalid amount: (missing)");
        return false;
    }

    bool seen_dot = false;
    size_t decimals = 0;
    bool any_digit = false;
    for (const char *cursor = raw; *cursor != '\0'; cursor++) {
        if (*cursor == '.') {
            if (seen_dot) {
                set_error(error, error_size, "Invalid amount: not a number");
                return false;
            }
            seen_dot = true;
            continue;
        }
        if (*cursor < '0' || *cursor > '9') {
            char message[96];
            snprintf(message, sizeof(message), "Invalid amount: %s", raw);
            set_error(error, error_size, message);
            return false;
        }
        any_digit = true;
        if (seen_dot) {
            decimals++;
        }
    }

    if (!any_digit) {
        set_error(error, error_size, "Invalid amount: not a number");
        return false;
    }
    if (decimals > TIP_MAX_DECIMALS) {
        char message[192];
        snprintf(message, sizeof(message),
                 "Invalid amount: %s. XAH allows at most %d decimal places (smallest unit is "
                 "0.000001).",
                 raw, TIP_MAX_DECIMALS);
        set_error(error, error_size, message);
        return false;
    }

    /* Zero is not a tip. Leading zeros are fine ("0.5"). */
    bool nonzero = false;
    for (const char *cursor = raw; *cursor != '\0'; cursor++) {
        if (*cursor >= '1' && *cursor <= '9') {
            nonzero = true;
            break;
        }
    }
    if (!nonzero) {
        char message[96];
        snprintf(message, sizeof(message), "Invalid amount: %s", raw);
        set_error(error, error_size, message);
        return false;
    }
    return true;
}

/* Splits on whitespace, in place. Returns the token count. */
static size_t split(char *text, char **tokens, size_t max_tokens) {
    size_t count = 0;
    char *cursor = text;
    while (*cursor != '\0' && count < max_tokens) {
        while (*cursor == ' ' || *cursor == '\t' || *cursor == '\n' || *cursor == '\r') {
            cursor++;
        }
        if (*cursor == '\0') {
            break;
        }
        tokens[count++] = cursor;
        while (*cursor != '\0' && *cursor != ' ' && *cursor != '\t' && *cursor != '\n' &&
               *cursor != '\r') {
            cursor++;
        }
        if (*cursor != '\0') {
            *cursor++ = '\0';
        }
    }
    return count;
}

evergram_status_t tip_parse(const char *text, const char *reply_sender, tip_command_t *out,
                            char *error, size_t error_size) {
    if (text == NULL || out == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    memset(out, 0, sizeof(*out));

    char buffer[EVERGRAM_TEXT_SIZE];
    snprintf(buffer, sizeof(buffer), "%s", text);

    char *tokens[8];
    size_t count = split(buffer, tokens, sizeof(tokens) / sizeof(tokens[0]));
    if (count == 0 || strcmp(tokens[0], "!tip") != 0) {
        set_error(error, error_size, "Not a tip command");
        return EVERGRAM_ERR_INVALID_ARG;
    }

    /* Everything after "!tip". */
    size_t rest = count - 1u;
    if (rest == 0) {
        set_error(error, error_size, "Usage: !tip [<@identityKey>|<address>] <amount> [XAH]");
        return EVERGRAM_ERR_INVALID_ARG;
    }

    const char *first = tokens[1];
    bool is_mention = first[0] == '@';
    bool is_address = !is_mention && looks_like_address(first);

    if (is_mention || is_address) {
        if (rest < 2) {
            set_error(error, error_size, "Invalid amount: (missing)");
            return EVERGRAM_ERR_INVALID_ARG;
        }
        const char *amount = tokens[2];
        const char *currency = rest >= 3 ? tokens[3] : "XAH";
        if (!validate_amount(amount, error, error_size)) {
            return EVERGRAM_ERR_INVALID_ARG;
        }

        snprintf(out->amount, sizeof(out->amount), "%s", amount);
        snprintf(out->currency, sizeof(out->currency), "%s", currency);
        if (is_mention) {
            out->target_kind = TIP_TARGET_MENTION;
            snprintf(out->identity_key, sizeof(out->identity_key), "%s", first + 1);
        } else {
            out->target_kind = TIP_TARGET_ADDRESS;
            snprintf(out->address, sizeof(out->address), "%s", first);
        }
        return EVERGRAM_OK;
    }

    /* No recognizable target: the amount comes first and the tip goes to the
     * author of the message being replied to. */
    const char *amount = tokens[1];
    const char *currency = rest >= 2 ? tokens[2] : "XAH";
    if (!validate_amount(amount, error, error_size)) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (reply_sender == NULL || reply_sender[0] == '\0') {
        set_error(error, error_size,
                  "No target given. Reply to the person's message, or use "
                  "!tip @<identityKey>/<address> <amount>.");
        return EVERGRAM_ERR_INVALID_ARG;
    }

    snprintf(out->amount, sizeof(out->amount), "%s", amount);
    snprintf(out->currency, sizeof(out->currency), "%s", currency);
    out->target_kind = TIP_TARGET_REPLY;
    snprintf(out->identity_key, sizeof(out->identity_key), "%s", reply_sender);
    return EVERGRAM_OK;
}

evergram_status_t tip_amount_to_drops(const char *amount, char *out, size_t out_size) {
    if (amount == NULL || out == NULL || out_size == 0) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    char error[192];
    if (!validate_amount(amount, error, sizeof(error))) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    /* Whole part, then the fraction padded or truncated to six places. */
    unsigned long long whole = 0;
    unsigned long long fraction = 0;
    size_t decimals = 0;
    const char *cursor = amount;
    for (; *cursor != '\0' && *cursor != '.'; cursor++) {
        whole = whole * 10u + (unsigned long long)(*cursor - '0');
        if (whole > 18446744073709ull) { /* keeping 6 decimals in range */
            return EVERGRAM_ERR_INVALID_ARG;
        }
    }
    if (*cursor == '.') {
        cursor++;
        for (; *cursor != '\0'; cursor++) {
            fraction = fraction * 10u + (unsigned long long)(*cursor - '0');
            decimals++;
        }
    }
    while (decimals < TIP_MAX_DECIMALS) {
        fraction *= 10u;
        decimals++;
    }

    int written = snprintf(out, out_size, "%llu", whole * 1000000ull + fraction);
    if (written < 0 || (size_t)written >= out_size) {
        out[0] = '\0';
        return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }
    return EVERGRAM_OK;
}

bool tip_address_from_identity(const char *identity_key, char *out, size_t out_size) {
    if (identity_key == NULL || out == NULL || out_size == 0) {
        return false;
    }
    out[0] = '\0';

    /* "<chainFamily>:<address>", and only XRPL (family 1) can be tipped. */
    const char *colon = strchr(identity_key, ':');
    if (colon == NULL || colon == identity_key) {
        return false;
    }
    size_t family_length = (size_t)(colon - identity_key);
    if (family_length != 1u || identity_key[0] != '1') {
        return false;
    }

    const char *address = colon + 1;
    if (*address == '\0' || strlen(address) >= out_size) {
        return false;
    }
    snprintf(out, out_size, "%s", address);
    return true;
}
