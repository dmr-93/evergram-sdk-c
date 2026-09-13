#ifndef EVERGRAM_XAHAU_COMMANDS_H
#define EVERGRAM_XAHAU_COMMANDS_H

#include <stdbool.h>
#include <stddef.h>

#include "evergram.h"

/*
 * Command parsing for the tip bot, kept free of any gateway or ledger
 * dependency so it is pure text in, struct out — and therefore unit testable
 * without a node. Port of examples/xahau-tip-bot/commands.ts.
 */

#define TIP_AMOUNT_MAX 32
#define TIP_CURRENCY_MAX 16

typedef enum {
    TIP_TARGET_REPLY = 0,  /* no target token: the message being replied to */
    TIP_TARGET_MENTION,    /* "@<identityKey>" */
    TIP_TARGET_ADDRESS,    /* a raw ledger address */
} tip_target_kind_t;

typedef struct {
    char amount[TIP_AMOUNT_MAX];
    char currency[TIP_CURRENCY_MAX];
    tip_target_kind_t target_kind;
    char identity_key[EVERGRAM_IDENTITY_SIZE]; /* for REPLY and MENTION */
    char address[EVERGRAM_ADDRESS_SIZE];       /* for ADDRESS */
} tip_command_t;

/*
 * Parses everything after "!tip ". Three shapes, tried in order:
 *   "!tip @<identityKey> <amount> [XAH]"
 *   "!tip <address> <amount> [XAH]"
 *   "!tip <amount> [XAH]"     — needs reply_sender, the author of the message
 *                               this one replied to
 * On failure `error` explains why, in the same words the TypeScript example
 * uses, because those strings are what a user sees.
 */
evergram_status_t tip_parse(const char *text, const char *reply_sender, tip_command_t *out,
                            char *error, size_t error_size);

/* "5" -> "5000000". Rejects anything that is not a plain decimal amount with at
 * most six places, which is XAH's smallest unit. */
evergram_status_t tip_amount_to_drops(const char *amount, char *out, size_t out_size);

/* "1:rAddress" -> "rAddress"; false when the key is not an XRPL identity. */
bool tip_address_from_identity(const char *identity_key, char *out, size_t out_size);

#endif /* EVERGRAM_XAHAU_COMMANDS_H */
