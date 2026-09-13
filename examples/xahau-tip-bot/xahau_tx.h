#ifndef EVERGRAM_XAHAU_TX_H
#define EVERGRAM_XAHAU_TX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "evergram.h"

/*
 * Minimal Xahau/XRPL payment builder: serialize, sign, hash.
 *
 * The TypeScript example gets all of this from the `xrpl` package; this is the
 * hand-written equivalent, kept with the example because the SDK itself never
 * talks to a ledger. It is deliberately narrow — one Payment, no memos, no
 * multisigning, no issued currencies — and every byte of its output is pinned
 * against transactions the reference library signed (tests/test_xahau_tx.c).
 *
 * Signing is ed25519 over 0x53545800 || the serialized transaction without its
 * signature, and the transaction id is SHA-512Half over 0x54584E00 || the signed
 * blob, exactly as the protocol specifies.
 */

#define XAHAU_BLOB_MAX 512
#define XAHAU_HASH_HEX_SIZE 65
#define XAHAU_SIGNING_DATA_MAX 384

typedef struct {
    const char *account;      /* source address ("r...") */
    const char *destination;  /* destination address */
    const char *amount_drops; /* decimal string, in drops */
    const char *fee_drops;    /* decimal string, in drops */
    uint64_t sequence;
    uint64_t last_ledger_sequence;
    /* Xahau reports a network id above 1024 and requires the field; XRPL
     * mainnet does not, so it is optional. */
    bool has_network_id;
    uint32_t network_id;
} xahau_payment_t;

/*
 * Fills signing_data_hex (optional, for diagnostics), blob_hex and hash_hex.
 * `private_key_hex` is the identity's own key ("ED" + 64 hex chars), the same
 * one the wallet signs chat authentication with.
 */
evergram_status_t xahau_sign_payment(const char *private_key_hex,
                                     const xahau_payment_t *payment, char *signing_data_hex,
                                     size_t signing_data_size, char *blob_hex,
                                     size_t blob_hex_size, char *hash_hex, size_t hash_hex_size);

#endif /* EVERGRAM_XAHAU_TX_H */
