#ifndef EVERGRAM_XAHAU_RPC_H
#define EVERGRAM_XAHAU_RPC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "evergram.h"

/*
 * Minimal Xahau/XRPL JSON-RPC client over websocket.
 *
 * Only the calls a tip bot needs, over one blocking connection at a time: the
 * ledger is queried from the poll loop, never from a message handler. The
 * reference example gets all of this from the `xrpl` package; this is the
 * hand-written equivalent, kept with the example.
 *
 * Every call returns the parsed numbers it needs rather than raw JSON, so the
 * gating conditions (is the account funded, what is the next sequence, what fee
 * does the network want) are explicit at the call site.
 */

#define XAHAU_RPC_URL_SIZE 256
#define XAHAU_RPC_TEXT_MAX 8192

typedef struct xahau_rpc xahau_rpc_t;

/* Connects lazily; returns NULL on a malformed URL or a missing library. */
xahau_rpc_t *xahau_rpc_create(const char *url, int timeout_ms);

/* Closes and releases the connection. Accepts NULL. */
void xahau_rpc_destroy(xahau_rpc_t *rpc);

bool xahau_rpc_is_connected(const xahau_rpc_t *rpc);

/* Last failure, for logging. Never NULL once a call has failed. */
const char *xahau_rpc_last_error(const xahau_rpc_t *rpc);

typedef struct {
    uint64_t sequence;  /* the next Sequence this account must use */
    uint64_t balance_drops;
    uint64_t owner_count;
} xahau_account_t;

/* account_info; EVERGRAM_ERR_STATE when the account has no ledger entry yet
 * (actNotFound), which for a fresh tip wallet simply means "not funded". */
evergram_status_t xahau_rpc_account_info(xahau_rpc_t *rpc, const char *address,
                                         xahau_account_t *out);

typedef struct {
    uint64_t reserve_base_drops;
    uint64_t reserve_inc_drops;
} xahau_reserves_t;

/* server_state: the reserves are reported by the server, never hardcoded. */
evergram_status_t xahau_rpc_reserves(xahau_rpc_t *rpc, xahau_reserves_t *out);

typedef struct {
    uint64_t ledger_index; /* the current (open) ledger */
    uint32_t network_id;   /* above 1024 on Xahau, which is why it is required */
    uint64_t base_fee_drops;
} xahau_network_t;

/* ledger_current_index, server_info and fee, in one round trip each. */
evergram_status_t xahau_rpc_network(xahau_rpc_t *rpc, xahau_network_t *out);

/* submit: returns the engine result ("tesSUCCESS" is queued, not validated). */
evergram_status_t xahau_rpc_submit(xahau_rpc_t *rpc, const char *blob_hex, char *result,
                                   size_t result_size);

/* `validated` is the ledger result; false means the transaction is still
 * pending (or was never included). */
evergram_status_t xahau_rpc_tx_result(xahau_rpc_t *rpc, const char *tx_hash, bool *validated,
                                      char *result, size_t result_size);

/*
 * Builds one JSON-RPC request. Exposed because the shape is the whole contract
 * with the node, and it is what the tests pin.
 */
evergram_status_t xahau_rpc_build_request(char *out, size_t out_size, int id, const char *method,
                                          const char *params_json);

#endif /* EVERGRAM_XAHAU_RPC_H */
