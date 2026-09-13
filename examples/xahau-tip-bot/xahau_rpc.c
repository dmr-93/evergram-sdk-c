#include "xahau_rpc.h"

#include <libwebsockets.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * One connection, one outstanding request: a tip is a rare event, and keeping
 * the client this small is what makes it reviewable. The socket is serviced in
 * a loop until the answer with our id arrives or the budget runs out.
 *
 * Request and response are flat enough for the SDK's own flat JSON reader to
 * handle... except the results, which nest. Rather than teach that reader about
 * nesting, the few scalars needed are pulled out with a small scanner that walks
 * to a named field and then to the first number/string after it. It is
 * deliberately narrow: it understands "find this key, take the value" and
 * nothing else, and the tests pin each extraction against real node replies.
 */

#define XAHAU_RESPONSE_MAX 16384
#define XAHAU_URL_HOST_MAX 200
#define XAHAU_URL_PATH_MAX 200

struct xahau_rpc {
    struct lws_context *context;
    struct lws *socket;
    int timeout_ms;

    char host[XAHAU_URL_HOST_MAX];
    char path[XAHAU_URL_PATH_MAX];
    int port;
    bool use_tls;

    char request[XAHAU_RPC_TEXT_MAX];
    char response[XAHAU_RESPONSE_MAX];
    size_t response_length;
    int next_id;
    int awaiting_id;
    bool complete;
    bool failed;
    /* True only between a successful handshake and the connection ending: the
     * socket handle alone says nothing, since lws returns one even for a
     * connection that never came up. */
    bool established;

    char error[256];
};


static const char *locate_value(const char *json, const char *key) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);

    const char *found = strstr(json, pattern);
    if (found == NULL) {
        return NULL;
    }
    const char *cursor = found + strlen(pattern);
    while (*cursor == ' ' || *cursor == '\t') {
        cursor++;
    }
    if (*cursor != ':') {
        return NULL;
    }
    cursor++;
    while (*cursor == ' ' || *cursor == '\t') {
        cursor++;
    }
    return cursor;
}

static void extract_string(const char *json, const char *key, char *out, size_t out_size) {
    out[0] = '\0';
    const char *value = locate_value(json, key);
    if (value == NULL || *value != '"') {
        return;
    }
    value++;
    size_t used = 0;
    while (*value != '\0' && *value != '"' && used + 1u < out_size) {
        out[used++] = *value++;
    }
    out[used] = '\0';
}

/* --- request/response plumbing -------------------------------------------- */

evergram_status_t xahau_rpc_build_request(char *out, size_t out_size, int id, const char *method,
                                          const char *params_json) {
    if (out == NULL || out_size == 0 || method == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    int written = snprintf(out, out_size, "{\"method\":\"%s\",\"params\":[%s],\"id\":%d}",
                           method, params_json != NULL ? params_json : "{}", id);
    if (written < 0 || (size_t)written >= out_size) {
        out[0] = '\0';
        return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }
    return EVERGRAM_OK;
}

static void set_error(xahau_rpc_t *rpc, const char *message) {
    snprintf(rpc->error, sizeof(rpc->error), "%s", message);
    rpc->failed = true;
}

/*
 * A websocket frame can be split, so the accumulated text is treated as
 * complete only when braces balance and the quotes are closed. That is enough
 * for the node's compact replies and avoids pulling in a JSON parser.
 */
static bool response_looks_complete(const char *text, size_t length) {
    if (length == 0) {
        return false;
    }

    int depth = 0;
    bool in_string = false;
    bool escaped = false;
    for (size_t i = 0; i < length; i++) {
        char c = text[i];
        if (in_string) {
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                in_string = false;
            }
            continue;
        }
        if (c == '"') {
            in_string = true;
        } else if (c == '{' || c == '[') {
            depth++;
        } else if (c == '}' || c == ']') {
            depth--;
            if (depth == 0) {
                return true;
            }
        }
    }
    return false;
}

static int rpc_callback(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in,
                        size_t len) {
    (void)user;
    xahau_rpc_t *rpc = (xahau_rpc_t *)lws_get_opaque_user_data(wsi);
    if (rpc == NULL) {
        return 0;
    }

    switch (reason) {
    case LWS_CALLBACK_CLIENT_ESTABLISHED:
        rpc->socket = wsi;
        rpc->established = true;
        {
            size_t length = strlen(rpc->request);
            unsigned char *frame = malloc(LWS_PRE + length);
            if (frame == NULL) {
                set_error(rpc, "cannot allocate a frame");
                return -1;
            }
            memcpy(frame + LWS_PRE, rpc->request, length);
            int written = lws_write(wsi, frame + LWS_PRE, length, LWS_WRITE_TEXT);
            free(frame);
            if (written < 0) {
                set_error(rpc, "cannot send the request");
                return -1;
            }
        }
        break;

    case LWS_CALLBACK_CLIENT_RECEIVE:
        if (rpc->response_length + len < sizeof(rpc->response)) {
            memcpy(rpc->response + rpc->response_length, in, len);
            rpc->response_length += len;
            rpc->response[rpc->response_length] = '\0';
            if (response_looks_complete(rpc->response, rpc->response_length)) {
                rpc->complete = true;
            }
        } else {
            set_error(rpc, "response too large");
        }
        break;

    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
        rpc->established = false;
        rpc->socket = NULL;
        set_error(rpc, in != NULL ? (const char *)in : "connection error");
        break;

    case LWS_CALLBACK_CLIENT_CLOSED:
        if (!rpc->complete) {
            set_error(rpc, "connection closed before a reply");
        }
        rpc->established = false;
        rpc->socket = NULL;
        break;

    default:
        break;
    }
    return 0;
}

static const struct lws_protocols RPC_PROTOCOLS[] = {
    {
        .name = "",
        .callback = rpc_callback,
        .per_session_data_size = 0,
        .rx_buffer_size = 0,
        .id = 0,
        .user = NULL,
        .tx_packet_size = 0,
    },
    {NULL, NULL, 0, 0, 0, NULL, 0},
};

static bool parse_url(xahau_rpc_t *rpc, const char *url) {
    const char *cursor = url;
    if (strncmp(cursor, "wss://", 6) == 0) {
        rpc->use_tls = true;
        cursor += 6;
    } else if (strncmp(cursor, "ws://", 5) == 0) {
        rpc->use_tls = false;
        cursor += 5;
    } else {
        return false;
    }

    const char *slash = strchr(cursor, '/');
    size_t host_length = slash != NULL ? (size_t)(slash - cursor) : strlen(cursor);
    if (host_length == 0 || host_length >= sizeof(rpc->host)) {
        return false;
    }
    memcpy(rpc->host, cursor, host_length);
    rpc->host[host_length] = '\0';

    rpc->port = rpc->use_tls ? 443 : 80;
    char *colon = strchr(rpc->host, ':');
    if (colon != NULL) {
        *colon = '\0';
        long port = strtol(colon + 1, NULL, 10);
        if (port <= 0 || port > 65535) {
            return false;
        }
        rpc->port = (int)port;
    }

    snprintf(rpc->path, sizeof(rpc->path), "%s", slash != NULL ? slash : "/");
    return true;
}

xahau_rpc_t *xahau_rpc_create(const char *url, int timeout_ms) {
    if (url == NULL || url[0] == '\0') {
        return NULL;
    }

    xahau_rpc_t *rpc = calloc(1, sizeof(*rpc));
    if (rpc == NULL) {
        return NULL;
    }
    rpc->timeout_ms = timeout_ms > 0 ? timeout_ms : 10000;
    rpc->next_id = 1;

    if (!parse_url(rpc, url)) {
        free(rpc);
        return NULL;
    }

    lws_set_log_level(LLL_ERR | LLL_WARN, NULL);

    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = RPC_PROTOCOLS;
    info.gid = -1;
    info.uid = -1;
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    rpc->context = lws_create_context(&info);
    if (rpc->context == NULL) {
        free(rpc);
        return NULL;
    }
    return rpc;
}

void xahau_rpc_destroy(xahau_rpc_t *rpc) {
    if (rpc == NULL) {
        return;
    }
    if (rpc->context != NULL) {
        lws_context_destroy(rpc->context);
    }
    free(rpc);
}

bool xahau_rpc_is_connected(const xahau_rpc_t *rpc) {
    return rpc != NULL && rpc->established;
}

const char *xahau_rpc_last_error(const xahau_rpc_t *rpc) {
    if (rpc == NULL) {
        return "no client";
    }
    return rpc->error[0] != '\0' ? rpc->error : "no error";
}

/*
 * Sends one request and waits for a reply that matches its id. A reply for
 * anything else (a subscription push, a stale answer) is ignored rather than
 * mistaken for ours.
 */
static evergram_status_t rpc_call(xahau_rpc_t *rpc, const char *method, const char *params,
                                  char *payload_out, size_t payload_size) {
    if (rpc == NULL || method == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    int id = rpc->next_id++;
    evergram_status_t status = xahau_rpc_build_request(rpc->request, sizeof(rpc->request), id,
                                                       method, params);
    if (status != EVERGRAM_OK) {
        return status;
    }
    rpc->response_length = 0;
    rpc->response[0] = '\0';
    rpc->complete = false;
    rpc->failed = false;
    rpc->error[0] = '\0';
    rpc->awaiting_id = id;

    struct lws_client_connect_info connect_info;
    memset(&connect_info, 0, sizeof(connect_info));
    connect_info.context = rpc->context;
    connect_info.address = rpc->host;
    connect_info.port = rpc->port;
    connect_info.path = rpc->path;
    connect_info.host = rpc->host;
    connect_info.origin = rpc->host;
    connect_info.protocol = RPC_PROTOCOLS[0].name;
    connect_info.ssl_connection = rpc->use_tls ? LCCSCF_USE_SSL : 0;
    connect_info.opaque_user_data = rpc;

    rpc->socket = lws_client_connect_via_info(&connect_info);
    if (rpc->socket == NULL) {
        set_error(rpc, "cannot start a connection");
        return EVERGRAM_ERR_TRANSPORT;
    }

    int budget = rpc->timeout_ms;
    while (!rpc->complete && !rpc->failed && budget > 0) {
        int slice = budget > 50 ? 50 : budget;
        int serviced = lws_service(rpc->context, slice);
        budget -= slice;
        if (serviced < 0) {
            set_error(rpc, "connection failed");
            break;
        }
    }

    if (rpc->failed) {
        return EVERGRAM_ERR_TRANSPORT;
    }
    if (!rpc->complete) {
        set_error(rpc, "the node did not answer in time");
        return EVERGRAM_ERR_TIMEOUT;
    }

    /* The reply must be ours, and must not carry a JSON-RPC error. */
    char id_key[32];
    snprintf(id_key, sizeof(id_key), "\"id\":%d", rpc->awaiting_id);
    if (strstr(rpc->response, id_key) == NULL) {
        set_error(rpc, "reply did not match the request id");
        return EVERGRAM_ERR_PROTOCOL;
    }
    if (strstr(rpc->response, "\"error\"") != NULL) {
        /* The node's message is the useful part, not the whole envelope. */
        char message[192];
        extract_string(rpc->response, "message", message, sizeof(message));
        set_error(rpc, message[0] != '\0' ? message : "the node returned an error");
        return EVERGRAM_ERR_PROTOCOL;
    }

    if (payload_out != NULL) {
        if (strlen(rpc->response) >= payload_size) {
            set_error(rpc, "reply does not fit the caller's buffer");
            return EVERGRAM_ERR_BUFFER_TOO_SMALL;
        }
        memcpy(payload_out, rpc->response, strlen(rpc->response) + 1u);
    }
    return EVERGRAM_OK;
}

/*
 * Finds "key" and returns the first character of its value (skipping the colon
 * and any spaces). Nested objects are not understood, which is why only the
 * fields listed in the header are read.
 */

static bool extract_u64(const char *json, const char *key, uint64_t *out) {
    const char *value = locate_value(json, key);
    if (value == NULL) {
        return false;
    }

    /* A number may be quoted in some replies; both spellings are accepted. */
    if (*value == '"') {
        value++;
    }
    if (*value < '0' || *value > '9') {
        return false;
    }

    uint64_t parsed = 0;
    while (*value >= '0' && *value <= '9') {
        uint64_t digit = (uint64_t)(*value - '0');
        if (parsed > (UINT64_MAX - digit) / 10u) {
            return false;
        }
        parsed = parsed * 10u + digit;
        value++;
    }
    *out = parsed;
    return true;
}


/* --- typed calls ---------------------------------------------------------- */

static evergram_status_t account_info_call(xahau_rpc_t *rpc, const char *address, char *out,
                                           size_t out_size) {
    char params[512];
    snprintf(params, sizeof(params),
             "{\"account\":\"%s\",\"ledger_index\":\"validated\",\"strict\":true}", address);
    return rpc_call(rpc, "account_info", params, out, out_size);
}

evergram_status_t xahau_rpc_account_info(xahau_rpc_t *rpc, const char *address,
                                         xahau_account_t *out) {
    if (rpc == NULL || address == NULL || out == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    memset(out, 0, sizeof(*out));

    char payload[XAHAU_RPC_TEXT_MAX];
    evergram_status_t status = account_info_call(rpc, address, payload, sizeof(payload));
    if (status != EVERGRAM_OK) {
        /* actNotFound: the account has never been funded above the reserve. */
        if (strstr(rpc->error, "actNotFound") != NULL) {
            return EVERGRAM_ERR_STATE;
        }
        return status;
    }

    if (!extract_u64(payload, "Sequence", &out->sequence) ||
        !extract_u64(payload, "Balance", &out->balance_drops)) {
        set_error(rpc, "account_info reply is missing Sequence or Balance");
        return EVERGRAM_ERR_PROTOCOL;
    }
    (void)extract_u64(payload, "OwnerCount", &out->owner_count);
    return EVERGRAM_OK;
}

evergram_status_t xahau_rpc_reserves(xahau_rpc_t *rpc, xahau_reserves_t *out) {
    if (rpc == NULL || out == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    memset(out, 0, sizeof(*out));

    char payload[XAHAU_RPC_TEXT_MAX];
    evergram_status_t status = rpc_call(rpc, "server_state", "{}", payload, sizeof(payload));
    if (status != EVERGRAM_OK) {
        return status;
    }
    if (!extract_u64(payload, "reserve_base", &out->reserve_base_drops) ||
        !extract_u64(payload, "reserve_inc", &out->reserve_inc_drops)) {
        set_error(rpc, "server_state reply is missing the reserves");
        return EVERGRAM_ERR_PROTOCOL;
    }
    return EVERGRAM_OK;
}

evergram_status_t xahau_rpc_network(xahau_rpc_t *rpc, xahau_network_t *out) {
    if (rpc == NULL || out == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    memset(out, 0, sizeof(*out));

    char payload[XAHAU_RPC_TEXT_MAX];
    evergram_status_t status = rpc_call(rpc, "ledger_current_index", "{}", payload,
                                        sizeof(payload));
    if (status != EVERGRAM_OK) {
        return status;
    }
    if (!extract_u64(payload, "ledger_current_index", &out->ledger_index) &&
        !extract_u64(payload, "ledger_index", &out->ledger_index)) {
        set_error(rpc, "ledger_current_index reply is missing the index");
        return EVERGRAM_ERR_PROTOCOL;
    }

    status = rpc_call(rpc, "server_info", "{}", payload, sizeof(payload));
    if (status != EVERGRAM_OK) {
        return status;
    }
    uint64_t network_id = 0;
    if (extract_u64(payload, "network_id", &network_id)) {
        out->network_id = (uint32_t)network_id;
    }
    /* The fee a node reports is in drops, and is the floor autofill uses. */
    uint64_t fee = 0;
    if (extract_u64(payload, "base_fee_xrp", &fee) && fee > 0) {
        out->base_fee_drops = fee * 1000000u; /* only if the node reports XRP units */
    }
    status = rpc_call(rpc, "fee", "{}", payload, sizeof(payload));
    if (status == EVERGRAM_OK) {
        uint64_t drops = 0;
        if (extract_u64(payload, "minimum_fee", &drops) ||
            extract_u64(payload, "drops", &drops)) {
            if (drops > 0) {
                out->base_fee_drops = drops;
            }
        }
    }
    if (out->base_fee_drops == 0) {
        out->base_fee_drops = 10; /* the protocol's own reference fee floor */
    }
    return EVERGRAM_OK;
}

evergram_status_t xahau_rpc_submit(xahau_rpc_t *rpc, const char *blob_hex, char *result,
                                   size_t result_size) {
    if (rpc == NULL || blob_hex == NULL || result == NULL || result_size == 0) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    result[0] = '\0';

    if (strlen(blob_hex) + 64u >= XAHAU_RPC_TEXT_MAX) {
        return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }
    char params[XAHAU_RPC_TEXT_MAX];
    snprintf(params, sizeof(params), "{\"tx_blob\":\"%s\"}", blob_hex);

    char payload[XAHAU_RPC_TEXT_MAX];
    evergram_status_t status = rpc_call(rpc, "submit", params, payload, sizeof(payload));
    if (status != EVERGRAM_OK) {
        return status;
    }
    extract_string(payload, "engine_result", result, result_size);
    if (result[0] == '\0') {
        set_error(rpc, "submit reply is missing engine_result");
        return EVERGRAM_ERR_PROTOCOL;
    }
    return EVERGRAM_OK;
}

evergram_status_t xahau_rpc_tx_result(xahau_rpc_t *rpc, const char *tx_hash, bool *validated,
                                      char *result, size_t result_size) {
    if (rpc == NULL || tx_hash == NULL || validated == NULL || result == NULL ||
        result_size == 0) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    *validated = false;
    result[0] = '\0';

    char params[256];
    snprintf(params, sizeof(params), "{\"transaction\":\"%s\"}", tx_hash);

    char payload[XAHAU_RPC_TEXT_MAX];
    evergram_status_t status = rpc_call(rpc, "tx", params, payload, sizeof(payload));
    if (status != EVERGRAM_OK) {
        return status;
    }

    const char *flag = locate_value(payload, "validated");
    *validated = flag != NULL && strncmp(flag, "true", 4) == 0;
    extract_string(payload, "engine_result", result, result_size);
    return EVERGRAM_OK;
}
