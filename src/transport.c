#include "transport.h"

#include <libwebsockets.h>
#include <sodium.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "rxqueue.h"

#define TRANSPORT_HOST_MAX 256
#define TRANSPORT_PATH_MAX 512
#define TRANSPORT_ERROR_MAX 128
#define TRANSPORT_DEFAULT_WSS_PORT 443
#define TRANSPORT_DEFAULT_WS_PORT 80
#define TRANSPORT_TLS 1
#define TRANSPORT_PLAIN 0

struct transport {
    struct lws_context *context;
    struct lws *socket;
    rxqueue_t *rx;
    transport_events_t events;

    char host[TRANSPORT_HOST_MAX];
    char path[TRANSPORT_PATH_MAX];
    char last_error[TRANSPORT_ERROR_MAX];

    int port;
    bool use_tls;
    bool open;
    bool activity; /* set by callbacks so service() can report "nothing happened" */
};

static void record_error(transport_t *transport, const char *what) {
    if (what != NULL) {
        snprintf(transport->last_error, sizeof(transport->last_error), "%s", what);
    }
}

/* Splits ws://host:port/path into its parts. All parts are bounded. */
static evergram_status_t parse_url(transport_t *transport, const char *url) {
    const char *rest;
    if (strncmp(url, "wss://", 6) == 0) {
        transport->use_tls = true;
        transport->port = TRANSPORT_DEFAULT_WSS_PORT;
        rest = url + 6;
    } else if (strncmp(url, "ws://", 5) == 0) {
        transport->use_tls = false;
        transport->port = TRANSPORT_DEFAULT_WS_PORT;
        rest = url + 5;
    } else {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    const char *path_start = strchr(rest, '/');
    size_t authority_len = path_start != NULL ? (size_t)(path_start - rest) : strlen(rest);
    if (authority_len == 0 || authority_len >= sizeof(transport->host)) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    const char *colon = memchr(rest, ':', authority_len);
    size_t host_len = colon != NULL ? (size_t)(colon - rest) : authority_len;
    if (host_len == 0 || host_len >= sizeof(transport->host)) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    memcpy(transport->host, rest, host_len);
    transport->host[host_len] = '\0';

    if (colon != NULL) {
        size_t port_len = authority_len - host_len - 1u;
        if (port_len == 0 || port_len > 5u) {
            return EVERGRAM_ERR_INVALID_ARG;
        }
        char port_text[6];
        memcpy(port_text, colon + 1, port_len);
        port_text[port_len] = '\0';

        char *end = NULL;
        long parsed = strtol(port_text, &end, 10);
        if (end == port_text || *end != '\0' || parsed <= 0 || parsed > 65535) {
            return EVERGRAM_ERR_INVALID_ARG;
        }
        transport->port = (int)parsed;
    }

    const char *path = path_start != NULL ? path_start : "/";
    if (strlen(path) >= sizeof(transport->path)) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    snprintf(transport->path, sizeof(transport->path), "%s", path);
    return EVERGRAM_OK;
}

static int transport_callback(struct lws *wsi, enum lws_callback_reasons reason, void *user,
                              void *in, size_t len) {
    transport_t *transport = user;
    if (transport == NULL) {
        struct lws_context *context = lws_get_context(wsi);
        if (context != NULL) {
            transport = lws_context_user(context);
        }
    }
    if (transport == NULL) {
        return 0;
    }

    switch (reason) {
    case LWS_CALLBACK_CLIENT_ESTABLISHED:
        transport->open = true;
        transport->activity = true;
        if (transport->events.on_open != NULL) {
            transport->events.on_open(transport->events.context);
        }
        break;

    case LWS_CALLBACK_CLIENT_RECEIVE:
        if (len > 0 && rxqueue_push(transport->rx, in, len) != EVERGRAM_OK) {
            record_error(transport, "receive buffer overflow");
            return -1;
        }
        if (lws_is_final_fragment(wsi) && rxqueue_end_frame(transport->rx) != EVERGRAM_OK) {
            record_error(transport, "receive buffer overflow");
            return -1;
        }
        break;

    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
        record_error(transport, in != NULL ? (const char *)in : "connection error");
        transport->open = false;
        transport->activity = true;
        if (transport->events.on_error != NULL) {
            transport->events.on_error(transport->events.context, EVERGRAM_ERR_TRANSPORT,
                                       transport->last_error);
        }
        break;

    case LWS_CALLBACK_CLOSED:
        transport->open = false;
        transport->socket = NULL;
        transport->activity = true;
        if (transport->events.on_closed != NULL) {
            transport->events.on_closed(transport->events.context);
        }
        break;

    default:
        break;
    }

    return 0;
}

static const struct lws_protocols PROTOCOLS[] = {
    {
        .name = "",
        .callback = transport_callback,
        .per_session_data_size = 0,
        .rx_buffer_size = 0,
        .id = 0,
        .user = NULL,
        .tx_packet_size = 0,
    },
    {NULL, NULL, 0, 0, 0, NULL, 0},
};

static void configure_lws_logging(void) {
    if (evergram_log_get_level() >= EVERGRAM_LOG_TRACE) {
        lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_INFO | LLL_CLIENT, NULL);
    } else {
        lws_set_log_level(LLL_ERR | LLL_WARN, NULL);
    }
}

transport_t *transport_create(const char *url, const transport_events_t *events) {
    if (url == NULL || events == NULL) {
        return NULL;
    }

    transport_t *transport = calloc(1, sizeof(*transport));
    if (transport == NULL) {
        return NULL;
    }

    transport->events = *events;
    if (parse_url(transport, url) != EVERGRAM_OK) {
        EG_ERROR("malformed url: %s", url);
        free(transport);
        return NULL;
    }

    transport->rx = rxqueue_create(0);
    if (transport->rx == NULL) {
        free(transport);
        return NULL;
    }

    configure_lws_logging();

    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = PROTOCOLS;
    info.gid = -1;
    info.uid = -1;
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    info.user = transport;

    transport->context = lws_create_context(&info);
    if (transport->context == NULL) {
        EG_ERROR("cannot create websocket context");
        rxqueue_destroy(transport->rx);
        free(transport);
        return NULL;
    }

    EG_DEBUG("transport ready for %s%s:%d%s", transport->use_tls ? "wss://" : "ws://",
             transport->host, transport->port, transport->path);
    return transport;
}

void transport_destroy(transport_t *transport) {
    if (transport == NULL) {
        return;
    }

    if (transport->context != NULL) {
        lws_context_destroy(transport->context);
    }
    rxqueue_destroy(transport->rx);
    sodium_memzero(transport, sizeof(*transport));
    free(transport);
}

evergram_status_t transport_connect(transport_t *transport) {
    if (transport == NULL || transport->context == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (transport->open || transport->socket != NULL) {
        return EVERGRAM_OK;
    }

    struct lws_client_connect_info connect_info;
    memset(&connect_info, 0, sizeof(connect_info));
    connect_info.context = transport->context;
    connect_info.address = transport->host;
    connect_info.port = transport->port;
    connect_info.path = transport->path;
    connect_info.host = transport->host;
    connect_info.origin = transport->host;
    connect_info.protocol = PROTOCOLS[0].name;
    connect_info.ssl_connection = transport->use_tls ? LCCSCF_USE_SSL : 0;
    connect_info.userdata = transport;

    transport->last_error[0] = '\0';
    transport->socket = lws_client_connect_via_info(&connect_info);
    if (transport->socket == NULL) {
        record_error(transport, "cannot start connection");
        return EVERGRAM_ERR_TRANSPORT;
    }

    EG_INFO("connecting to %s%s:%d%s", transport->use_tls ? "wss://" : "ws://", transport->host,
            transport->port, transport->path);
    return EVERGRAM_OK;
}

evergram_status_t transport_service(transport_t *transport, int timeout_ms) {
    if (transport == NULL || transport->context == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    transport->activity = false;

    int result = lws_service(transport->context, timeout_ms);
    if (result < 0) {
        record_error(transport, "service loop failed");
        return EVERGRAM_ERR_TRANSPORT;
    }

    bool delivered = false;
    size_t len = 0;
    const uint8_t *frame;
    while ((frame = rxqueue_frame(transport->rx, &len)) != NULL) {
        if (transport->events.on_message != NULL) {
            transport->events.on_message(transport->events.context, frame, len);
        }
        rxqueue_pop(transport->rx);
        delivered = true;
    }

    return (delivered || transport->activity) ? EVERGRAM_OK : EVERGRAM_ERR_TIMEOUT;
}

evergram_status_t transport_send(transport_t *transport, const uint8_t *data, size_t len) {
    if (transport == NULL || data == NULL || len == 0) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (!transport->open || transport->socket == NULL) {
        return EVERGRAM_ERR_NOT_CONNECTED;
    }

    /* libwebsockets requires LWS_PRE bytes of headroom and tail padding. */
    unsigned char *buffer = malloc(LWS_PRE + len + LWS_PRE);
    if (buffer == NULL) {
        return EVERGRAM_ERR_NO_MEMORY;
    }

    memcpy(buffer + LWS_PRE, data, len);
    int written = lws_write(transport->socket, buffer + LWS_PRE, len, LWS_WRITE_BINARY);
    free(buffer);

    if (written < 0 || (size_t)written < len) {
        record_error(transport, "short write");
        return EVERGRAM_ERR_TRANSPORT;
    }

    EG_TRACE("sent %zu bytes", len);
    return EVERGRAM_OK;
}

bool transport_is_open(const transport_t *transport) {
    return transport != NULL && transport->open;
}

const char *transport_last_error(const transport_t *transport) {
    if (transport == NULL || transport->last_error[0] == '\0') {
        return NULL;
    }
    return transport->last_error;
}
