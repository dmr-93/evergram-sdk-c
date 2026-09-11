/**
 * @file transport_websocket.c
 * @brief Implementação do transporte WebSocket usando libwebsockets
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <libwebsockets.h>
#include "evergram.h"
#include "transport.h"

// ============================================================================
// Estruturas Internas do Transporte
// ============================================================================

struct ws_transport {
    evergram_t* eg;                        // Ponteiro para contexto principal (void* para evitar include circular)
    struct lws_context* context;     // Contexto libwebsockets
    struct lws* wsi;                 // WebSocket instance
    evergram_state_t state;          // Estado atual
    char* recv_buffer;               // Buffer de recepção
    size_t recv_len;                 // Tamanho dos dados recebidos
    size_t recv_capacity;            // Capacidade do buffer
    int connection_completed;        // Flag de conexão completada
    int should_close;                // Flag para fechar conexão
    
    // Callbacks externos (setados pelo contexto principal)
    void (*ext_on_connected)(void* eg);
    void (*ext_on_disconnected)(void* eg);
    void (*ext_on_error)(void* eg, int error, const char* msg);
};

// ============================================================================
// Callbacks do libwebsockets
// ============================================================================

static int
ws_callback(struct lws* wsi, enum lws_callback_reasons reason,
            void* user, void* in, size_t len)
{
    ws_transport_t* transport = (ws_transport_t*)user;
    (void)in;
    (void)len;

    if (!transport) {
        return 0;
    }

    switch (reason) {
        case LWS_CALLBACK_ESTABLISHED:
            fprintf(stderr, "[WebSocket] Conexão estabelecida\n");
            transport->state = EVERGRAM_STATE_CONNECTED;
            transport->connection_completed = 1;
            
            // Notificar callback externo de conexão
            if (transport->ext_on_connected) {
                transport->ext_on_connected(transport->eg);
            }
            break;

        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
            fprintf(stderr, "[WebSocket] Erro de conexão: %s\n", 
                    in ? (const char*)in : "desconhecido");
            transport->state = EVERGRAM_STATE_ERROR;
            transport->connection_completed = 1;
            
            if (transport->ext_on_error) {
                transport->ext_on_error(transport->eg, EVERGRAM_ERR_NETWORK, 
                                   in ? (const char*)in : "Connection error");
            }
            break;

        case LWS_CALLBACK_CLIENT_RECEIVE:
            // Recebimento de dados do servidor
            if (len > 0) {
                // Expandir buffer se necessário
                if (transport->recv_len + len + 1 > transport->recv_capacity) {
                    size_t new_capacity = (transport->recv_capacity == 0) ? 
                                         4096 : transport->recv_capacity * 2;
                    while (new_capacity < transport->recv_len + len + 1) {
                        new_capacity *= 2;
                    }
                    
                    char* new_buffer = realloc(transport->recv_buffer, new_capacity);
                    if (!new_buffer) {
                        fprintf(stderr, "[WebSocket] Erro de alocação de memória\n");
                        return -1;
                    }
                    transport->recv_buffer = new_buffer;
                    transport->recv_capacity = new_capacity;
                }
                
                // Copiar dados para o buffer
                memcpy(transport->recv_buffer + transport->recv_len, in, len);
                transport->recv_len += len;
                transport->recv_buffer[transport->recv_len] = '\0';
                
                // Logar recebimento (parse real será implementado depois)
                fprintf(stderr, "[WebSocket] Recebido %zu bytes\n", len);
            }
            break;

        case LWS_CALLBACK_CLIENT_WRITEABLE:
            // Socket pronto para escrita
            break;

        case LWS_CALLBACK_CLOSED:
            fprintf(stderr, "[WebSocket] Conexão fechada\n");
            transport->state = EVERGRAM_STATE_DISCONNECTED;
            transport->wsi = NULL;
            
            if (transport->ext_on_disconnected) {
                transport->ext_on_disconnected(transport->eg);
            }
            break;

        default:
            break;
    }

    return lws_callback_on_writable(wsi);
}

// Protocolo libwebsockets
static struct lws_protocols protocols[] = {
    {
        .name = "evergram-protocol",
        .callback = ws_callback,
        .per_session_data_size = sizeof(ws_transport_t),
        .rx_buffer_size = 0,  // Usar buffer padrão
    },
    { NULL, NULL, 0, 0, 0, NULL, 0 }  // Terminador
};

// ============================================================================
// Funções de Transporte
// ============================================================================

ws_transport_t* transport_init(evergram_t* eg, const char* url) {
    (void)url;  // URL será usada no connect
    
    ws_transport_t* transport = calloc(1, sizeof(ws_transport_t));
    if (!transport) {
        return NULL;
    }

    transport->eg = eg;
    transport->state = EVERGRAM_STATE_CONNECTING;
    transport->recv_buffer = NULL;
    transport->recv_len = 0;
    transport->recv_capacity = 0;
    transport->connection_completed = 0;
    transport->should_close = 0;
    
    // Inicializar callbacks externos como NULL
    // O evergram.c setará esses callbacks via funções específicas se necessário
    transport->ext_on_connected = NULL;
    transport->ext_on_disconnected = NULL;
    transport->ext_on_error = NULL;

    // Configurar estrutura do libwebsockets
    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));

    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = protocols;
    info.gid = -1;
    info.uid = -1;
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    info.timeout_secs = 10;

    transport->context = lws_create_context(&info);
    if (!transport->context) {
        fprintf(stderr, "[WebSocket] Falha ao criar contexto\n");
        free(transport);
        return NULL;
    }

    fprintf(stderr, "[WebSocket] Contexto criado com sucesso\n");
    return transport;
}

int transport_connect(ws_transport_t* transport, const char* host, int port, 
                     int use_ssl, const char* path) {
    if (!transport || !transport->context || !host) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }

    struct lws_client_connect_info ccinfo;
    memset(&ccinfo, 0, sizeof(ccinfo));

    ccinfo.context = transport->context;
    ccinfo.address = host;
    ccinfo.port = port;
    ccinfo.path = path;
    ccinfo.host = host;
    ccinfo.origin = host;
    ccinfo.protocol = protocols[0].name;
    ccinfo.ssl_connection = use_ssl ? 2 : 0;  // 2 = LCCSCF_USE_SSL
    ccinfo.userdata = transport;

    transport->wsi = lws_client_connect_via_info(&ccinfo);
    if (!transport->wsi) {
        fprintf(stderr, "[WebSocket] Falha ao conectar\n");
        return EVERGRAM_ERR_NETWORK;
    }

    fprintf(stderr, "[WebSocket] Conectando a %s:%d%s...\n", host, port, path);
    return EVERGRAM_SUCCESS;
}

int transport_send(ws_transport_t* transport, const uint8_t* data, size_t len) {
    if (!transport || !transport->wsi || !data || len == 0) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }

    // Buffer para envio (LWS_SEND_BUFFER_PRE_PADDING + dados + LWS_SEND_BUFFER_POST_PADDING)
    unsigned char* buf = malloc(LWS_SEND_BUFFER_PRE_PADDING + len + LWS_SEND_BUFFER_POST_PADDING);
    if (!buf) {
        return EVERGRAM_ERR_MEMORY;
    }

    memcpy(buf + LWS_SEND_BUFFER_PRE_PADDING, data, len);
    
    int n = lws_write(transport->wsi, buf + LWS_SEND_BUFFER_PRE_PADDING, len, LWS_WRITE_TEXT);
    free(buf);

    if (n < (int)len) {
        fprintf(stderr, "[WebSocket] Erro ao enviar dados (enviado %d de %zu)\n", n, len);
        return EVERGRAM_ERR_NETWORK;
    }

    return EVERGRAM_SUCCESS;
}

int transport_poll(ws_transport_t* transport, int timeout_ms) {
    if (!transport || !transport->context) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }

    // Processar eventos por timeout_ms milissegundos
    int ret = lws_service(transport->context, timeout_ms);
    
    // Verificar se devemos fechar
    if (transport->should_close && transport->wsi) {
        lws_close_reason(transport->wsi, LWS_CLOSE_STATUS_NORMAL, NULL, 0);
        transport->wsi = NULL;
    }

    return (ret < 0) ? EVERGRAM_ERR_NETWORK : EVERGRAM_SUCCESS;
}

void transport_destroy(ws_transport_t* transport) {
    if (!transport) {
        return;
    }

    transport->should_close = 1;

    if (transport->wsi) {
        lws_close_reason(transport->wsi, LWS_CLOSE_STATUS_NORMAL, NULL, 0);
    }

    if (transport->context) {
        lws_context_destroy(transport->context);
    }

    if (transport->recv_buffer) {
        free(transport->recv_buffer);
    }

    free(transport);
    fprintf(stderr, "[WebSocket] Transporte destruído\n");
}

int transport_is_connected(ws_transport_t* transport) {
    return (transport && transport->state == EVERGRAM_STATE_CONNECTED) ? 1 : 0;
}

evergram_state_t transport_get_state(ws_transport_t* transport) {
    return transport ? transport->state : EVERGRAM_STATE_DISCONNECTED;
}
