/**
 * evergram-c - Core Implementation (evergram_create, evergram_reply, callbacks)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "evergram.h"
#include "transport.h"

/* Estrutura interna - deve ser consistente com message_parser.c e handshake.c */
struct evergram {
    char *server_url;
    evergram_wallet_t wallet;
    evergram_device_t device;
    void *ws_context;
    evergram_state_t state;
    evergram_hs_state_t hs_state;
    unsigned char session_key[32];
    bool session_keys_ready;
    uint64_t send_nonce;
    uint64_t recv_nonce;
    uint8_t *recv_buffer;
    size_t recv_buffer_size;
    size_t recv_buffer_len;
    time_t handshake_start_time;
    evergram_message_callback on_message;
    evergram_reaction_callback on_reaction;
    evergram_typing_callback on_typing;
    evergram_error_callback on_error;
    evergram_connected_callback on_connected;
    evergram_disconnected_callback on_disconnected;
    evergram_chat_synced_callback on_chat_synced;
    void *user_data;
};

/* Implementação de evergram_strerror */
const char* evergram_strerror(evergram_error_t err) {
    switch ((int)err) {
        case EVERGRAM_SUCCESS: return "Success";
        case EVERGRAM_ERR_INVALID_PARAM: return "Invalid parameter";
        case EVERGRAM_ERR_MEMORY: return "Out of memory";
        case EVERGRAM_ERR_CRYPTO: return "Cryptographic error";
        case EVERGRAM_ERR_NETWORK: return "Network error";
        case EVERGRAM_ERR_AUTH: return "Authentication failed";
        case EVERGRAM_ERR_TIMEOUT: return "Operation timeout";
        case EVERGRAM_ERR_PROTO: return "Protocol error";
        case EVERGRAM_ERR_NOT_CONNECTED: return "Not connected";
        case EVERGRAM_ERR_RATE_LIMITED: return "Rate limited";
        case EVERGRAM_ERR_ACCESS_DENIED: return "Access denied";
        case EVERGRAM_ERR_NOT_FOUND: return "Not found";
        case EVERGRAM_ERR_ROTATION_REQUIRED: return "Key rotation required";
        case EVERGRAM_ERR_DEVICE_REVOKED: return "Device revoked";
        case EVERGRAM_ERR_INSUFFICIENT_BALANCE: return "Insufficient balance";
        case EVERGRAM_ERR_BUFFER_TOO_SMALL: return "Buffer too small";
        default: return "Unknown error";
    }
}

/* evergram_create - cria nova instância */
evergram_t* evergram_create(const evergram_options_t* options) {
    if (!options || !options->url || !options->wallet || !options->device) {
        return NULL;
    }
    
    evergram_t* eg = (evergram_t*)calloc(1, sizeof(evergram_t));
    if (!eg) {
        return NULL;
    }
    
    /* Copiar configurações */
    eg->server_url = strdup(options->url);
    if (!eg->server_url) {
        free(eg);
        return NULL;
    }
    
    memcpy(&eg->wallet, options->wallet, sizeof(evergram_wallet_t));
    memcpy(&eg->device, options->device, sizeof(evergram_device_t));
    
    eg->state = EVERGRAM_STATE_DISCONNECTED;
    eg->hs_state = EVERGRAM_HS_DISCONNECTED;
    eg->session_keys_ready = false;
    eg->send_nonce = 0;
    eg->recv_nonce = 0;
    eg->user_data = options->user_data;
    
    /* Inicializar buffer de recebimento */
    eg->recv_buffer_size = 4096;
    eg->recv_buffer = (uint8_t*)malloc(eg->recv_buffer_size);
    if (!eg->recv_buffer) {
        free(eg->server_url);
        free(eg);
        return NULL;
    }
    eg->recv_buffer_len = 0;
    
    /* Criar transporte WebSocket */
    eg->ws_context = transport_create(eg);
    if (!eg->ws_context) {
        free(eg->recv_buffer);
        free(eg->server_url);
        free(eg);
        return NULL;
    }
    
    return eg;
}

/* evergram_destroy - libera recursos */
void evergram_destroy(evergram_t* eg) {
    if (!eg) return;
    
    /* Destruir transporte */
    if (eg->ws_context) {
        transport_destroy((ws_transport_t*)eg->ws_context);
    }
    
    /* Liberar buffer */
    if (eg->recv_buffer) {
        free(eg->recv_buffer);
    }
    
    /* Liberar URL */
    if (eg->server_url) {
        free(eg->server_url);
    }
    
    /* Zerar estrutura */
    memset(eg, 0, sizeof(evergram_t));
    free(eg);
}

/* Registro de callbacks */
void evergram_on_message(evergram_t* eg, evergram_message_callback cb) {
    if (eg) eg->on_message = cb;
}

void evergram_on_reaction(evergram_t* eg, evergram_reaction_callback cb) {
    if (eg) eg->on_reaction = cb;
}

void evergram_on_typing(evergram_t* eg, evergram_typing_callback cb) {
    if (eg) eg->on_typing = cb;
}

void evergram_on_error(evergram_t* eg, evergram_error_callback cb) {
    if (eg) eg->on_error = cb;
}

void evergram_on_connected(evergram_t* eg, evergram_connected_callback cb) {
    if (eg) eg->on_connected = cb;
}

void evergram_on_disconnected(evergram_t* eg, evergram_disconnected_callback cb) {
    if (eg) eg->on_disconnected = cb;
}

void evergram_on_chat_synced(evergram_t* eg, evergram_chat_synced_callback cb) {
    if (eg) eg->on_chat_synced = cb;
}

/* evergram_reply - responde a uma mensagem */
int evergram_reply(evergram_t* eg, const evergram_message_t* reply_to, 
                   const char* format, ...) {
    if (!eg || !reply_to || !format) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    /* Construir mensagem formatada */
    char text[EVERGRAM_MAX_MESSAGE_LEN];
    va_list args;
    va_start(args, format);
    int len = vsnprintf(text, sizeof(text), format, args);
    va_end(args);
    
    if (len < 0 || len >= (int)sizeof(text)) {
        return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }
    
    /* Enviar para o mesmo chat */
    return evergram_send(eg, reply_to->chat_id, text);
}

/* evergram_sendf - envia mensagem formatada */
int evergram_sendf(evergram_t* eg, const char* chat_id, const char* format, ...) {
    if (!eg || !chat_id || !format) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    char text[EVERGRAM_MAX_MESSAGE_LEN];
    va_list args;
    va_start(args, format);
    int len = vsnprintf(text, sizeof(text), format, args);
    va_end(args);
    
    if (len < 0 || len >= (int)sizeof(text)) {
        return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }
    
    return evergram_send(eg, chat_id, text);
}

/* evergram_is_connected - verifica estado da conexão */
bool evergram_is_connected(evergram_t* eg) {
    if (!eg) return false;
    return (eg->state == EVERGRAM_STATE_CONNECTED);
}

/* evergram_get_user_data - retorna dados do usuário */
void* evergram_get_user_data(evergram_t* eg) {
    if (!eg) return NULL;
    return eg->user_data;
}

/* evergram_set_user_data - define dados do usuário */
void evergram_set_user_data(evergram_t* eg, void* user_data) {
    if (eg) eg->user_data = user_data;
}
