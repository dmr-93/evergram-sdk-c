#include "evergram.h"
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sodium.h>
#include <libwebsockets.h>
#include "transport.h"

// Forward declaration do transporte
typedef struct ws_transport ws_transport_t;

// ============================================================================
// Estruturas Internas
// ============================================================================

struct evergram {
    // Configuração
    evergram_options_t options;
    
    // Estado da conexão
    evergram_state_t state;
    char nonce[EVERGRAM_MAX_NONCE_LEN];  // Nonce atual para auth
    
    // Callbacks
    evergram_message_callback on_msg;
    evergram_reaction_callback on_reaction;
    evergram_typing_callback on_typing;
    evergram_error_callback on_error;
    evergram_connected_callback on_connected;
    evergram_disconnected_callback on_disconnected;
    evergram_chat_synced_callback on_chat_synced;
    
    // Transporte WebSocket
    ws_transport_t* transport;
    
    // Chats conhecidos (para cache de chaves simétricas)
    struct chat_cache* chats;
    int chat_count;
    
    // Dados do usuário
    void* user_data;
};

// ============================================================================
// Implementação das Funções Utilitárias
// ============================================================================

const char* evergram_strerror(evergram_error_t error) {
    switch (error) {
        case EVERGRAM_SUCCESS: return "Success";
        case EVERGRAM_ERR_INVALID_PARAM: return "Invalid parameter";
        case EVERGRAM_ERR_MEMORY: return "Memory allocation failed";
        case EVERGRAM_ERR_CRYPTO: return "Cryptographic operation failed";
        case EVERGRAM_ERR_NETWORK: return "Network error";
        case EVERGRAM_ERR_AUTH: return "Authentication failed";
        case EVERGRAM_ERR_TIMEOUT: return "Operation timed out";
        case EVERGRAM_ERR_PROTO: return "Protocol error";
        case EVERGRAM_ERR_NOT_CONNECTED: return "Not connected";
        case EVERGRAM_ERR_RATE_LIMITED: return "Rate limited";
        case EVERGRAM_ERR_ACCESS_DENIED: return "Access denied";
        case EVERGRAM_ERR_NOT_FOUND: return "Not found";
        case EVERGRAM_ERR_ROTATION_REQUIRED: return "Key rotation required";
        case EVERGRAM_ERR_DEVICE_REVOKED: return "Device revoked";
        case EVERGRAM_ERR_INSUFFICIENT_BALANCE: return "Insufficient balance";
        default: return "Unknown error";
    }
}

const char* evergram_version(void) {
    return "0.1.0";
}

void evergram_set_user_data(evergram_t* eg, void* user_data) {
    if (!eg) return;
    eg->user_data = user_data;
}

void* evergram_get_user_data(evergram_t* eg) {
    if (!eg) return NULL;
    return eg->user_data;
}

// ============================================================================
// Funções Criptográficas (Stub - implementação real requer libsodium)
// ============================================================================

int evergram_hex_to_bytes(const char* hex, uint8_t* out, size_t out_len) {
    if (!hex || !out || out_len == 0) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    size_t bytes_needed = hex_len / 2;
    if (bytes_needed > out_len) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    for (size_t i = 0; i < bytes_needed; i++) {
        unsigned int byte;
        char byte_str[3] = {hex[i*2], hex[i*2+1], 0};
        if (sscanf(byte_str, "%02x", &byte) != 1) {
            return EVERGRAM_ERR_INVALID_PARAM;
        }
        out[i] = (uint8_t)byte;
    }
    
    return (int)bytes_needed;
}

int evergram_bytes_to_hex(const uint8_t* bytes, size_t len, char* out, size_t out_len) {
    if (!bytes || !out || out_len < len * 2 + 1) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    for (size_t i = 0; i < len; i++) {
        sprintf(out + i * 2, "%02x", bytes[i]);
    }
    out[len * 2] = '\0';
    
    return EVERGRAM_SUCCESS;
}

// ============================================================================
// Gerenciamento de Carteira e Dispositivo (Stubs)
// ============================================================================

int evergram_generate_wallet(evergram_wallet_t* wallet) {
    if (!wallet) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    // NOTA: Implementação real requer biblioteca ripple-keypairs ou equivalente
    // Este é um stub que deve ser substituído por chamadas reais à API XRPL
    
    fprintf(stderr, "AVISO: evergram_generate_wallet() é um stub.\n");
    fprintf(stderr, "Implementação real requer integração com ripple-keypairs.\n");
    
    memset(wallet, 0, sizeof(*wallet));
    strcpy(wallet->seed, "stub_seed_placeholder");
    strcpy(wallet->address, "rStubAddressPlaceholder");
    strcpy(wallet->public_key_hex, "stub_pubkey_hex");
    strcpy(wallet->private_key_hex, "stub_privkey_hex");
    
    return EVERGRAM_SUCCESS;
}

int evergram_wallet_from_seed(evergram_wallet_t* wallet, const char* seed) {
    if (!wallet || !seed) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    // NOTA: Implementação real requer derivar chaves a partir do seed
    fprintf(stderr, "AVISO: evergram_wallet_from_seed() é um stub.\n");
    
    memset(wallet, 0, sizeof(*wallet));
    strncpy(wallet->seed, seed, sizeof(wallet->seed) - 1);
    strcpy(wallet->address, "rStubAddressFromSeed");
    strcpy(wallet->public_key_hex, "stub_pubkey_hex");
    strcpy(wallet->private_key_hex, "stub_privkey_hex");
    
    return EVERGRAM_SUCCESS;
}

int evergram_generate_device(evergram_device_t* device) {
    if (!device) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    /* Inicializa libsodium se necessário */
    if (sodium_init() < 0) {
        fprintf(stderr, "[Evergram] Falha ao inicializar libsodium\n");
        return EVERGRAM_ERR_CRYPTO;
    }
    
    /* Gera par de chaves usando crypto_box_keypair do libsodium */
    unsigned char pub_bin[crypto_box_PUBLICKEYBYTES];
    unsigned char priv_bin[crypto_box_SECRETKEYBYTES];
    
    if (crypto_box_keypair(pub_bin, priv_bin) != 0) {
        fprintf(stderr, "[Evergram] Falha ao gerar par de chaves do dispositivo\n");
        return EVERGRAM_ERR_CRYPTO;
    }
    
    /* Converte chaves binárias para hex */
    sodium_bin2hex(device->pub_hex, EVERGRAM_MAX_HEX_KEY_LEN, pub_bin, sizeof(pub_bin));
    sodium_bin2hex(device->priv_hex, EVERGRAM_MAX_HEX_KEY_LEN, priv_bin, sizeof(priv_bin));
    
    /* Deriva device_id a partir da chave pública */
    if (evergram_derive_device_id(device->pub_hex, device->device_id) != EVERGRAM_SUCCESS) {
        fprintf(stderr, "[Evergram] Falha ao derivar device_id\n");
        return EVERGRAM_ERR_CRYPTO;
    }
    
    return EVERGRAM_SUCCESS;
}

/* evergram_derive_device_id foi movido para crypto.c com implementação real */


// ============================================================================
// Criação e Destruição da Instância

// ============================================================================
// Gerenciamento da Instância (Implementação Real com WebSocket)
// ============================================================================

evergram_t* evergram_create(const evergram_options_t* options) {
    if (!options || !options->url || !options->wallet || !options->device) {
        return NULL;
    }

    evergram_t* eg = (evergram_t*)calloc(1, sizeof(evergram_t));
    if (!eg) {
        return NULL;
    }

    // Copiar opções
    eg->options.url = strdup(options->url);
    eg->options.wallet = options->wallet;
    eg->options.device = options->device;
    eg->options.name = options->name ? strdup(options->name) : NULL;
    eg->options.platform = options->platform ? strdup(options->platform) : NULL;
    eg->options.max_participants = options->max_participants > 0 ?
                                    options->max_participants : 250;
    eg->options.request_timeout_ms = options->request_timeout_ms > 0 ?
                                      options->request_timeout_ms : 30000;
    eg->options.auto_reconnect = options->auto_reconnect;
    eg->options.user_data = options->user_data;

    // Inicializar estado
    eg->state = EVERGRAM_STATE_DISCONNECTED;
    memset(eg->nonce, 0, sizeof(eg->nonce));
    eg->chats = NULL;
    eg->chat_count = 0;
    eg->user_data = options->user_data;

    // Inicializar transporte WebSocket
    eg->transport = transport_init(eg, options->url);
    if (!eg->transport) {
        fprintf(stderr, "[Evergram] Falha ao inicializar transporte WebSocket\n");
        evergram_destroy(eg);
        return NULL;
    }

    fprintf(stderr, "[Evergram] Instância criada com sucesso\n");
    return eg;
}

void evergram_destroy(evergram_t* eg) {
    if (!eg) return;

    // Liberar strings alocadas
    free((char*)eg->options.url);
    free((char*)eg->options.name);
    free((char*)eg->options.platform);

    // Destruir transporte WebSocket
    if (eg->transport) {
        transport_destroy(eg->transport);
        eg->transport = NULL;
    }

    // Limpar cache de chats
    // ... (implementação dependente da estrutura chat_cache)

    free(eg);
    fprintf(stderr, "[Evergram] Instância destruída\n");
}

// ============================================================================
// Controle de Conexão
// ============================================================================

// Callback interno chamado quando WebSocket conecta
__attribute__((unused))
static void on_ws_connected(void* user_data) {
    evergram_t* eg = (evergram_t*)user_data;
    if (!eg) return;
    
    fprintf(stderr, "[Evergram] WebSocket conectado, iniciando handshake...\n");
    
    // Gerar nonce para auth
    uint8_t nonce_bytes[24];
    randombytes_buf(nonce_bytes, sizeof(nonce_bytes));
    evergram_bytes_to_hex(nonce_bytes, sizeof(nonce_bytes), eg->nonce, sizeof(eg->nonce));
    
    // TODO: Construir e enviar mensagem de handshake/auth
    // Formato esperado pelo servidor Evergram:
    // {
    //   "type": "handshake",
    //   "nonce": "<nonce_hex>",
    //   "wallet": "<wallet_address>",
    //   "device_id": "<device_id>",
    //   "signature": "<assinatura>"
    // }
    
    // Por enquanto, apenas notificar conexão estabelecida
    eg->state = EVERGRAM_STATE_CONNECTED;
    fprintf(stderr, "[Evergram] Handshake completado (stub)\n");
    
    if (eg->on_connected) {
        eg->on_connected(eg);
    }
}

// Callback interno chamado quando WebSocket desconecta
__attribute__((unused))
static void on_ws_disconnected(void* user_data) {
    evergram_t* eg = (evergram_t*)user_data;
    if (!eg) return;
    
    eg->state = EVERGRAM_STATE_DISCONNECTED;
    fprintf(stderr, "[Evergram] Conexão fechada\n");
    
    if (eg->on_disconnected) {
        eg->on_disconnected(eg);
    }
}

// Callback interno chamado quando há erro no WebSocket
__attribute__((unused))
static void on_ws_error(void* user_data, int error, const char* msg) {
    evergram_t* eg = (evergram_t*)user_data;
    if (!eg) return;
    
    eg->state = EVERGRAM_STATE_ERROR;
    fprintf(stderr, "[Evergram] Erro: %s\n", msg ? msg : "desconhecido");
    
    if (eg->on_error) {
        eg->on_error(eg, error, msg);
    }
}

int evergram_start(evergram_t* eg) {
    if (!eg || !eg->transport) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }

    if (eg->state != EVERGRAM_STATE_DISCONNECTED) {
        return EVERGRAM_SUCCESS; // Já está iniciando/conectado
    }

    // Configurar callbacks do transporte
    // Nota: transport é ws_transport_t*, precisamos acessar via ponteiro opaco
    // Os callbacks são setados internamente no transport_init
    
    // Parse da URL para obter host, port, path
    // Formato: wss://host:port/path ou ws://host:port/path
    const char* url = eg->options.url;
    int use_ssl = 0;
    int port = 443;
    char host[256] = {0};
    char path[256] = "/";
    
    if (strncmp(url, "wss://", 6) == 0) {
        use_ssl = 1;
        url += 6;
        port = 443;
    } else if (strncmp(url, "ws://", 5) == 0) {
        use_ssl = 0;
        url += 5;
        port = 80;
    } else {
        fprintf(stderr, "[Evergram] URL inválida (deve começar com ws:// ou wss://)\n");
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    // Extrair host e path
    char* slash = strchr(url, '/');
    if (slash) {
        size_t host_len = slash - url;
        if (host_len >= sizeof(host)) host_len = sizeof(host) - 1;
        strncpy(host, url, host_len);
        host[host_len] = '\0';
        strncpy(path, slash, sizeof(path) - 1);
        path[sizeof(path) - 1] = '\0';
    } else {
        strncpy(host, url, sizeof(host) - 1);
        host[sizeof(host) - 1] = '\0';
    }
    
    // Extrair porta se presente
    char* colon = strchr(host, ':');
    if (colon) {
        *colon = '\0';
        port = atoi(colon + 1);
    }
    
    fprintf(stderr, "[Evergram] Conectando a %s:%d%s (SSL=%d)\n", host, port, path, use_ssl);
    
    eg->state = EVERGRAM_STATE_CONNECTING;
    
    int ret = transport_connect(eg->transport, host, port, use_ssl, path);
    if (ret != EVERGRAM_SUCCESS) {
        eg->state = EVERGRAM_STATE_ERROR;
        return ret;
    }
    
    // NOTA: A conexão é assíncrona. O estado EVERGRAM_STATE_CONNECTED
    // será setado no callback LWS_CALLBACK_ESTABLISHED -> on_ws_connected
    // O usuário deve chamar evergram_poll() para processar eventos.
    
    return EVERGRAM_SUCCESS;
}

int evergram_poll(evergram_t* eg, int timeout_ms) {
    if (!eg || !eg->transport) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }

    // Processar eventos do WebSocket
    int ret = transport_poll(eg->transport, timeout_ms);
    
    // Verificar reconexão automática se necessário
    if (ret != EVERGRAM_SUCCESS && eg->options.auto_reconnect && 
        eg->state == EVERGRAM_STATE_CONNECTED) {
        fprintf(stderr, "[Evergram] Conexão perdida, tentando reconectar...\n");
        eg->state = EVERGRAM_STATE_DISCONNECTED;
        // Tentar reconectar no próximo start
    }
    
    return ret;
}

bool evergram_is_connected(evergram_t* eg) {
    if (!eg || !eg->transport) {
        return false;
    }
    return transport_is_connected(eg->transport);
}

// Registro de Callbacks
// ============================================================================

void evergram_on_message(evergram_t* eg, evergram_message_callback cb) {
    if (!eg) return;
    eg->on_msg = cb;
}

void evergram_on_reaction(evergram_t* eg, evergram_reaction_callback cb) {
    if (!eg) return;
    eg->on_reaction = cb;
}

void evergram_on_typing(evergram_t* eg, evergram_typing_callback cb) {
    if (!eg) return;
    eg->on_typing = cb;
}

void evergram_on_error(evergram_t* eg, evergram_error_callback cb) {
    if (!eg) return;
    eg->on_error = cb;
}

void evergram_on_connected(evergram_t* eg, evergram_connected_callback cb) {
    if (!eg) return;
    eg->on_connected = cb;
}

void evergram_on_disconnected(evergram_t* eg, evergram_disconnected_callback cb) {
    if (!eg) return;
    eg->on_disconnected = cb;
}

void evergram_on_chat_synced(evergram_t* eg, evergram_chat_synced_callback cb) {
    if (!eg) return;
    eg->on_chat_synced = cb;
}

// ============================================================================
// Envio de Mensagens (Stubs)
// ============================================================================

int evergram_send(evergram_t* eg, const char* chat_id, const char* text) {
    if (!eg || !chat_id || !text) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    if (!transport_is_connected(eg->transport)) {
        return EVERGRAM_ERR_NOT_CONNECTED;
    }
    
    fprintf(stderr, "AVISO: evergram_send() é um stub.\n");
    fprintf(stderr, "Implementação real requer:\n");
    fprintf(stderr, "  1. Obter chave simétrica do chat\n");
    fprintf(stderr, "  2. Criptografar texto com nacl.secretbox\n");
    fprintf(stderr, "  3. Construir envelope protobuf\n");
    fprintf(stderr, "  4. Enviar via WebSocket\n");
    
    return EVERGRAM_SUCCESS;
}

int evergram_sendf(evergram_t* eg, const char* chat_id, const char* format, ...) {
    if (!eg || !chat_id || !format) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    char buffer[EVERGRAM_MAX_MESSAGE_LEN];
    va_list args;
    va_start(args, format);
    int ret = vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    
    if (ret < 0 || ret >= (int)sizeof(buffer)) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    return evergram_send(eg, chat_id, buffer);
}

int evergram_reply(evergram_t* eg, const evergram_message_t* reply_to, 
                   const char* format, ...) {
    if (!eg || !reply_to || !format) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    char buffer[EVERGRAM_MAX_MESSAGE_LEN];
    va_list args;
    va_start(args, format);
    int ret = vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    
    if (ret < 0 || ret >= (int)sizeof(buffer)) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    // NOTA: Implementação real precisaria setar reply_to_msg_id no envelope
    fprintf(stderr, "AVISO: evergram_reply() é um stub.\n");
    
    return evergram_send(eg, reply_to->chat_id, buffer);
}

int evergram_send_typing(evergram_t* eg, const char* chat_id) {
    if (!eg || !chat_id) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    if (!transport_is_connected(eg->transport)) {
        return EVERGRAM_ERR_NOT_CONNECTED;
    }
    
    fprintf(stderr, "AVISO: evergram_send_typing() é um stub.\n");
    
    return EVERGRAM_SUCCESS;
}

int evergram_send_reaction(evergram_t* eg, const char* chat_id, 
                           const char* msg_id, const char* emoji) {
    if (!eg || !chat_id || !msg_id || !emoji) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    if (!transport_is_connected(eg->transport)) {
        return EVERGRAM_ERR_NOT_CONNECTED;
    }
    
    fprintf(stderr, "AVISO: evergram_send_reaction() é um stub.\n");
    
    return EVERGRAM_SUCCESS;
}

int evergram_remove_reaction(evergram_t* eg, const char* chat_id, const char* msg_id) {
    if (!eg || !chat_id || !msg_id) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    if (!transport_is_connected(eg->transport)) {
        return EVERGRAM_ERR_NOT_CONNECTED;
    }
    
    fprintf(stderr, "AVISO: evergram_remove_reaction() é um stub.\n");
    
    return EVERGRAM_SUCCESS;
}

int evergram_edit_message(evergram_t* eg, const char* chat_id, 
                          const char* msg_id, const char* new_text) {
    if (!eg || !chat_id || !msg_id || !new_text) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    if (!transport_is_connected(eg->transport)) {
        return EVERGRAM_ERR_NOT_CONNECTED;
    }
    
    fprintf(stderr, "AVISO: evergram_edit_message() é um stub.\n");
    
    return EVERGRAM_SUCCESS;
}

int evergram_delete_message(evergram_t* eg, const char* chat_id, const char* msg_id) {
    if (!eg || !chat_id || !msg_id) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    if (!transport_is_connected(eg->transport)) {
        return EVERGRAM_ERR_NOT_CONNECTED;
    }
    
    fprintf(stderr, "AVISO: evergram_delete_message() é um stub.\n");
    
    return EVERGRAM_SUCCESS;
}

// ============================================================================
// Gerenciamento de Chats (Stubs)
// ============================================================================

int evergram_create_chat(evergram_t* eg, const char* identity_key, char* chat_id_out) {
    if (!eg || !identity_key) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    if (!transport_is_connected(eg->transport)) {
        return EVERGRAM_ERR_NOT_CONNECTED;
    }
    
    fprintf(stderr, "AVISO: evergram_create_chat() é um stub.\n");
    
    if (chat_id_out) {
        strcpy(chat_id_out, "stub_chat_id");
    }
    
    return EVERGRAM_SUCCESS;
}

int evergram_create_group(evergram_t* eg, const char* name,
                          const char** participant_keys, int participant_count,
                          char* chat_id_out) {
    if (!eg || !name || !participant_keys || participant_count <= 0) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    if (!transport_is_connected(eg->transport)) {
        return EVERGRAM_ERR_NOT_CONNECTED;
    }
    
    fprintf(stderr, "AVISO: evergram_create_group() é um stub.\n");
    
    if (chat_id_out) {
        strcpy(chat_id_out, "stub_group_id");
    }
    
    return EVERGRAM_SUCCESS;
}

int evergram_add_participant(evergram_t* eg, const char* chat_id, 
                             const char* identity_key) {
    if (!eg || !chat_id || !identity_key) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    if (!transport_is_connected(eg->transport)) {
        return EVERGRAM_ERR_NOT_CONNECTED;
    }
    
    fprintf(stderr, "AVISO: evergram_add_participant() é um stub.\n");
    
    return EVERGRAM_SUCCESS;
}

int evergram_remove_participant(evergram_t* eg, const char* chat_id, 
                                const char* identity_key) {
    if (!eg || !chat_id || !identity_key) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    if (!transport_is_connected(eg->transport)) {
        return EVERGRAM_ERR_NOT_CONNECTED;
    }
    
    fprintf(stderr, "AVISO: evergram_remove_participant() é um stub.\n");
    
    return EVERGRAM_SUCCESS;
}

int evergram_leave_chat(evergram_t* eg, const char* chat_id) {
    if (!eg || !chat_id) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    if (!transport_is_connected(eg->transport)) {
        return EVERGRAM_ERR_NOT_CONNECTED;
    }
    
    fprintf(stderr, "AVISO: evergram_leave_chat() é um stub.\n");
    
    return EVERGRAM_SUCCESS;
}

int evergram_rotate_chat_version(evergram_t* eg, const char* chat_id) {
    if (!eg || !chat_id) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    if (!transport_is_connected(eg->transport)) {
        return EVERGRAM_ERR_NOT_CONNECTED;
    }
    
    fprintf(stderr, "AVISO: evergram_rotate_chat_version() é um stub.\n");
    
    return EVERGRAM_SUCCESS;
}

// ============================================================================
// Consultas e Informações (Stubs)
// ============================================================================

int evergram_get_profile(evergram_t* eg, const char* identity_key, 
                         evergram_profile_t* profile_out) {
    if (!eg || !identity_key || !profile_out) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    if (!transport_is_connected(eg->transport)) {
        return EVERGRAM_ERR_NOT_CONNECTED;
    }
    
    fprintf(stderr, "AVISO: evergram_get_profile() é um stub.\n");
    
    strncpy(profile_out->identity_key, identity_key, 
            sizeof(profile_out->identity_key) - 1);
    strcpy(profile_out->name, "Stub User");
    strcpy(profile_out->bio, "Stub bio");
    
    return EVERGRAM_SUCCESS;
}

int evergram_set_profile(evergram_t* eg, const char* name, const char* bio) {
    (void)name;  // Stub não usa parâmetros
    (void)bio;
    
    if (!eg) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    if (!transport_is_connected(eg->transport)) {
        return EVERGRAM_ERR_NOT_CONNECTED;
    }
    
    fprintf(stderr, "AVISO: evergram_set_profile() é um stub.\n");
    
    return EVERGRAM_SUCCESS;
}

int evergram_list_chats(evergram_t* eg, evergram_chat_info_t** chats_out, int max_chats) {
    if (!eg || !chats_out || max_chats <= 0) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    if (!transport_is_connected(eg->transport)) {
        return EVERGRAM_ERR_NOT_CONNECTED;
    }
    
    fprintf(stderr, "AVISO: evergram_list_chats() é um stub.\n");
    
    // Retorna 0 chats no stub
    return 0;
}

void evergram_free_chat_info(evergram_chat_info_t* chat) {
    if (!chat) return;
    
    // Liberar array de participantes se alocado
    if (chat->participants) {
        for (int i = 0; i < chat->participant_count; i++) {
            free(chat->participants[i]);
        }
        free(chat->participants);
    }
}
