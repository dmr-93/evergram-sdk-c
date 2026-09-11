/**
 * evergram-c - Implementação Principal (v4 - com proto real)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <stdarg.h>
#include "evergram.h"
#include "evergram.pb-c.h"

extern int evergram_init_parser(evergram_t *eg);
extern void evergram_cleanup_parser(evergram_t *eg);
extern int evergram_process_incoming_data(evergram_t *eg, const uint8_t *data, size_t len);
extern int evergram_start_handshake(evergram_t *eg);
extern int evergram_process_handshake_data(evergram_t *eg, const uint8_t *data, size_t len);
extern int evergram_check_handshake_timeout(evergram_t *eg);
extern int transport_connect(const char *url, void **ws_context);
extern int transport_send(void *ws_context, const uint8_t *data, size_t len);
extern int transport_poll(void *ws_context, uint8_t *buffer, size_t max_len, int timeout_ms);
extern void transport_disconnect(void *ws_context);
extern int xrpl_generate_wallet(evergram_wallet_t *wallet);
extern int xrpl_generate_device(evergram_device_t *device, const evergram_wallet_t *wallet);

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

static int send_encrypted_message(evergram_t *eg, uint8_t msg_type, const uint8_t *payload, size_t payload_len) {
    if (!eg || !eg->session_keys_ready) return EVERGRAM_ERR_NOT_CONNECTED;
    
    unsigned char encrypted[payload_len + 16];
    unsigned char nonce[12];
    memset(nonce, 0, 4);
    for (int i = 0; i < 8; i++) nonce[4 + i] = (eg->send_nonce >> (i * 8)) & 0xFF;
    
    if (evergram_encrypt_message(payload, payload_len, nonce, eg->session_key, encrypted, NULL) != EVERGRAM_SUCCESS)
        return EVERGRAM_ERR_CRYPTO;
    
    // Envia diretamente os dados criptografados com header [type][length][encrypted_data]
    uint8_t header[5];
    header[0] = msg_type;
    header[1] = ((payload_len + 16) >> 24) & 0xFF;
    header[2] = ((payload_len + 16) >> 16) & 0xFF;
    header[3] = ((payload_len + 16) >> 8) & 0xFF;
    header[4] = (payload_len + 16) & 0xFF;
    
    int result = transport_send(eg->ws_context, header, 5);
    if (result < 0) return EVERGRAM_ERR_NETWORK;
    
    result = transport_send(eg->ws_context, encrypted, payload_len + 16);
    if (result < 0) return EVERGRAM_ERR_NETWORK;
    
    eg->send_nonce++;
    return EVERGRAM_SUCCESS;
}

int evergram_start(evergram_t *eg) {
    if (!eg) return EVERGRAM_ERR_INVALID_PARAM;
    if (transport_connect(eg->server_url, &eg->ws_context) != 0) {
        if (eg->on_error) eg->on_error(eg, EVERGRAM_ERR_NETWORK, "Failed to connect");
        return EVERGRAM_ERR_NETWORK;
    }
    if (evergram_init_parser(eg) != 0) {
        transport_disconnect(eg->ws_context);
        if (eg->on_error) eg->on_error(eg, EVERGRAM_ERR_MEMORY, "Failed to init parser");
        return EVERGRAM_ERR_MEMORY;
    }
    eg->state = EVERGRAM_STATE_CONNECTING;
    eg->hs_state = EVERGRAM_HS_CONNECTING;
    eg->handshake_start_time = time(NULL);
    if (evergram_start_handshake(eg) != 0) {
        evergram_cleanup_parser(eg);
        transport_disconnect(eg->ws_context);
        if (eg->on_error) eg->on_error(eg, EVERGRAM_ERR_AUTH, "Failed handshake");
        return EVERGRAM_ERR_AUTH;
    }
    return EVERGRAM_SUCCESS;
}

int evergram_poll(evergram_t *eg, int timeout_ms) {
    if (!eg || eg->state == EVERGRAM_STATE_DISCONNECTED) return EVERGRAM_ERR_INVALID_PARAM;
    uint8_t buffer[10000];
    int bytes_read = transport_poll(eg->ws_context, buffer, sizeof(buffer), timeout_ms);
    if (bytes_read < 0) {
        if (bytes_read == -2) {
            if (eg->hs_state < EVERGRAM_HS_CONNECTED) {
                if (evergram_check_handshake_timeout(eg) != 0) {
                    eg->state = EVERGRAM_STATE_DISCONNECTED;
                    if (eg->on_disconnected) eg->on_disconnected(eg);
                    return EVERGRAM_ERR_TIMEOUT;
                }
            }
            return EVERGRAM_SUCCESS;
        }
        eg->state = EVERGRAM_STATE_DISCONNECTED;
        if (eg->on_disconnected) eg->on_disconnected(eg);
        return EVERGRAM_ERR_NETWORK;
    }
    if (bytes_read == 0) {
        eg->state = EVERGRAM_STATE_DISCONNECTED;
        if (eg->on_disconnected) eg->on_disconnected(eg);
        return EVERGRAM_ERR_NETWORK;
    }
    if (eg->hs_state < EVERGRAM_HS_CONNECTED) {
        if (evergram_process_handshake_data(eg, buffer, bytes_read) != 0)
            return EVERGRAM_ERR_AUTH;
    } else {
        int msgs = evergram_process_incoming_data(eg, buffer, bytes_read);
        if (msgs < 0) return EVERGRAM_ERR_PROTO;
    }
    return EVERGRAM_SUCCESS;
}

int evergram_send(evergram_t *eg, const char *chat_id, const char *content) {
    if (!eg || !chat_id || !content || eg->state != EVERGRAM_STATE_CONNECTED)
        return EVERGRAM_ERR_INVALID_PARAM;
    
    // O conteúdo precisa ser criptografado antes de enviar
    // Para simplificar, vamos enviar o texto puro no campo ciphertext
    // Em produção, deve-se usar a chave da sessão para criptografar
    Evergram__SendContent send_content = EVERGRAM__SEND_CONTENT__INIT;
    char msg_id[64];
    snprintf(msg_id, sizeof(msg_id), "msg_%lu", (unsigned long)time(NULL));
    send_content.msg_id = msg_id;
    send_content.ciphertext = (char*)content;  // Texto puro (em produção, criptografar)
    send_content.nonce = "";  // Nonce vazio (em produção, usar nonce real)
    send_content.reply_to_msg_id = "";
    
    // Criar Envelope
    Evergram__Envelope envelope = EVERGRAM__ENVELOPE__INIT;
    envelope.type = "SEND";
    envelope.chat_id = (char*)chat_id;
    envelope.sender = (char*)eg->wallet.address;
    envelope.content_case = EVERGRAM__ENVELOPE__CONTENT_SEND;
    envelope.send = &send_content;
    
    size_t env_size = evergram__envelope__get_packed_size(&envelope);
    uint8_t *env_data = malloc(env_size);
    if (!env_data) return EVERGRAM_ERR_MEMORY;
    evergram__envelope__pack(&envelope, env_data);
    
    int result = send_encrypted_message(eg, 1, env_data, env_size);
    free(env_data);
    return result;
}

int evergram_sendf(evergram_t *eg, const char *chat_id, const char *format, ...) {
    if (!eg || !chat_id || !format) return EVERGRAM_ERR_INVALID_PARAM;
    char buffer[10000];
    va_list args;
    va_start(args, format);
    int len = vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    if (len < 0 || len >= (int)sizeof(buffer)) return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    return evergram_send(eg, chat_id, buffer);
}

int evergram_reply(evergram_t* eg, const evergram_message_t* reply_to, const char* content, ...) {
    if (!eg || !reply_to || !content) return EVERGRAM_ERR_INVALID_PARAM;
    return evergram_send(eg, reply_to->chat_id, content);
}

int evergram_react(evergram_t *eg, const char *chat_id, const char *message_id, const char *emoji) {
    if (!eg || !chat_id || !message_id || !emoji || eg->state != EVERGRAM_STATE_CONNECTED)
        return EVERGRAM_ERR_INVALID_PARAM;
    
    // Criar ReactContent (emoji vai puro no ciphertext para simplificar)
    Evergram__ReactContent react_content = EVERGRAM__REACT_CONTENT__INIT;
    react_content.msg_id = (char*)message_id;
    react_content.ciphertext = (char*)emoji;  // Emoji puro (em produção, criptografar)
    react_content.nonce = "";  // Nonce vazio (em produção, usar nonce real)
    react_content.has_removed = 0;
    react_content.removed = 0;
    
    // Criar Envelope
    Evergram__Envelope envelope = EVERGRAM__ENVELOPE__INIT;
    envelope.type = "REACT";
    envelope.chat_id = (char*)chat_id;
    envelope.sender = (char*)eg->wallet.address;
    envelope.content_case = EVERGRAM__ENVELOPE__CONTENT_REACT;
    envelope.react = &react_content;
    
    size_t env_size = evergram__envelope__get_packed_size(&envelope);
    uint8_t *env_data = malloc(env_size);
    if (!env_data) return EVERGRAM_ERR_MEMORY;
    evergram__envelope__pack(&envelope, env_data);
    
    int result = send_encrypted_message(eg, 2, env_data, env_size);
    free(env_data);
    return result;
}

int evergram_typing(evergram_t *eg, const char *chat_id, bool is_typing) {
    if (!eg || !chat_id || eg->state != EVERGRAM_STATE_CONNECTED)
        return EVERGRAM_ERR_INVALID_PARAM;
    
    // Criar TypingContent
    Evergram__TypingContent typing_content = EVERGRAM__TYPING_CONTENT__INIT;
    typing_content.is_typing = is_typing ? 1 : 0;
    
    // Criar Envelope
    Evergram__Envelope envelope = EVERGRAM__ENVELOPE__INIT;
    envelope.type = "TYPING";
    envelope.chat_id = (char*)chat_id;
    envelope.sender = (char*)eg->wallet.address;
    envelope.content_case = EVERGRAM__ENVELOPE__CONTENT_TYPING;
    envelope.typing = &typing_content;
    
    size_t env_size = evergram__envelope__get_packed_size(&envelope);
    uint8_t *env_data = malloc(env_size);
    if (!env_data) return EVERGRAM_ERR_MEMORY;
    evergram__envelope__pack(&envelope, env_data);
    
    int result = send_encrypted_message(eg, 3, env_data, env_size);
    free(env_data);
    return result;
}

void evergram_set_message_callback(evergram_t *eg, evergram_message_callback cb, void *user_data) {
    if (eg) { eg->on_message = cb; eg->user_data = user_data; }
}
void evergram_set_reaction_callback(evergram_t *eg, evergram_reaction_callback cb, void *user_data) {
    if (eg) { eg->on_reaction = cb; eg->user_data = user_data; }
}
void evergram_set_typing_callback(evergram_t *eg, evergram_typing_callback cb, void *user_data) {
    if (eg) { eg->on_typing = cb; eg->user_data = user_data; }
}
void evergram_set_error_callback(evergram_t *eg, evergram_error_callback cb, void *user_data) {
    if (eg) { eg->on_error = cb; eg->user_data = user_data; }
}
void evergram_set_connected_callback(evergram_t *eg, evergram_connected_callback cb, void *user_data) {
    if (eg) { eg->on_connected = cb; eg->user_data = user_data; }
}
void evergram_set_disconnected_callback(evergram_t *eg, evergram_disconnected_callback cb, void *user_data) {
    if (eg) { eg->on_disconnected = cb; eg->user_data = user_data; }
}
void evergram_set_chat_synced_callback(evergram_t *eg, evergram_chat_synced_callback cb, void *user_data) {
    if (eg) { eg->on_chat_synced = cb; eg->user_data = user_data; }
}

evergram_state_t evergram_get_state(evergram_t *eg) {
    return eg ? eg->state : EVERGRAM_STATE_DISCONNECTED;
}
const evergram_wallet_t* evergram_get_wallet(evergram_t *eg) {
    return eg ? &eg->wallet : NULL;
}
const evergram_device_t* evergram_get_device(evergram_t *eg) {
    return eg ? &eg->device : NULL;
}

void evergram_destroy(evergram_t *eg) {
    if (!eg) return;
    if (eg->ws_context) transport_disconnect(eg->ws_context);
    evergram_cleanup_parser(eg);
    if (eg->server_url) free(eg->server_url);
    free(eg);
}
