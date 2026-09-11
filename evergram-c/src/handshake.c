/**
 * evergram-c - Handshake Implementation (Real)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "evergram.h"
#include "protobuf_generated.h"
#include <sodium.h>

extern int transport_send(void *ws_context, const uint8_t *data, size_t len);

/* Definição completa da struct para acesso interno */
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
    /* Campos adicionais para handshake */
    unsigned char ephemeral_secret[32];
    unsigned char ephemeral_public[32];
    unsigned char server_public[32];
    char session_id[64];
};

/**
 * Constrói mensagem ClientHello usando protobuf
 */
static int build_client_hello(evergram_t *eg, uint8_t **out_data, size_t *out_len) {
    if (!eg || !out_data || !out_len) return -1;
    
    Evergram__ClientHello hello = EVERGRAM__CLIENT_HELLO__INIT;
    Evergram__Envelope env = EVERGRAM__ENVELOPE__INIT;
    
    /* Gera nonce aleatório */
    uint8_t nonce[24];
    randombytes_buf(nonce, sizeof(nonce));
    
    hello.version = strdup("1.0.0");
    hello.ephemeral_public_key.len = 32;
    hello.ephemeral_public_key.data = eg->ephemeral_public;
    hello.nonce.len = sizeof(nonce);
    hello.nonce.data = nonce;
    hello.device_id = eg->device.device_id;
    hello.wallet_address = eg->wallet.address;
    
    /* Assina o ClientHello com a chave privada da carteira */
    unsigned char signature[64];
    unsigned char msg_to_sign[128];
    memcpy(msg_to_sign, eg->ephemeral_public, 32);
    memcpy(msg_to_sign + 32, nonce, 24);
    memcpy(msg_to_sign + 56, eg->device.device_id, strlen(eg->device.device_id));
    
    if (crypto_sign_detached(signature, NULL, msg_to_sign, 56 + strlen(eg->device.device_id),
                             (unsigned char*)eg->wallet.private_key_hex) != 0) {
        free(hello.version);
        return -1;
    }
    hello.signature.len = 64;
    hello.signature.data = signature;
    
    /* Monta o envelope */
    env.payload_case = EVERGRAM__ENVELOPE__PAYLOAD_CLIENT_HELLO;
    env.client_hello = &hello;
    env.nonce.len = sizeof(nonce);
    env.nonce.data = nonce;
    
    /* Serializa */
    size_t len = evergram__envelope__get_packed_size(&env);
    uint8_t *data = malloc(len);
    if (!data) {
        free(hello.version);
        return -1;
    }
    evergram__envelope__pack(&env, data);
    
    *out_data = data;
    *out_len = len;
    
    free(hello.version);
    return 0;
}

/**
 * Parse ServerHello e deriva chaves de sessão
 */
static int parse_server_hello(evergram_t *eg, const uint8_t *data, size_t len) {
    if (!eg || !data) return -1;
    
    Evergram__ServerHello *server_hello = 
        evergram__server_hello__unpack(NULL, len, data);
    if (!server_hello) {
        fprintf(stderr, "[handshake] Failed to unpack ServerHello\n");
        return -1;
    }
    
    if (!server_hello->success) {
        fprintf(stderr, "[handshake] Server rejected: %s\n", 
                server_hello->error_message ? server_hello->error_message : "unknown");
        evergram__server_hello__free_unpacked(server_hello, NULL);
        return -1;
    }
    
    /* Copia chave pública do servidor */
    if (server_hello->server_public_key.len != 32) {
        fprintf(stderr, "[handshake] Invalid server public key length\n");
        evergram__server_hello__free_unpacked(server_hello, NULL);
        return -1;
    }
    memcpy(eg->server_public, server_hello->server_public_key.data, 32);
    
    /* Deriva chave de sessão usando ECDH */
    unsigned char qstate[crypto_box_BEFORENMBYTES];
    if (crypto_box_beforenm(qstate, eg->server_public, eg->ephemeral_secret) != 0) {
        fprintf(stderr, "[handshake] ECDH failed\n");
        evergram__server_hello__free_unpacked(server_hello, NULL);
        return -1;
    }
    
    /* Usa primeiros 32 bytes como chave de sessão */
    memcpy(eg->session_key, qstate, 32);
    eg->session_keys_ready = true;
    
    /* Copia session ID */
    if (server_hello->session_id) {
        strncpy(eg->session_id, server_hello->session_id, sizeof(eg->session_id) - 1);
    }
    
    evergram__server_hello__free_unpacked(server_hello, NULL);
    return 0;
}

int evergram_start_handshake(evergram_t *eg) {
    if (!eg) return -1;
    
    printf("[handshake] Starting handshake with staging.evergram.app...\n");
    
    /* Gera par de chaves efêmeras */
    if (crypto_box_keypair(eg->ephemeral_public, eg->ephemeral_secret) != 0) {
        fprintf(stderr, "[handshake] Failed to generate ephemeral keys\n");
        return -1;
    }
    
    /* Constrói ClientHello */
    uint8_t *hello_data = NULL;
    size_t hello_len = 0;
    if (build_client_hello(eg, &hello_data, &hello_len) != 0) {
        fprintf(stderr, "[handshake] Failed to build ClientHello\n");
        return -1;
    }
    
    /* Envia ClientHello */
    if (transport_send(eg->ws_context, hello_data, hello_len) != 0) {
        fprintf(stderr, "[handshake] Failed to send ClientHello\n");
        free(hello_data);
        return -1;
    }
    free(hello_data);
    
    eg->hs_state = EVERGRAM_HS_CLIENT_HELLO_SENT;
    eg->handshake_start_time = time(NULL);
    eg->state = EVERGRAM_STATE_AUTHENTICATING;
    
    printf("[handshake] ClientHello sent, waiting for ServerHello...\n");
    return 0;
}

int evergram_process_handshake_data(evergram_t *eg, const uint8_t *data, size_t len) {
    if (!eg || !data) return -1;
    
    if (eg->hs_state != EVERGRAM_HS_CLIENT_HELLO_SENT) {
        fprintf(stderr, "[handshake] Unexpected state %d\n", eg->hs_state);
        return -1;
    }
    
    printf("[handshake] Processing ServerHello (%zu bytes)...\n", len);
    
    if (parse_server_hello(eg, data, len) != 0) {
        fprintf(stderr, "[handshake] Failed to process ServerHello\n");
        eg->hs_state = EVERGRAM_HS_ERROR;
        eg->state = EVERGRAM_STATE_ERROR;
        return -1;
    }
    
    eg->hs_state = EVERGRAM_HS_CONNECTED;
    eg->state = EVERGRAM_STATE_CONNECTED;
    
    printf("[handshake] Handshake complete! Session established.\n");
    
    if (eg->on_connected) {
        eg->on_connected(eg);
    }
    
    return 0;
}

int evergram_check_handshake_timeout(evergram_t *eg) {
    if (!eg) return -1;
    
    if (eg->hs_state == EVERGRAM_HS_CLIENT_HELLO_SENT) {
        time_t now = time(NULL);
        if (now - eg->handshake_start_time > 10) {
            fprintf(stderr, "[handshake] Timeout waiting for ServerHello\n");
            eg->hs_state = EVERGRAM_HS_ERROR;
            eg->state = EVERGRAM_STATE_ERROR;
            return -1;
        }
    }
    return 0;
}
