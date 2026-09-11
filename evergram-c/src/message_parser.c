/**
 * evergram-c - Message Parser and Router (Corrigido)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "evergram.h"
#include "evergram.pb-c.h"

/* Estrutura interna */
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

/**
 * Processa dados recebidos do transporte
 */
int evergram_process_incoming_data(evergram_t *eg, const uint8_t *data, size_t len) {
    if (!eg || !data || len == 0) {
        return -1;
    }

    /* Adicionar dados ao buffer */
    if (eg->recv_buffer_len + len > eg->recv_buffer_size) {
        size_t new_size = eg->recv_buffer_size + len + 10000;
        uint8_t *new_buffer = realloc(eg->recv_buffer, new_size);
        if (!new_buffer) {
            return -1;
        }
        eg->recv_buffer = new_buffer;
        eg->recv_buffer_size = new_size;
    }

    memcpy(eg->recv_buffer + eg->recv_buffer_len, data, len);
    eg->recv_buffer_len += len;

    int messages_processed = 0;
    
    while (eg->recv_buffer_len >= 5) {
        uint8_t msg_type = eg->recv_buffer[0];
        
        uint32_t payload_len = 
            ((uint32_t)eg->recv_buffer[1] << 24) |
            ((uint32_t)eg->recv_buffer[2] << 16) |
            ((uint32_t)eg->recv_buffer[3] << 8) |
            ((uint32_t)eg->recv_buffer[4]);

        if (payload_len > 10000000) {
            eg->recv_buffer_len = 0;
            return -1;
        }

        size_t total_msg_len = 1 + 4 + payload_len;
        
        if (eg->recv_buffer_len < total_msg_len) {
            break;
        }

        const uint8_t *payload = eg->recv_buffer + 5;
        
        /* Aqui entraria o decrypt e parse protobuf */
        /* Por enquanto apenas avisa que recebeu dados */
        printf("[DEBUG] Received message type %u, len %u\n", msg_type, payload_len);
        
        messages_processed++;

        memmove(eg->recv_buffer, eg->recv_buffer + total_msg_len, eg->recv_buffer_len - total_msg_len);
        eg->recv_buffer_len -= total_msg_len;
    }

    return messages_processed;
}

int evergram_init_parser(evergram_t *eg) {
    if (!eg) {
        return -1;
    }

    eg->recv_buffer = malloc(4096);
    if (!eg->recv_buffer) {
        return -1;
    }
    eg->recv_buffer_size = 4096;
    eg->recv_buffer_len = 0;
    eg->recv_nonce = 0;
    eg->send_nonce = 0;

    return 0;
}

void evergram_cleanup_parser(evergram_t *eg) {
    if (eg && eg->recv_buffer) {
        free(eg->recv_buffer);
        eg->recv_buffer = NULL;
        eg->recv_buffer_size = 0;
        eg->recv_buffer_len = 0;
    }
}
