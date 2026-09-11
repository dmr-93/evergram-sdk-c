/**
 * evergram-c - Handshake Implementation (Stub)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "evergram.h"
#include "evergram.pb-c.h"

extern int transport_send(void *ws_context, const uint8_t *data, size_t len);

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

int evergram_start_handshake(evergram_t *eg) {
    if (!eg) return -1;
    
    printf("[handshake] Starting handshake (stub)...\n");
    
    /* Em implementação real: enviar ClientHello */
    eg->hs_state = EVERGRAM_HS_CLIENT_HELLO_SENT;
    eg->handshake_start_time = time(NULL);
    
    /* Simular handshake completo para teste */
    eg->hs_state = EVERGRAM_HS_CONNECTED;
    eg->state = EVERGRAM_STATE_CONNECTED;
    eg->session_keys_ready = true;
    
    if (eg->on_connected) {
        eg->on_connected(eg);
    }
    
    return 0;
}

int evergram_process_handshake_data(evergram_t *eg, const uint8_t *data, size_t len) {
    if (!eg || !data) return -1;
    
    printf("[handshake] Processing %zu bytes (stub)...\n", len);
    
    /* Em implementação real: parse ServerHello e derivar chaves */
    eg->hs_state = EVERGRAM_HS_CONNECTED;
    eg->state = EVERGRAM_STATE_CONNECTED;
    eg->session_keys_ready = true;
    
    if (eg->on_connected) {
        eg->on_connected(eg);
    }
    
    return 0;
}

int evergram_check_handshake_timeout(evergram_t *eg) {
    if (!eg) return -1;
    
    time_t now = time(NULL);
    if (now - eg->handshake_start_time > 10) {
        printf("[handshake] Timeout!\n");
        return -1;
    }
    return 0;
}
