/*
 * Evergram SDK for C - Handshake Implementation
 * Implements the ClientHello/ServerHello protocol for establishing secure sessions
 */

#include "evergram.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sodium/crypto_box.h>
#include <sodium/randombytes.h>
#include <sodium/crypto_generichash.h>

// Protocol constants
#define EVERGRAM_PROTOCOL_VERSION 1
#define EVERGRAM_NONCE_SIZE       24
#define EVERGRAM_HANDSHAKE_TIMEOUT_MS 10000

/*
 * Build ClientHello message
 * Contains: protocol version, client capabilities, ephemeral public key
 */
static int build_client_hello(evergram_t* eg, uint8_t **out_buffer, size_t *out_size) {
    if (!eg || !out_buffer || !out_size) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }

    size_t hello_size = 1 + 2 + crypto_box_PUBLICKEYBYTES + 8 + EVERGRAM_NONCE_SIZE;
    uint8_t *buffer = (uint8_t *)malloc(hello_size);
    
    if (!buffer) {
        return EVERGRAM_ERR_MEMORY;
    }

    size_t offset = 0;
    buffer[offset++] = EVERGRAM_PROTOCOL_VERSION;

    uint16_t capabilities = 0x0007;
    buffer[offset++] = capabilities & 0xFF;
    buffer[offset++] = (capabilities >> 8) & 0xFF;

    memcpy(buffer + offset, eg->handshake.ephemeral_pubkey, crypto_box_PUBLICKEYBYTES);
    offset += crypto_box_PUBLICKEYBYTES;

    uint64_t timestamp = (uint64_t)time(NULL) * 1000;
    for (int i = 0; i < 8; i++) {
        buffer[offset++] = (timestamp >> (i * 8)) & 0xFF;
    }

    randombytes_buf(buffer + offset, EVERGRAM_NONCE_SIZE);
    memcpy(eg->handshake.client_nonce, buffer + offset, EVERGRAM_NONCE_SIZE);
    offset += EVERGRAM_NONCE_SIZE;

    *out_buffer = buffer;
    *out_size = hello_size;

    printf("[HANDSHAKE] ClientHello built: version=%d, caps=0x%04X, timestamp=%lu\n", 
           EVERGRAM_PROTOCOL_VERSION, capabilities, (unsigned long)timestamp);
    
    return EVERGRAM_SUCCESS;
}

/*
 * Parse ServerHello response
 */
static int parse_server_hello(evergram_t* eg, const uint8_t *buffer, size_t size) {
    if (!eg || !buffer || size < (1 + 2 + crypto_box_PUBLICKEYBYTES + 8 + EVERGRAM_NONCE_SIZE)) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }

    size_t offset = 0;
    uint8_t server_version = buffer[offset++];
    
    if (server_version != EVERGRAM_PROTOCOL_VERSION) {
        fprintf(stderr, "[HANDSHAKE] Protocol version mismatch: expected %d, got %d\n", 
                EVERGRAM_PROTOCOL_VERSION, server_version);
        return EVERGRAM_ERR_PROTO;
    }

    uint16_t server_caps = buffer[offset] | (buffer[offset + 1] << 8);
    offset += 2;
    printf("[HANDSHAKE] Server capabilities: 0x%04X\n", server_caps);

    memcpy(eg->handshake.server_ephemeral_pubkey, buffer + offset, crypto_box_PUBLICKEYBYTES);
    offset += crypto_box_PUBLICKEYBYTES;
    printf("[HANDSHAKE] Server ephemeral key received\n");

    uint64_t server_timestamp = 0;
    for (int i = 0; i < 8; i++) {
        server_timestamp |= ((uint64_t)buffer[offset++]) << (i * 8);
    }
    
    uint64_t current_time = (uint64_t)time(NULL) * 1000;
    if (current_time - server_timestamp > 300000) {
        fprintf(stderr, "[HANDSHAKE] Server timestamp too old or clock skew detected\n");
        return EVERGRAM_ERR_PROTO;
    }

    memcpy(eg->handshake.server_nonce, buffer + offset, EVERGRAM_NONCE_SIZE);
    offset += EVERGRAM_NONCE_SIZE;

    printf("[HANDSHAKE] ServerHello parsed successfully\n");
    return EVERGRAM_SUCCESS;
}

/*
 * Derive shared session keys from ephemeral key exchange
 */
static int derive_session_keys(evergram_t* eg) {
    if (!eg) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }

    unsigned char shared_secret[crypto_box_BEFORENMBYTES];
    
    if (crypto_box_beforenm(shared_secret, 
                            eg->handshake.server_ephemeral_pubkey,
                            eg->handshake.ephemeral_privkey) != 0) {
        fprintf(stderr, "[HANDSHAKE] Failed to derive shared secret\n");
        return EVERGRAM_ERR_CRYPTO;
    }

    printf("[HANDSHAKE] Shared secret derived successfully\n");

    uint8_t context[] = "evergram-session-v1";
    uint8_t send_label[] = "send-key";
    uint8_t recv_label[] = "recv-key";
    
    unsigned char send_key_material[crypto_box_BEFORENMBYTES + sizeof(context) + sizeof(send_label)];
    unsigned char recv_key_material[crypto_box_BEFORENMBYTES + sizeof(context) + sizeof(recv_label)];
    
    memcpy(send_key_material, shared_secret, crypto_box_BEFORENMBYTES);
    memcpy(send_key_material + crypto_box_BEFORENMBYTES, context, sizeof(context));
    memcpy(send_key_material + crypto_box_BEFORENMBYTES + sizeof(context), send_label, sizeof(send_label));
    
    memcpy(recv_key_material, shared_secret, crypto_box_BEFORENMBYTES);
    memcpy(recv_key_material + crypto_box_BEFORENMBYTES, context, sizeof(context));
    memcpy(recv_key_material + crypto_box_BEFORENMBYTES + sizeof(context), recv_label, sizeof(recv_label));
    
    if (crypto_generichash(eg->session.send_key, sizeof(eg->session.send_key),
                          send_key_material, sizeof(send_key_material),
                          NULL, 0) != 0) {
        return EVERGRAM_ERR_CRYPTO;
    }
    
    if (crypto_generichash(eg->session.recv_key, sizeof(eg->session.recv_key),
                          recv_key_material, sizeof(recv_key_material),
                          NULL, 0) != 0) {
        return EVERGRAM_ERR_CRYPTO;
    }

    memset(eg->session.send_nonce, 0, EVERGRAM_NONCE_SIZE);
    memset(eg->session.recv_nonce, 0, EVERGRAM_NONCE_SIZE);
    eg->session.send_nonce_counter = 0;
    eg->session.recv_nonce_counter = 0;

    printf("[HANDSHAKE] Session keys derived and nonces initialized\n");
    return EVERGRAM_SUCCESS;
}

/*
 * Send ClientHello over WebSocket
 */
static int send_client_hello(evergram_t* eg) {
    if (!eg || !eg->transport) {
        return EVERGRAM_ERR_NOT_CONNECTED;
    }

    uint8_t *hello_buffer = NULL;
    size_t hello_size = 0;
    
    int ret = build_client_hello(eg, &hello_buffer, &hello_size);
    if (ret != EVERGRAM_SUCCESS) {
        return ret;
    }

    printf("[HANDSHAKE] Sending ClientHello (%zu bytes)...\n", hello_size);
    
    // TODO: Replace with actual WebSocket send
    free(hello_buffer);
    
    eg->hs_state = EVERGRAM_HS_CLIENT_HELLO_SENT;
    printf("[HANDSHAKE] ClientHello sent, waiting for ServerHello...\n");
    
    return EVERGRAM_SUCCESS;
}

/*
 * Process incoming handshake data
 */
int evergram_process_handshake_data(evergram_t* eg, const uint8_t *data, size_t size) {
    if (!eg || !data || size == 0) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }

    if (eg->hs_state != EVERGRAM_HS_CLIENT_HELLO_SENT) {
        fprintf(stderr, "[HANDSHAKE] Unexpected state %d for incoming data\n", eg->hs_state);
        return EVERGRAM_ERR_STATE;
    }

    printf("[HANDSHAKE] Processing ServerHello (%zu bytes)...\n", size);
    
    int ret = parse_server_hello(eg, data, size);
    if (ret != EVERGRAM_SUCCESS) {
        eg->state = EVERGRAM_STATE_ERROR;
        return ret;
    }
    
    ret = derive_session_keys(eg);
    if (ret != EVERGRAM_SUCCESS) {
        eg->state = EVERGRAM_STATE_ERROR;
        return ret;
    }
    
    eg->state = EVERGRAM_STATE_CONNECTED;
    printf("[HANDSHAKE] Handshake completed successfully!\n");
    
    if (eg->on_connected) {
        eg->on_connected(eg);
    }
    
    return EVERGRAM_SUCCESS;
}

/*
 * Initialize handshake state and generate ephemeral keys
 */
static int evergram_init_handshake(evergram_t* eg) {
    if (!eg) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }

    printf("[HANDSHAKE] Initializing handshake...\n");

    if (crypto_box_keypair(eg->handshake.ephemeral_pubkey, 
                          eg->handshake.ephemeral_privkey) != 0) {
        fprintf(stderr, "[HANDSHAKE] Failed to generate ephemeral keypair\n");
        return EVERGRAM_ERR_CRYPTO;
    }

    printf("[HANDSHAKE] Ephemeral keypair generated\n");

    memset(eg->handshake.client_nonce, 0, EVERGRAM_NONCE_SIZE);
    memset(eg->handshake.server_nonce, 0, EVERGRAM_NONCE_SIZE);
    memset(eg->handshake.server_ephemeral_pubkey, 0, crypto_box_PUBLICKEYBYTES);
    eg->handshake.started_at = time(NULL);
    eg->hs_state = EVERGRAM_HS_CONNECTING;
    
    return EVERGRAM_SUCCESS;
}

/*
 * Start the handshake process
 */
int evergram_start_handshake(evergram_t* eg) {
    if (!eg) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }

    if (eg->state != EVERGRAM_STATE_CONNECTING) {
        fprintf(stderr, "[HANDSHAKE] Cannot start handshake in state %d\n", eg->state);
        return EVERGRAM_ERR_STATE;
    }

    printf("[HANDSHAKE] Starting handshake protocol...\n");

    int ret = evergram_init_handshake(eg);
    if (ret != EVERGRAM_SUCCESS) {
        return ret;
    }

    ret = send_client_hello(eg);
    if (ret != EVERGRAM_SUCCESS) {
        eg->state = EVERGRAM_STATE_ERROR;
        return ret;
    }

    return EVERGRAM_SUCCESS;
}

/*
 * Check if handshake has timed out
 */
int evergram_check_handshake_timeout(evergram_t* eg) {
    if (!eg || eg->hs_state != EVERGRAM_HS_CLIENT_HELLO_SENT) {
        return EVERGRAM_SUCCESS;
    }

    time_t now = time(NULL);
    if (now - eg->handshake.started_at > (EVERGRAM_HANDSHAKE_TIMEOUT_MS / 1000)) {
        fprintf(stderr, "[HANDSHAKE] Handshake timeout exceeded\n");
        eg->state = EVERGRAM_STATE_ERROR;
        
        if (eg->on_error) {
            eg->on_error(eg, EVERGRAM_ERR_TIMEOUT, "Handshake timeout");
        }
        
        return EVERGRAM_ERR_TIMEOUT;
    }

    return EVERGRAM_SUCCESS;
}
