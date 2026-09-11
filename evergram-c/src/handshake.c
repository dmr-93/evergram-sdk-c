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

// Forward declaration da estrutura interna (definida em evergram.c)
typedef struct evergram_internal {
    int dummy; // Placeholder para compilar
} evergram_internal_t;

struct evergram {
    evergram_options_t options;
    evergram_state_t state;
    evergram_hs_state_t hs_state;
    char nonce[EVERGRAM_MAX_NONCE_LEN];
    
    void (*on_msg)(struct evergram*, const void*);
    void (*on_reaction)(struct evergram*, const char*, const char*, int);
    void (*on_typing)(struct evergram*, const char*, int);
    void (*on_error)(struct evergram*, int, const char*);
    void (*on_connected)(struct evergram*);
    void (*on_disconnected)(struct evergram*);
    void (*on_chat_synced)(struct evergram*, int);
    
    void* transport;
    
    struct {
        unsigned char ephemeral_pubkey[32];
        unsigned char ephemeral_privkey[32];
        unsigned char server_ephemeral_pubkey[32];
        unsigned char client_nonce[24];
        unsigned char server_nonce[24];
        time_t started_at;
    } handshake;
    
    struct {
        unsigned char send_key[32];
        unsigned char recv_key[32];
        unsigned char send_nonce[24];
        unsigned char recv_nonce[24];
        uint64_t send_nonce_counter;
        uint64_t recv_nonce_counter;
    } session;
    
    void* chats;
    int chat_count;
    void* user_data;
};

// Protótipos das funções de transporte (definidas em transport_websocket.c)
int transport_send(void* transport, const uint8_t* data, size_t len);

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
    return EVERGRAM_SUCCESS;
}

/*
 * Parse ServerHello response
 * Extracts: server ephemeral public key, server nonce, session ID
 */
static int parse_server_hello(evergram_t* eg, const uint8_t* buffer, size_t size) {
    if (!eg || !buffer || size < (1 + crypto_box_PUBLICKEYBYTES + EVERGRAM_NONCE_SIZE + 8)) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }

    size_t offset = 0;
    uint8_t server_version = buffer[offset++];
    
    if (server_version != EVERGRAM_PROTOCOL_VERSION) {
        fprintf(stderr, "[HANDSHAKE] Protocol version mismatch: expected %d, got %d\n", 
                EVERGRAM_PROTOCOL_VERSION, server_version);
        return EVERGRAM_ERR_PROTO;
    }

    memcpy(eg->handshake.server_ephemeral_pubkey, buffer + offset, crypto_box_PUBLICKEYBYTES);
    offset += crypto_box_PUBLICKEYBYTES;

    memcpy(eg->handshake.server_nonce, buffer + offset, EVERGRAM_NONCE_SIZE);
    offset += EVERGRAM_NONCE_SIZE;

    uint64_t session_id = 0;
    for (int i = 0; i < 8; i++) {
        session_id |= ((uint64_t)buffer[offset++]) << (i * 8);
    }

    fprintf(stderr, "[HANDSHAKE] ServerHello parsed successfully, session_id=%lu\n", 
            (unsigned long)session_id);
    return EVERGRAM_SUCCESS;
}

/*
 * Derive session keys using ECDH
 * Uses libsodium's crypto_box_beforenm for key derivation
 */
static int derive_session_keys(evergram_t* eg) {
    if (!eg) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }

    unsigned char shared_secret[crypto_box_BEFORENMBYTES];
    
    if (crypto_box_beforenm(shared_secret,
                            eg->handshake.server_ephemeral_pubkey,
                            eg->handshake.ephemeral_privkey) != 0) {
        fprintf(stderr, "[HANDSHAKE] Key derivation failed\n");
        return EVERGRAM_ERR_CRYPTO;
    }

    if (crypto_generichash(eg->session.send_key, sizeof(eg->session.send_key),
                           shared_secret, sizeof(shared_secret),
                           eg->handshake.client_nonce, EVERGRAM_NONCE_SIZE) != 0) {
        return EVERGRAM_ERR_CRYPTO;
    }

    if (crypto_generichash(eg->session.recv_key, sizeof(eg->session.recv_key),
                           shared_secret, sizeof(shared_secret),
                           eg->handshake.server_nonce, EVERGRAM_NONCE_SIZE) != 0) {
        return EVERGRAM_ERR_CRYPTO;
    }

    memset(eg->session.send_nonce, 0, EVERGRAM_NONCE_SIZE);
    memset(eg->session.recv_nonce, 0, EVERGRAM_NONCE_SIZE);
    eg->session.send_nonce_counter = 0;
    eg->session.recv_nonce_counter = 0;

    fprintf(stderr, "[HANDSHAKE] Session keys derived successfully\n");
    return EVERGRAM_SUCCESS;
}

/*
 * Send ClientHello to server
 */
static int send_client_hello(evergram_t* eg) {
    if (!eg || !eg->transport) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }

    uint8_t* hello_buffer = NULL;
    size_t hello_size = 0;
    
    int ret = build_client_hello(eg, &hello_buffer, &hello_size);
    if (ret != EVERGRAM_SUCCESS) {
        return ret;
    }

    fprintf(stderr, "[HANDSHAKE] Sending ClientHello (%zu bytes)\n", hello_size);
    
    ret = transport_send(eg->transport, hello_buffer, hello_size);
    free(hello_buffer);
    
    if (ret != EVERGRAM_SUCCESS) {
        return ret;
    }

    eg->hs_state = EVERGRAM_HS_CLIENT_HELLO_SENT;
    return EVERGRAM_SUCCESS;
}

/*
 * Process incoming handshake data
 * Called when ServerHello is received
 */
int evergram_process_handshake_data(evergram_t* eg, const uint8_t* data, size_t len) {
    if (!eg || !data || len == 0) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }

    if (eg->hs_state != EVERGRAM_HS_CLIENT_HELLO_SENT) {
        fprintf(stderr, "[HANDSHAKE] Unexpected state %d for incoming data\n", eg->hs_state);
        return EVERGRAM_ERR_PROTO;
    }

    int ret = parse_server_hello(eg, data, len);
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
    eg->hs_state = EVERGRAM_HS_CONNECTED;

    fprintf(stderr, "[HANDSHAKE] Handshake completed successfully\n");

    if (eg->on_connected) {
        eg->on_connected(eg);
    }

    return EVERGRAM_SUCCESS;
}

/*
 * Initialize handshake state machine
 */
int evergram_init_handshake(evergram_t* eg) {
    if (!eg) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }

    if (crypto_box_keypair(eg->handshake.ephemeral_pubkey,
                          eg->handshake.ephemeral_privkey) != 0) {
        fprintf(stderr, "[HANDSHAKE] Failed to generate ephemeral keypair\n");
        return EVERGRAM_ERR_CRYPTO;
    }

    memset(eg->handshake.client_nonce, 0, EVERGRAM_NONCE_SIZE);
    memset(eg->handshake.server_nonce, 0, EVERGRAM_NONCE_SIZE);
    memset(eg->handshake.server_ephemeral_pubkey, 0, crypto_box_PUBLICKEYBYTES);
    eg->handshake.started_at = time(NULL);
    eg->hs_state = EVERGRAM_HS_CONNECTING;

    fprintf(stderr, "[HANDSHAKE] Initialized with ephemeral pubkey\n");
    return EVERGRAM_SUCCESS;
}

/*
 * Start the handshake process
 * Called after WebSocket connection is established
 */
int evergram_start_handshake(evergram_t* eg) {
    if (!eg) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }

    if (eg->state != EVERGRAM_STATE_CONNECTING) {
        fprintf(stderr, "[HANDSHAKE] Cannot start handshake in state %d\n", eg->state);
        return EVERGRAM_ERR_PROTO;
    }

    int ret = evergram_init_handshake(eg);
    if (ret != EVERGRAM_SUCCESS) {
        eg->state = EVERGRAM_STATE_ERROR;
        return ret;
    }

    return send_client_hello(eg);
}

/*
 * Check for handshake timeout
 * Should be called periodically during handshake
 */
int evergram_check_handshake_timeout(evergram_t* eg) {
    if (!eg || eg->hs_state != EVERGRAM_HS_CLIENT_HELLO_SENT) {
        return EVERGRAM_SUCCESS;
    }

    time_t now = time(NULL);
    if (now - eg->handshake.started_at > (EVERGRAM_HANDSHAKE_TIMEOUT_MS / 1000)) {
        fprintf(stderr, "[HANDSHAKE] Timeout waiting for ServerHello\n");
        eg->state = EVERGRAM_STATE_ERROR;
        
        if (eg->on_error) {
            eg->on_error(eg, EVERGRAM_ERR_TIMEOUT, "Handshake timeout");
        }
        return EVERGRAM_ERR_TIMEOUT;
    }

    return EVERGRAM_SUCCESS;
}
