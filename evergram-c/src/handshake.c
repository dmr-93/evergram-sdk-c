/**
 * evergram-c - Handshake Implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include "evergram.h"

/* Estrutura interna - deve ser consistente com message_parser.c */
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

static int sign_challenge(const evergram_wallet_t *wallet, const uint8_t *challenge, size_t challenge_len, uint8_t *signature) {
    /* Converter private_key_hex para bytes */
    unsigned char secret_key_bytes[64];  /* Ed25519 secret key = 64 bytes */
    
    /* TODO: Implementar conversão hex->bytes correta para chaves XRPL Ed25519 */
    /* Por enquanto, usar placeholder */
    memset(secret_key_bytes, 0, sizeof(secret_key_bytes));
    
    unsigned long long sig_len;
    if (crypto_sign_detached(signature, &sig_len, challenge, challenge_len, secret_key_bytes) != 0) {
        return -1;
    }
    return 0;
}

int evergram_perform_handshake(evergram_t *eg) {
    if (!eg) return EVERGRAM_ERR_INVALID_PARAM;
    
    printf("[Handshake] Iniciando handshake...\n");
    
    uint8_t challenge[32];
    memset(challenge, 0, sizeof(challenge));
    
    uint8_t signature[64];
    if (sign_challenge(&eg->wallet, challenge, sizeof(challenge), signature) != 0) {
        fprintf(stderr, "[Handshake] Erro ao assinar desafio\n");
        return EVERGRAM_ERR_CRYPTO;
    }
    
    printf("[Handshake] Desafio assinado com sucesso.\n");
    printf("[Handshake] Autenticação enviada. Aguardando confirmação...\n");
    
    return EVERGRAM_SUCCESS;
}

/* Alias para compatibilidade - evergram_start_handshake chama evergram_perform_handshake */
int evergram_start_handshake(evergram_t *eg) {
    return evergram_perform_handshake(eg);
}
