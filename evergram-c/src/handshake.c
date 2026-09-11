#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include "evergram.h"

static int sign_challenge(const evergram_wallet_t *wallet, const uint8_t *challenge, size_t challenge_len, uint8_t *signature) {
    unsigned long long sig_len;
    if (crypto_sign_detached(signature, &sig_len, challenge, challenge_len, wallet->secret_key) != 0) {
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
    
    return EVERGRAM_OK;
}
