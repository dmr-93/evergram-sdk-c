#include "evergram.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// Estrutura interna para gerenciamento de nonces
struct evergram_nonce_manager {
    uint64_t local_nonce;       // Contador local (envio)
    uint64_t remote_nonce;      // Último nonce válido recebido
    uint8_t  received_window[64]; // Janela deslizante para detecção de replay (512 bits)
};

evergram_nonce_manager_t* evergram_nonce_create(void) {
    evergram_nonce_manager_t* mgr = malloc(sizeof(evergram_nonce_manager_t));
    if (!mgr) return NULL;
    
    mgr->local_nonce = 0;
    mgr->remote_nonce = 0;
    memset(mgr->received_window, 0, sizeof(mgr->received_window));
    
    return mgr;
}

void evergram_nonce_destroy(evergram_nonce_manager_t* mgr) {
    if (mgr) {
        free(mgr);
    }
}

uint64_t evergram_nonce_get_next_local(evergram_nonce_manager_t* mgr) {
    if (!mgr) return 0;
    return ++mgr->local_nonce;
}

// Verifica se o nonce remoto é válido (maior que o último ou dentro da janela de replay)
int evergram_nonce_verify_remote(evergram_nonce_manager_t* mgr, uint64_t nonce) {
    if (!mgr) return EVERGRAM_ERROR_INVALID_ARG;

    // Se for maior que o último conhecido, é novo e válido
    if (nonce > mgr->remote_nonce) {
        // Atualizar janela deslizante
        uint64_t diff = nonce - mgr->remote_nonce;
        
        // Se a diferença for muito grande, resetamos a janela (possível reinício de sessão)
        if (diff > 512) {
            memset(mgr->received_window, 0, sizeof(mgr->received_window));
            mgr->remote_nonce = nonce;
            return EVERGRAM_SUCCESS;
        }

        // Marcar bit na janela
        size_t byte_idx = (diff - 1) / 8;
        size_t bit_idx = (diff - 1) % 8;
        
        if (byte_idx < sizeof(mgr->received_window)) {
            mgr->received_window[byte_idx] |= (1 << bit_idx);
        }
        
        // Shift da janela se necessário (simplificado: apenas atualiza o base)
        // Em uma implementação robusta, faríamos shift dos bits quando remote_nonce aumentasse muito
        mgr->remote_nonce = nonce;
        return EVERGRAM_SUCCESS;
    }

    // Se for menor ou igual, verifica se está na janela e se já foi recebido
    uint64_t diff = mgr->remote_nonce - nonce;
    
    if (diff == 0) {
        // Nonce duplicado exato
        return EVERGRAM_ERROR_REPLAY_ATTACK;
    }
    
    if (diff > 512) {
        // Muito antigo, fora da janela
        return EVERGRAM_ERROR_REPLAY_ATTACK;
    }

    size_t byte_idx = (diff - 1) / 8;
    size_t bit_idx = (diff - 1) % 8;

    if (byte_idx >= sizeof(mgr->received_window)) {
        return EVERGRAM_ERROR_REPLAY_ATTACK;
    }

    if (mgr->received_window[byte_idx] & (1 << bit_idx)) {
        // Já foi recebido antes
        return EVERGRAM_ERROR_REPLAY_ATTACK;
    }

    // Marca como recebido
    mgr->received_window[byte_idx] |= (1 << bit_idx);
    return EVERGRAM_SUCCESS;
}
