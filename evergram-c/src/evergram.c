#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "evergram.h"

int evergram_start(evergram_t *eg) {
    if (!eg) return EVERGRAM_ERR_INVALID_PARAM;

    printf("[Evergram] Conectando...\n");
    
    int ret = evergram_perform_handshake(eg);
    if (ret != EVERGRAM_OK) {
        return ret;
    }
    
    printf("[Evergram] Conectado e autenticado com sucesso!\n");
    return EVERGRAM_OK;
}

int evergram_poll(evergram_t *eg, int timeout_ms) {
    if (!eg) return EVERGRAM_ERR_INVALID_PARAM;
    (void)timeout_ms;
    return 0;
}

int evergram_send(evergram_t *eg, const char *chat_id, const char *text) {
    if (!eg || !chat_id || !text) return EVERGRAM_ERR_INVALID_PARAM;
    
    printf("[Send] Enviando para %s: %s\n", chat_id, text);
    return EVERGRAM_OK;
}

void evergram_destroy(evergram_t *eg) {
    if (eg) {
        memset(eg, 0, sizeof(evergram_t));
        free(eg);
    }
}
