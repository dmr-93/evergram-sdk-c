/**
 * evergram-c - Message Parser and Router
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "evergram.h"
#include "evergram.pb-c.h"
#include "transport.h"

/* Declaracao forward */
extern int send_auth_response(evergram_t *eg);

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
        
        /* Deserializar mensagem protobuf */
        Evergram__ServerMessage *server_msg = 
            evergram__server_message__unpack(NULL, payload_len, payload);
        
        if (server_msg) {
            /* Verificar se e AuthChallenge */
            if (server_msg->auth_challenge) {
                printf("[Parser] AuthChallenge recebido\n");
                
                Evergram__AuthChallenge *chal = server_msg->auth_challenge;
                if (chal->nonce && strlen(chal->nonce) <= sizeof(eg->auth_challenge_nonce)) {
                    memcpy(eg->auth_challenge_nonce, chal->nonce, strlen(chal->nonce));
                    eg->auth_challenge_nonce_len = strlen(chal->nonce);
                    
                    /* Enviar resposta Auth */
                    send_auth_response(eg);
                }
            }
            /* Verificar se e AuthResponse */
            else if (server_msg->auth_response) {
                printf("[Parser] AuthResponse recebido\n");
                
                Evergram__AuthResponse *auth_resp = server_msg->auth_response;
                if (auth_resp && auth_resp->status == EVERGRAM__RESPONSE_STATUS__SUCCESS) {
                    eg->state = EVERGRAM_STATE_CONNECTED;
                    eg->hs_state = EVERGRAM_HS_AUTHENTICATED;
                    printf("[Parser] Autenticado com sucesso!\n");
                    
                    /* Chamar callback de conexao */
                    if (eg->on_connected) {
                        eg->on_connected(eg);
                    }
                } else {
                    fprintf(stderr, "[Parser] Falha na autenticacao: %d\n", 
                            auth_resp ? auth_resp->status : -1);
                    if (eg->on_error) {
                        eg->on_error(eg, EVERGRAM_ERR_AUTH, "Authentication failed");
                    }
                }
            }
            
            evergram__server_message__free_unpacked(server_msg, NULL);
        }
        
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
