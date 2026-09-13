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

/* Definicao completa da estrutura interna */
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
    
    /* Campos para handshake e autenticacao */
    uint8_t auth_challenge_nonce[256];
    size_t auth_challenge_nonce_len;
    bool auth_challenge_received;
    bool device_registered;
    
    /* Callbacks */
    evergram_message_callback on_message;
    evergram_reaction_callback on_reaction;
    evergram_typing_callback on_typing;
    evergram_error_callback on_error;
    evergram_connected_callback on_connected;
    evergram_disconnected_callback on_disconnected;
    evergram_chat_synced_callback on_chat_synced;
    void *user_data;
};

/* Declaracao forward */
extern int send_auth_response(evergram_t *eg);
extern int send_register_device(evergram_t *eg);

/**
 * Processa dados recebidos do transporte
 * Formato: bytes protobuf puros (sem header customizado)
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
    
    /* Processar todos os bytes no buffer como uma mensagem protobuf completa */
    if (eg->recv_buffer_len < 1) {
        return 0;
    }
    
    printf("[Parser] Processando %zu bytes de dados protobuf...\n", eg->recv_buffer_len);
    printf("[Parser] Primeiros bytes: ");
    for (size_t i = 0; i < (eg->recv_buffer_len < 20 ? eg->recv_buffer_len : 20); i++) {
        printf("%02x ", eg->recv_buffer[i]);
    }
    printf("\n");
    
    /* Deserializar mensagem protobuf diretamente dos bytes recebidos */
    Evergram__ServerMessage *server_msg = 
        evergram__server_message__unpack(NULL, eg->recv_buffer_len, eg->recv_buffer);
    
    if (!server_msg) {
        fprintf(stderr, "[Parser] Falha ao deserializar ServerMessage\n");
        eg->recv_buffer_len = 0;  /* Limpar buffer para proxima tentativa */
        return -1;
    }
    
    /* Processar a mensagem */
    messages_processed = 1;
    
    /* Verificar se e AuthChallenge */
    if (server_msg->payload_case == EVERGRAM__SERVER_MESSAGE__PAYLOAD_AUTH_CHALLENGE && server_msg->auth_challenge) {
        printf("[Parser] AuthChallenge recebido\n");
        
        Evergram__AuthChallenge *chal = server_msg->auth_challenge;
        if (chal->nonce) {
            size_t nonce_len = strlen(chal->nonce);
            printf("[Parser] Nonce length: %zu bytes\n", nonce_len);
            printf("[Parser] Nonce string: %s\n", chal->nonce);
            
            // Imprimir bytes do nonce para debug
            printf("[Parser] Nonce bytes: ");
            for (size_t i = 0; i < nonce_len && i < 64; i++) {
                printf("%02x ", (unsigned char)chal->nonce[i]);
            }
            printf("\n");
            
            if (nonce_len <= sizeof(eg->auth_challenge_nonce)) {
                /* Armazenar nonce como string hex (já vem em hex do servidor) */
                memcpy(eg->auth_challenge_nonce, chal->nonce, nonce_len);
                eg->auth_challenge_nonce[nonce_len] = '\0';  // Null-terminate
                eg->auth_challenge_nonce_len = nonce_len;
                eg->auth_challenge_received = true;
                printf("[Parser] Nonce armazenado como string hex (%zu bytes)\n", nonce_len);
                
                printf("[Handshake] Wallet address: %s\n", eg->wallet.address);
                printf("[Handshake] Device ID: %s\n", eg->device.device_id);
                printf("[Handshake] Private key hex length: %zu\n", strlen(eg->wallet.private_key_hex));
                
                /* Enviar resposta Auth */
                int ret = send_auth_response(eg);
                if (ret != EVERGRAM_SUCCESS) {
                    fprintf(stderr, "[Parser] Erro ao enviar AuthResponse: %d\n", ret);
                } else {
                    printf("[Parser] AuthResponse enviado com sucesso, aguardando resposta...\n");
                }
            } else {
                fprintf(stderr, "[Parser] Nonce muito grande: %zu bytes (max %zu)\n", nonce_len, sizeof(eg->auth_challenge_nonce));
            }
        } else {
            fprintf(stderr, "[Parser] AuthChallenge sem nonce\n");
        }
    }
    /* Verificar se e AuthResponse */
    else if (server_msg->payload_case == EVERGRAM__SERVER_MESSAGE__PAYLOAD_AUTH_RESPONSE && server_msg->auth_response) {
        printf("[Parser] AuthResponse recebido\n");
        
        Evergram__AuthResponse *auth_resp = server_msg->auth_response;
        if (auth_resp && auth_resp->status && auth_resp->status->ok) {
            eg->state = EVERGRAM_STATE_CONNECTED;
            eg->hs_state = EVERGRAM_HS_AUTHENTICATED;
            printf("[Parser] Autenticado com sucesso!\n");
            
            /* Chamar callback de conexao */
            if (eg->on_connected) {
                eg->on_connected(eg);
            }
        } else if (auth_resp && auth_resp->status && auth_resp->status->code && 
                   strstr(auth_resp->status->code, "device_not_registered")) {
            /* Device nao registrado: registrar e so reenviar o Auth quando o
             * registerDeviceResponse chegar (branch abaixo).
             * Reenviar o Auth imediatamente aqui fazia o gateway responder
             * device_not_registered de novo em loop apertado: o registro e uma
             * escrita de consenso e demora (o SDK TS espera ate 35s). */
            printf("[Parser] Device nao registrado, registrando...\n");
            int reg_ret = send_register_device(eg);
            if (reg_ret != EVERGRAM_SUCCESS) {
                fprintf(stderr, "[Parser] Falha ao enviar RegisterDevice: %d\n", reg_ret);
            }
        } else {
            fprintf(stderr, "[Parser] Falha na autenticacao: %s\n", 
                    auth_resp && auth_resp->status && auth_resp->status->message 
                    ? auth_resp->status->message : "unknown error");
            if (eg->on_error) {
                eg->on_error(eg, EVERGRAM_ERR_AUTH, "Authentication failed");
            }
        }
    }
    /* Resposta do registro de dispositivo. So depois dela o Auth pode ser
     * reenviado: o registro e uma escrita de consenso e pode demorar. */
    else if (server_msg->payload_case == EVERGRAM__SERVER_MESSAGE__PAYLOAD_REGISTER_DEVICE_RESPONSE
             && server_msg->register_device_response) {
        Evergram__RegisterDeviceResponse *reg_resp = server_msg->register_device_response;
        int reg_ok = (reg_resp->status && reg_resp->status->ok);
        const char *reg_code = (reg_resp->status && reg_resp->status->code) ? reg_resp->status->code : "";
        const char *reg_msg = (reg_resp->status && reg_resp->status->message) ? reg_resp->status->message : "";
        
        printf("[Parser] RegisterDeviceResponse recebido: ok=%d code=%s msg=%s\n", reg_ok, reg_code, reg_msg);
        
        if (reg_ok && eg->hs_state != EVERGRAM_HS_AUTHENTICATED) {
            printf("[Parser] Device registrado, reenviando Auth...\n");
            send_auth_response(eg);
        } else if (!reg_ok) {
            fprintf(stderr, "[Parser] Falha ao registrar device: %s\n", reg_msg[0] ? reg_msg : reg_code);
            if (eg->on_error) {
                eg->on_error(eg, EVERGRAM_ERR_AUTH, reg_msg[0] ? reg_msg : "register device failed");
            }
        }
    }
    /* Verificar se e ErrorResponse (mensagem de erro direta do servidor) */
    else if (server_msg->payload_case == EVERGRAM__SERVER_MESSAGE__PAYLOAD_ERROR && server_msg->error) {
        fprintf(stderr, "[Parser] ErrorResponse recebido\n");
        
        Evergram__Error *err = server_msg->error;
        if (err && err->message) {
            printf("[Parser] Erro: %s\n", err->message);
            
            /* Se for device_not_registered ou invalid_device, tentar registrar */
            if (err->code && (strstr(err->code, "device_not_registered") || strstr(err->code, "invalid_device"))) {
                printf("[Parser] Device nao registrado/invalido, tentando registrar...\n");
                send_register_device(eg);
            }
            
            if (eg->on_error) {
                eg->on_error(eg, EVERGRAM_ERR_PROTO, err->message);
            }
        }
    }
    /* Verificar se e Envelope (mensagem de chat recebida) */
    else if (server_msg->payload_case == EVERGRAM__SERVER_MESSAGE__PAYLOAD_ENVELOPE && server_msg->envelope) {
        Evergram__Envelope *env = server_msg->envelope;
        
        /*
         * IMPORTANTE: em protobuf-c o oneof "content" do Envelope e um UNION —
         * env->send, env->typing, env->react, ... apontam para O MESMO endereco.
         * Testar `env->send != NULL` nao diz nada sobre o tipo do conteudo: num
         * envelope TYPING ele fica igual a env->typing (portanto nao-NULL) e ler
         * env->send->msg_id reinterpreta um TypingContent{bool,bool} como
         * SendContent -> ponteiro 0x1 -> strncpy(0x1) -> segfault.
         * O discriminante correto e env->content_case.
         */
        printf("[Parser] Envelope recebido (type=%s content_case=%d)\n",
               env->type ? env->type : "?", env->content_case);
        
        if (!env->chat_id || !env->sender) {
            fprintf(stderr, "[Parser] Envelope sem chat_id/sender, ignorando\n");
        } else {
            switch (env->content_case) {
            case EVERGRAM__ENVELOPE__CONTENT_SEND: {
                Evergram__SendContent *send = env->send;
                if (!send) break;
                
                evergram_message_t msg;
                memset(&msg, 0, sizeof(msg));
                
                strncpy(msg.chat_id, env->chat_id, sizeof(msg.chat_id) - 1);
                strncpy(msg.sender, env->sender, sizeof(msg.sender) - 1);
                
                if (send->msg_id) {
                    strncpy(msg.msg_id, send->msg_id, sizeof(msg.msg_id) - 1);
                }
                
                msg.timestamp = (env->has_ts && env->ts) ? (uint64_t)env->ts
                                                         : evergram_get_timestamp_ms();
                
                /* TODO: decrypt E2EE — por enquanto entrega o ciphertext cru */
                if (send->ciphertext) {
                    msg.text = (char*)send->ciphertext;
                }
                
                if (send->reply_to_msg_id && send->reply_to_msg_id[0]) {
                    msg.reply_to_msg_id = (char*)send->reply_to_msg_id;
                }
                
                if (eg->on_message) {
                    eg->on_message(eg, &msg);
                }
                break;
            }
            case EVERGRAM__ENVELOPE__CONTENT_TYPING: {
                Evergram__TypingContent *typing = env->typing;
                if (!typing || !eg->on_typing) break;
                
                evergram_typing_event_t ev;
                memset(&ev, 0, sizeof(ev));
                strncpy(ev.chat_id, env->chat_id, sizeof(ev.chat_id) - 1);
                strncpy(ev.sender, env->sender, sizeof(ev.sender) - 1);
                ev.is_typing = typing->is_typing;
                ev.timestamp = (env->has_ts && env->ts) ? (uint64_t)env->ts
                                                        : evergram_get_timestamp_ms();
                
                eg->on_typing(eg, &ev);
                break;
            }
            case EVERGRAM__ENVELOPE__CONTENT_REACT: {
                Evergram__ReactContent *react = env->react;
                if (!react || !eg->on_reaction) break;
                
                evergram_reaction_t r;
                memset(&r, 0, sizeof(r));
                strncpy(r.chat_id, env->chat_id, sizeof(r.chat_id) - 1);
                strncpy(r.sender, env->sender, sizeof(r.sender) - 1);
                if (react->msg_id) {
                    strncpy(r.msg_id, react->msg_id, sizeof(r.msg_id) - 1);
                }
                /* TODO: decrypt E2EE — por enquanto o ciphertext cru */
                if (react->ciphertext) {
                    strncpy(r.emoji, react->ciphertext, sizeof(r.emoji) - 1);
                }
                r.removed = react->removed;
                r.timestamp = (env->has_ts && env->ts) ? (uint64_t)env->ts
                                                       : evergram_get_timestamp_ms();
                
                eg->on_reaction(eg, &r);
                break;
            }
            default:
                printf("[Parser] Envelope sem conteudo tratado (content_case=%d)\n",
                       env->content_case);
                break;
            }
        }
    }
    /* Verificar se e Error */
    else if (server_msg->payload_case == EVERGRAM__SERVER_MESSAGE__PAYLOAD_ERROR && server_msg->error) {
        fprintf(stderr, "[Parser] ErrorResponse recebido\n");
        
        Evergram__Error *err = server_msg->error;
        if (err && err->message && eg->on_error) {
            eg->on_error(eg, EVERGRAM_ERR_PROTO, err->message);
        }
    }
    else {
        printf("[Parser] Mensagem de tipo desconhecido (payload_case: %d)\n", server_msg->payload_case);
    }
    
    evergram__server_message__free_unpacked(server_msg, NULL);
    
    /* Limpar buffer apos processamento */
    eg->recv_buffer_len = 0;

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
