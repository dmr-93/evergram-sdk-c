/**
 * evergram-c - Handshake Implementation
 * Implementa handshake real usando estruturas protobuf da Evergram
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "evergram.h"
#include "evergram.pb-c.h"
#include <sodium.h>

extern int transport_send(void *ws_context, const uint8_t *data, size_t len);
extern void transport_disconnect(void *ws_context);

/* Definição completa da struct para acesso interno */
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
    unsigned char ephemeral_secret[32];
    unsigned char ephemeral_public[32];
    unsigned char server_public[32];
    char session_id[64];
    char auth_challenge_nonce[128];
};

/**
 * Assina o challenge do servidor com a chave privada da wallet
 */
static int sign_challenge(const evergram_t *eg, const char *challenge, 
                          char *signature_hex_out, size_t sig_out_size) {
    if (!eg || !challenge || !signature_hex_out) return -1;
    
    /* Converte private_key_hex para binário */
    unsigned char wallet_priv_bin[32];
    if (sodium_hex2bin(wallet_priv_bin, 32, eg->wallet.private_key_hex,
                       strlen(eg->wallet.private_key_hex), NULL, NULL, NULL) != 0) {
        fprintf(stderr, "[handshake] Failed to convert wallet private key from hex\n");
        return -1;
    }
    
    /* Assina o challenge */
    unsigned char signature[64];
    if (crypto_sign_detached(signature, NULL, (const unsigned char*)challenge,
                             strlen(challenge), wallet_priv_bin) != 0) {
        fprintf(stderr, "[handshake] Failed to sign challenge\n");
        return -1;
    }
    
    /* Converte assinatura para hex */
    sodium_bin2hex(signature_hex_out, sig_out_size, signature, 64);
    return 0;
}

/**
 * Constrói mensagem Auth usando estruturas reais do protobuf Evergram
 */
static int build_auth_message(evergram_t *eg, uint8_t **out_data, size_t *out_len) {
    if (!eg || !out_data || !out_len) return -1;

    /* Cria SignedMessageProof */
    Evergram__SignedMessageProof signed_proof = EVERGRAM__SIGNED_MESSAGE_PROOF__INIT;
    signed_proof.public_key_hex = eg->wallet.public_key_hex;
    
    /* Assina o challenge nonce */
    char signature_hex[129];
    if (sign_challenge(eg, eg->auth_challenge_nonce, signature_hex, sizeof(signature_hex)) != 0) {
        fprintf(stderr, "[handshake] Failed to sign challenge\n");
        return -1;
    }
    signed_proof.signature_hex = signature_hex;
    
    /* Cria AuthProof */
    Evergram__AuthProof proof = EVERGRAM__AUTH_PROOF__INIT;
    proof.proof_case = EVERGRAM__AUTH_PROOF__PROOF_SIGNED_MESSAGE;
    proof.signed_message = &signed_proof;
    
    /* Cria ChainIdentity */
    Evergram__ChainIdentity identity = EVERGRAM__CHAIN_IDENTITY__INIT;
    identity.address = eg->wallet.address;
    identity.chain_family = EVERGRAM__CHAIN_FAMILY__XRPL;
    
    /* Cria Device */
    Evergram__Device device_proto = EVERGRAM__DEVICE__INIT;
    device_proto.device_id = eg->device.device_id;
    device_proto.device_pub_hex = eg->device.pub_hex;
    
    /* Monta Auth */
    Evergram__Auth auth = EVERGRAM__AUTH__INIT;
    auth.identity = &identity;
    auth.proof = &proof;
    auth.device = &device_proto;
    
    /* Serializa Auth */
    size_t len = evergram__auth__get_packed_size(&auth);
    uint8_t *data = malloc(len);
    if (!data) return -1;
    
    evergram__auth__pack(&auth, data);
    
    *out_data = data;
    *out_len = len;
    
    return 0;
}

/**
 * Envia mensagem Auth encapsulada em ClientMessage
 */
static int send_auth_message(evergram_t *eg) {
    if (!eg) return -1;
    
    /* Constrói Auth */
    uint8_t *auth_data = NULL;
    size_t auth_len = 0;
    if (build_auth_message(eg, &auth_data, &auth_len) != 0) {
        fprintf(stderr, "[handshake] Failed to build auth message\n");
        return -1;
    }
    
    /* Unpack Auth para usar no ClientMessage */
    Evergram__Auth *auth = evergram__auth__unpack(NULL, auth_len, auth_data);
    free(auth_data);
    
    if (!auth) {
        fprintf(stderr, "[handshake] Failed to unpack auth\n");
        return -1;
    }
    
    /* Monta ClientMessage */
    Evergram__ClientMessage client_msg = EVERGRAM__CLIENT_MESSAGE__INIT;
    client_msg.has_request_id = 1;
    client_msg.request_id = 2;  /* Request ID 2 para auth */
    client_msg.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_AUTH;
    client_msg.auth = auth;
    
    /* Serializa ClientMessage */
    size_t len = evergram__client_message__get_packed_size(&client_msg);
    uint8_t *data = malloc(len);
    if (!data) {
        evergram__auth__free_unpacked(auth, NULL);
        return -1;
    }
    evergram__client_message__pack(&client_msg, data);
    evergram__auth__free_unpacked(auth, NULL);
    
    /* Envia via transporte */
    if (transport_send(eg->ws_context, data, len) != 0) {
        free(data);
        return -1;
    }
    free(data);
    
    printf("[handshake] Auth message sent\n");
    return 0;
}

/**
 * Processa ServerMessage recebido durante handshake
 */
static int parse_server_message(evergram_t *eg, const uint8_t *data, size_t len) {
    if (!eg || !data) return -1;

    Evergram__ServerMessage *server_msg =
        evergram__server_message__unpack(NULL, len, data);
    if (!server_msg) {
        fprintf(stderr, "[handshake] Failed to unpack ServerMessage\n");
        return -1;
    }

    /* Verifica se é um auth_challenge */
    if (server_msg->payload_case == EVERGRAM__SERVER_MESSAGE__PAYLOAD_AUTH_CHALLENGE) {
        Evergram__AuthChallenge *challenge = server_msg->auth_challenge;
        printf("[handshake] Received auth challenge with nonce: %s\n",
               challenge->nonce ? challenge->nonce : "null");

        /* Armazena o nonce para assinar */
        if (challenge->nonce) {
            strncpy(eg->auth_challenge_nonce, challenge->nonce, sizeof(eg->auth_challenge_nonce) - 1);
        }

        evergram__server_message__free_unpacked(server_msg, NULL);
        
        /* Envia resposta de auth */
        return send_auth_message(eg);
    }

    /* Verifica se é uma auth_response */
    if (server_msg->payload_case == EVERGRAM__SERVER_MESSAGE__PAYLOAD_AUTH_RESPONSE) {
        Evergram__AuthResponse *auth_resp = server_msg->auth_response;

        /* Verifica status da resposta */
        if (auth_resp->status && auth_resp->status->has_ok && !auth_resp->status->ok) {
            fprintf(stderr, "[handshake] Server rejected auth: code=%s, message=%s\n",
                    auth_resp->status->code ? auth_resp->status->code : "unknown",
                    auth_resp->status->message ? auth_resp->status->message : "unknown");
            evergram__server_message__free_unpacked(server_msg, NULL);
            return -1;
        }

        /* Autenticação bem-sucedida */
        printf("[handshake] Auth successful!\n");
        
        evergram__server_message__free_unpacked(server_msg, NULL);
        return 0;  /* Handshake completo */
    }

    fprintf(stderr, "[handshake] Unexpected payload_case %d\n", server_msg->payload_case);
    evergram__server_message__free_unpacked(server_msg, NULL);
    return -1;
}

int evergram_start_handshake(evergram_t *eg) {
    if (!eg) return -1;

    printf("[handshake] Starting handshake with %s...\n", eg->server_url);

    /* Inicializa estado */
    eg->hs_state = EVERGRAM_HS_CLIENT_HELLO_SENT;
    eg->handshake_start_time = time(NULL);
    eg->state = EVERGRAM_STATE_AUTHENTICATING;
    eg->auth_challenge_nonce[0] = '\0';

    /* Nota: No protocolo real, o servidor envia auth_challenge automaticamente
     * após a conexão WebSocket ser estabelecida. Não precisamos enviar ClientHello.
     * Apenas aguardamos o challenge e respondemos com Auth. */
    
    printf("[handshake] Waiting for auth challenge from server...\n");
    return 0;
}

int evergram_process_handshake_data(evergram_t *eg, const uint8_t *data, size_t len) {
    if (!eg || !data) return -1;

    printf("[handshake] Processing server message (%zu bytes)...\n", len);

    int result = parse_server_message(eg, data, len);
    
    if (result < 0) {
        fprintf(stderr, "[handshake] Handshake failed\n");
        eg->hs_state = EVERGRAM_HS_ERROR;
        eg->state = EVERGRAM_STATE_ERROR;
        return -1;
    }
    
    if (result == 0) {
        /* Handshake completo */
        printf("[handshake] Handshake complete! Session established.\n");
        eg->hs_state = EVERGRAM_HS_CONNECTED;
        eg->state = EVERGRAM_STATE_CONNECTED;

        if (eg->on_connected) {
            eg->on_connected(eg);
        }
    }
    /* result == 1 significa que enviamos auth e aguardamos response */

    return result;
}

int evergram_check_handshake_timeout(evergram_t *eg) {
    if (!eg) return -1;

    if (eg->hs_state == EVERGRAM_HS_CLIENT_HELLO_SENT) {
        time_t now = time(NULL);
        if (now - eg->handshake_start_time > 30) {
            fprintf(stderr, "[handshake] Timeout waiting for server response\n");
            eg->hs_state = EVERGRAM_HS_ERROR;
            eg->state = EVERGRAM_STATE_ERROR;
            return -1;
        }
    }
    return 0;
}
