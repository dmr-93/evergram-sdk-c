/**
 * evergram-c - Handshake Implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include "evergram.h"
#include "evergram.pb-c.h"
#include "transport.h"

/* Converter hex string para bytes */
static int hex_to_bytes(const char* hex, uint8_t* out, size_t out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return -1;
    size_t bytes_len = hex_len / 2;
    if (bytes_len > out_len) return -1;
    
    for (size_t i = 0; i < bytes_len; i++) {
        unsigned int byte;
        if (sscanf(hex + 2*i, "%2x", &byte) != 1) {
            return -1;
        }
        out[i] = (uint8_t)byte;
    }
    return (int)bytes_len;
}

static int sign_challenge(const evergram_wallet_t *wallet, const char *challenge, size_t challenge_len, uint8_t *signature) {
    /* Converter private_key_hex para bytes */
    unsigned char secret_key_bytes[64];  /* Ed25519 secret key = 64 bytes */
    
    int sk_len = hex_to_bytes(wallet->private_key_hex, secret_key_bytes, sizeof(secret_key_bytes));
    if (sk_len <= 0) {
        fprintf(stderr, "[Handshake] Erro ao converter private key hex\n");
        return -1;
    }
    
    unsigned long long sig_len;
    if (crypto_sign_detached(signature, &sig_len, (const uint8_t*)challenge, challenge_len, secret_key_bytes) != 0) {
        fprintf(stderr, "[Handshake] Erro ao assinar desafio\n");
        return -1;
    }
    return 0;
}

/* Enviar resposta Auth para o gateway */
int send_auth_response(evergram_t *eg) {
    if (!eg) return EVERGRAM_ERR_INVALID_PARAM;
    
    /* Construir ChainIdentity */
    Evergram__ChainIdentity identity = EVERGRAM__CHAIN_IDENTITY__INIT;
    identity.address = eg->wallet.address;
    identity.chain_family = EVERGRAM__CHAIN_FAMILY__XRPL;
    identity.network_id = "0";
    
    /* Assinar o challenge */
    uint8_t signature[64];
    if (sign_challenge(&eg->wallet, (char*)eg->auth_challenge_nonce, eg->auth_challenge_nonce_len, signature) != 0) {
        return EVERGRAM_ERR_CRYPTO;
    }
    
    /* Criar SignedMessageProof */
    Evergram__SignedMessageProof signed_proof = EVERGRAM__SIGNED_MESSAGE_PROOF__INIT;
    signed_proof.signed_message.data = signature;
    signed_proof.signed_message.len = 64;
    
    /* Criar AuthProof com signed_message */
    Evergram__AuthProof proof = EVERGRAM__AUTH_PROOF__INIT;
    proof.proof_case = EVERGRAM__AUTH_PROOF__PROOF_SIGNED_MESSAGE;
    proof.signed_message = &signed_proof;
    
    /* Criar Device */
    Evergram__Device device = EVERGRAM__DEVICE__INIT;
    device.device_id = eg->device.device_id;
    device.device_pub_hex = eg->device.pub_hex;
    device.platform = "Terminal";
    
    /* Criar Auth message */
    Evergram__Auth auth = EVERGRAM__AUTH__INIT;
    auth.identity = &identity;
    auth.proof = &proof;
    auth.device = &device;
    
    /* Criar ClientMessage */
    Evergram__ClientMessage msg = EVERGRAM__CLIENT_MESSAGE__INIT;
    msg.auth = &auth;
    
    /* Serializar protobuf */
    size_t packed_size = evergram__client_message__get_packed_size(&msg);
    uint8_t *packed = malloc(packed_size);
    if (!packed) {
        return EVERGRAM_ERR_MEMORY;
    }
    
    evergram__client_message__pack(&msg, packed);
    
    /* Enviar via transporte */
    ws_transport_t *transport = (ws_transport_t*)eg->ws_context;
    if (!transport) {
        free(packed);
        return EVERGRAM_ERR_NOT_CONNECTED;
    }
    
    int ret = transport_send(transport, packed, packed_size);
    free(packed);
    
    if (ret == EVERGRAM_SUCCESS) {
        printf("[Handshake] Mensagem Auth enviada\n");
        eg->hs_state = EVERGRAM_HS_AUTHENTICATED;
    }
    
    return ret;
}

int evergram_perform_handshake(evergram_t *eg) {
    if (!eg) return EVERGRAM_ERR_INVALID_PARAM;
    
    printf("[Handshake] Iniciando handshake...\n");
    eg->hs_state = EVERGRAM_HS_CONNECTING;
    
    /* O handshake real acontece de forma assincrona */
    return EVERGRAM_SUCCESS;
}

int evergram_start_handshake(evergram_t *eg) {
    return evergram_perform_handshake(eg);
}
