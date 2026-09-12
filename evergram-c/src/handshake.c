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

/* Definicao completa da estrutura interna (deve ser consistente com evergram.c) */
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

/* Assinar desafio com wallet XRPL */
static int sign_challenge(const uint8_t *secret_key_bytes, const char *address, 
                          const char *device_id, const char *nonce_hex, size_t nonce_len, 
                          uint8_t *signature_out) {
    /* Construir mensagem: "evergram-auth:{address}:{deviceId}:{nonce}" */
    /* O nonce já vem como string hex do servidor */
    char challenge[512];
    int len = snprintf(challenge, sizeof(challenge), "evergram-auth:%s:%s:%.*s", address, device_id, (int)nonce_len, nonce_hex);
    if (len < 0 || len >= (int)sizeof(challenge)) {
        fprintf(stderr, "[Handshake] Challenge muito grande: %d bytes\n", len);
        return -1;
    }
    
    printf("[Handshake] Challenge string: %s\n", challenge);
    printf("[Handshake] Challenge length: %d\n", len);
    printf("[Handshake] Challenge bytes: ");
    for (int i = 0; i < len && i < 50; i++) {
        printf("%02x ", (unsigned char)challenge[i]);
    }
    printf("\n");
    
    /* Assinar com Ed25519 */
    unsigned long long sig_len;
    if (crypto_sign_detached(signature_out, &sig_len, 
                             (const uint8_t*)challenge, strlen(challenge), 
                             secret_key_bytes) != 0) {
        fprintf(stderr, "[Handshake] Erro ao assinar desafio\n");
        return -1;
    }
    
    printf("[Handshake] Assinatura gerada com sucesso (%llu bytes)\n", sig_len);
    return 0;
}

/* Enviar resposta Auth para o gateway */
int send_auth_response(evergram_t *eg) {
    if (!eg) return EVERGRAM_ERR_INVALID_PARAM;
    
    /* Cast para estrutura interna completa */
    evergram_t *egi = eg;
    
    /* Converter private_key_hex para bytes 
     * Para libsodium, crypto_sign_detached precisa da secret key COMPLETA (64 bytes)
     * A secret key Ed25519 é: seed (32 bytes) + public key (32 bytes)
     * Nosso private_key_hex armazena apenas a seed (32 bytes = 64 caracteres hex)
     * Precisamos reconstruir a secret key completa usando crypto_sign_seed_keypair
     */
    unsigned char seed_bytes[32];
    int seed_len = hex_to_bytes(egi->wallet.private_key_hex, seed_bytes, sizeof(seed_bytes));
    if (seed_len != 32) {
        fprintf(stderr, "[Handshake] Erro ao converter seed hex (esperado 32 bytes, obtido %d)\n", seed_len);
        fprintf(stderr, "[Handshake] private_key_hex: %s (len=%zu)\n", egi->wallet.private_key_hex, strlen(egi->wallet.private_key_hex));
        return EVERGRAM_ERR_CRYPTO;
    }
    
    /* Reconstruir o par de chaves completo a partir da seed */
    unsigned char pk[32], sk[64];
    if (crypto_sign_seed_keypair(pk, sk, seed_bytes) != 0) {
        fprintf(stderr, "[Handshake] Erro ao reconstruir chaves Ed25519\n");
        return EVERGRAM_ERR_CRYPTO;
    }
    
    /* Agora sk contém a secret key completa (64 bytes) necessária para crypto_sign_detached */
    
    /* O nonce está armazenado como string hex no buffer auth_challenge_nonce */
    /* Precisamos usar essa string diretamente na assinatura */
    char nonce_str[257];
    if (egi->auth_challenge_nonce_len >= sizeof(nonce_str)) {
        fprintf(stderr, "[Handshake] Nonce muito grande: %zu bytes\n", egi->auth_challenge_nonce_len);
        return EVERGRAM_ERR_CRYPTO;
    }
    memcpy(nonce_str, egi->auth_challenge_nonce, egi->auth_challenge_nonce_len);
    nonce_str[egi->auth_challenge_nonce_len] = '\0';
    
    printf("[Handshake] Usando nonce string: %s (len=%zu)\n", nonce_str, egi->auth_challenge_nonce_len);
    
    /* Assinar o challenge */
    uint8_t signature[64];
    if (sign_challenge(sk, egi->wallet.address, egi->device.device_id,
                       nonce_str, egi->auth_challenge_nonce_len, signature) != 0) {
        return EVERGRAM_ERR_CRYPTO;
    }
    
    /* Construir ChainIdentity */
    Evergram__ChainIdentity identity = EVERGRAM__CHAIN_IDENTITY__INIT;
    identity.chain_family = EVERGRAM__CHAIN_FAMILY__XRPL;  // XRPL = 1
    identity.address = egi->wallet.address;
    identity.network_id = "0";
    
    printf("[Handshake] Chain family set: XRPL (%d)\n", identity.chain_family);
    
    /* Criar SignedMessageProof - usa public_key_hex e signature_hex como strings hex */
    char signature_hex[129];
    for (int i = 0; i < 64; i++) {
        sprintf(signature_hex + i*2, "%02x", signature[i]);
    }
    
    printf("[Handshake] Public key hex: %s\\n", egi->wallet.public_key_hex);
    printf("[Handshake] Signature hex: %s\\n", signature_hex);
    
    Evergram__SignedMessageProof signed_proof = EVERGRAM__SIGNED_MESSAGE_PROOF__INIT;
    signed_proof.public_key_hex = egi->wallet.public_key_hex;
    signed_proof.signature_hex = signature_hex;
    
    /* Criar AuthProof com signed_message */
    Evergram__AuthProof proof = EVERGRAM__AUTH_PROOF__INIT;
    proof.proof_case = EVERGRAM__AUTH_PROOF__PROOF_SIGNED_MESSAGE;
    proof.signed_message = &signed_proof;
    
    /* Criar Device */
    Evergram__Device device = EVERGRAM__DEVICE__INIT;
    device.device_id = egi->device.device_id;
    device.device_pub_hex = egi->device.pub_hex;
    device.platform = "Terminal";
    
    /* Criar Auth message - garantir que TODOS os campos required estejam preenchidos */
    Evergram__Auth auth = EVERGRAM__AUTH__INIT;
    auth.identity = &identity;
    auth.proof = &proof;
    auth.device = &device;
    
    /* Verificar se todos os campos estão preenchidos antes de criar ClientMessage */
    if (!auth.identity || !auth.proof || !auth.device) {
        fprintf(stderr, "[Handshake] ERRO: Campos required do Auth nao preenchidos\\n");
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    printf("[Handshake] Identity address: %s\\n", auth.identity->address);
    printf("[Handshake] Proof case: %d\\n", auth.proof->proof_case);
    printf("[Handshake] Device ID: %s\\n", auth.device->device_id);
    
    /* Criar ClientMessage */
    Evergram__ClientMessage msg = EVERGRAM__CLIENT_MESSAGE__INIT;
    msg.request_id = 1;  // Primeiro request - ID deve ser >= 1 conforme proto
    msg.auth = &auth;
    msg.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_AUTH;
    
    /* Serializar protobuf */
    size_t packed_size = evergram__client_message__get_packed_size(&msg);
    uint8_t *packed = malloc(packed_size);
    if (!packed) {
        return EVERGRAM_ERR_MEMORY;
    }
    
    if (packed_size == 0) {
        fprintf(stderr, "[Handshake] ERRO: Tamanho da mensagem é 0! Verifique campos required\\n");
        free(packed);
        return EVERGRAM_ERR_PROTO;
    }
    
    evergram__client_message__pack(&msg, packed);
    
    printf("[Handshake] Tamanho da mensagem Auth: %zu bytes\n", packed_size);
    printf("[Handshake] Primeiros bytes da mensagem: ", packed_size);
    for (size_t i = 0; i < (packed_size < 20 ? packed_size : 20); i++) {
        printf("%02x ", packed[i]);
    }
    printf("\n");
    
    /* Enviar via transporte */
    ws_transport_t *transport = (ws_transport_t*)egi->ws_context;
    if (!transport) {
        free(packed);
        return EVERGRAM_ERR_NOT_CONNECTED;
    }
    
    int ret = transport_send(transport, packed, packed_size);
    free(packed);
    
    if (ret == EVERGRAM_SUCCESS) {
        printf("[Handshake] Mensagem Auth enviada com sucesso\n");
        egi->hs_state = EVERGRAM_HS_AUTHENTICATED;
    } else {
        fprintf(stderr, "[Handshake] Falha ao enviar AuthResponse: %d\n", ret);
    }
    
    return ret;
}

/* Enviar mensagem de registro de dispositivo */
int send_register_device(evergram_t *eg) {
    if (!eg) return EVERGRAM_ERR_INVALID_PARAM;
    
    /* Cast para estrutura interna completa */
    evergram_t *egi = eg;
    
    /* Construir ChainIdentity */
    Evergram__ChainIdentity identity = EVERGRAM__CHAIN_IDENTITY__INIT;
    identity.chain_family = EVERGRAM__CHAIN_FAMILY__XRPL;  // XRPL = 1
    identity.address = egi->wallet.address;
    identity.network_id = "0";
    
    printf("[Handshake] RegisterDevice - Chain family set: XRPL (%d)\n", identity.chain_family);
    
    /* Criar Device */
    Evergram__Device device = EVERGRAM__DEVICE__INIT;
    device.device_id = egi->device.device_id;
    device.device_pub_hex = egi->device.pub_hex;
    device.platform = "Terminal";
    
    /* Criar RegisterDevice message */
    Evergram__RegisterDevice register_dev = EVERGRAM__REGISTER_DEVICE__INIT;
    register_dev.identity = &identity;
    register_dev.device = &device;
    
    /* Criar ClientMessage */
    Evergram__ClientMessage msg = EVERGRAM__CLIENT_MESSAGE__INIT;
    msg.register_device = &register_dev;
    
    /* Serializar protobuf */
    size_t packed_size = evergram__client_message__get_packed_size(&msg);
    uint8_t *packed = malloc(packed_size);
    if (!packed) {
        return EVERGRAM_ERR_MEMORY;
    }
    
    evergram__client_message__pack(&msg, packed);
    
    /* Enviar via transporte */
    ws_transport_t *transport = (ws_transport_t*)egi->ws_context;
    if (!transport) {
        free(packed);
        return EVERGRAM_ERR_NOT_CONNECTED;
    }
    
    int ret = transport_send(transport, packed, packed_size);
    free(packed);
    
    if (ret == EVERGRAM_SUCCESS) {
        printf("[Handshake] Mensagem RegisterDevice enviada\n");
    }
    
    return ret;
}

int evergram_perform_handshake(evergram_t *eg) {
    if (!eg) return EVERGRAM_ERR_INVALID_PARAM;
    
    printf("[Handshake] Iniciando handshake...\n");
    evergram_t *egi = eg;
    egi->hs_state = EVERGRAM_HS_CONNECTING;
    
    /* O handshake real acontece de forma assincrona */
    return EVERGRAM_SUCCESS;
}

int evergram_start_handshake(evergram_t *eg) {
    return evergram_perform_handshake(eg);
}
