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

/* Assinar desafio com wallet XRPL usando ripple-keypairs compativel */
static int sign_challenge(const char *private_key_hex, const char *public_key_hex, const char *address, 
                          const char *device_id, const char *nonce_str, size_t nonce_len, 
                          uint8_t *signature_out, char *public_key_out) {
    /* Construir mensagem: "evergram-auth:{address}:{deviceId}:{nonce}" */
    /* O nonce já vem como string ASCII hex do servidor (ex: "48f55c342e81c3394a3fc62bd3d9cb46") */
    char challenge[512];
    int len = snprintf(challenge, sizeof(challenge), "evergram-auth:%s:%s:%.*s", address, device_id, (int)nonce_len, nonce_str);
    if (len < 0 || len >= (int)sizeof(challenge)) {
        fprintf(stderr, "[Handshake] Challenge muito grande: %d bytes\n", len);
        return -1;
    }
    
    printf("[Handshake] Challenge string: %s\n", challenge);
    printf("[Handshake] Challenge length: %d\n", len);
    printf("[Handshake] Challenge bytes (UTF-8): ");
    for (int i = 0; i < len && i < 50; i++) {
        printf("%02x ", (unsigned char)challenge[i]);
    }
    printf("\n");
    
    /* Assinar usando a função compatível com ripple-keypairs */
    /* IMPORTANTE: Passamos a mensagem como string hex dos bytes UTF-8, não os bytes brutos */
    char challenge_hex[1025];
    if (len * 2 + 1 > sizeof(challenge_hex)) {
        fprintf(stderr, "[Handshake] Buffer challenge_hex muito pequeno\n");
        return -1;
    }
    sodium_bin2hex(challenge_hex, sizeof(challenge_hex), (const unsigned char*)challenge, len);
    
    char signature_hex[129];
    int ret = evergram_sign_with_xrpl_seed(challenge_hex, private_key_hex, signature_hex, sizeof(signature_hex));
    if (ret != EVERGRAM_SUCCESS) {
        fprintf(stderr, "[Handshake] Erro ao assinar desafio: %d\n", ret);
        return -1;
    }
    
    /* Converter assinatura hex para bytes */
    size_t sig_len_bin;
    if (sodium_hex2bin(signature_out, 64, signature_hex, 128, NULL, &sig_len_bin, NULL) != 0) {
        fprintf(stderr, "[Handshake] Erro ao converter assinatura hex\n");
        return -1;
    }
    
    printf("[Handshake] Assinatura gerada com sucesso (64 bytes)\n");
    
    /* Usar a public_key_hex já fornecida (derivada corretamente da seed) */
    strncpy(public_key_out, public_key_hex, 64);
    public_key_out[64] = '\0';
    
    printf("[Handshake] Public key usada: %s\n", public_key_out);
    return 0;
}

/* Enviar resposta Auth para o gateway */
int send_auth_response(evergram_t *eg) {
    if (!eg) return EVERGRAM_ERR_INVALID_PARAM;
    
    /* Cast para estrutura interna completa */
    evergram_t *egi = eg;
    
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
    
    /* Assinar o challenge usando ripple-keypairs compativel */
    /* Esta função já faz todo o processo: decodificar seed XRPL, aplicar HMAC-SHA512, derivar chaves e assinar */
    uint8_t signature[64];
    char derived_public_key[65];
    if (sign_challenge(egi->wallet.private_key_hex, egi->wallet.public_key_hex, egi->wallet.address, egi->device.device_id,
                       nonce_str, egi->auth_challenge_nonce_len, signature, derived_public_key) != 0) {
        return EVERGRAM_ERR_CRYPTO;
    }
    
    /* Construir ChainIdentity */
    Evergram__ChainIdentity identity = EVERGRAM__CHAIN_IDENTITY__INIT;
    identity.has_chain_family = 1;  // Marcar campo como presente (protobuf required)
    identity.chain_family = EVERGRAM__CHAIN_FAMILY__XRPL;  // XRPL = 1
    identity.address = egi->wallet.address;
    identity.network_id = "0";
    
    printf("[Handshake] Chain family set: XRPL (%d), has_chain_family=%d\n", identity.chain_family, identity.has_chain_family);
    
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
    printf("[Handshake] Primeiros bytes da mensagem: ");
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
    identity.has_chain_family = 1;  // Marcar campo como presente (protobuf required)
    identity.chain_family = EVERGRAM__CHAIN_FAMILY__XRPL;  // XRPL = 1
    identity.address = egi->wallet.address;
    identity.network_id = "0";
    
    printf("[Handshake] RegisterDevice - Chain family set: XRPL (%d), has_chain_family=%d\n", identity.chain_family, identity.has_chain_family);
    
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
