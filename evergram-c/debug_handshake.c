#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

// Simula o que acontece no handshake
int main() {
    if (sodium_init() < 0) {
        fprintf(stderr, "Erro ao inicializar libsodium\n");
        return 1;
    }
    
    // Dados do identity.json
    const char* seed_hex = "369366f86c040a6e6d7f94f0905e5a11051e7a316115c5efda8cd14fcfae6c82";
    const char* address = "rB5uP8LszTYj29n6X5or1sWkbp8qNoy5Mr";
    const char* device_id = "c207b3a54bb7b3405681b1b1b7910eb4";
    const char* pubkey_hex = "f5789c1dccfdcdadaef5cec105e073968278b15afff6e456ebe7451946bf55ea";
    
    // Nonce do servidor (STRING HEX)
    const char* nonce_str = "40d45bc14de331f5af709daf7c0c39bf";
    size_t nonce_len = strlen(nonce_str);
    
    printf("=== Teste de Handshake ===\n");
    printf("Address: %s\n", address);
    printf("Device ID: %s\n", device_id);
    printf("Nonce: %s (len=%zu)\n", nonce_str, nonce_len);
    
    // Converter seed hex para bytes
    unsigned char seed[32];
    for (int i = 0; i < 32; i++) {
        sscanf(seed_hex + i*2, "%2x", &seed[i]);
    }
    
    // Gerar par de chaves Ed25519
    unsigned char pk[32], sk[64];
    if (crypto_sign_seed_keypair(pk, sk, seed) != 0) {
        fprintf(stderr, "Erro ao gerar par de chaves\n");
        return 1;
    }
    
    printf("Public key gerada: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", pk[i]);
    }
    printf("\n");
    printf("Public key do identity.json: %s\n", pubkey_hex);
    
    // Construir challenge
    char challenge[512];
    int len = snprintf(challenge, sizeof(challenge), "evergram-auth:%s:%s:%.*s", address, device_id, (int)nonce_len, nonce_str);
    printf("Challenge: %s (len=%d)\n", challenge, len);
    
    // Assinar
    unsigned char signature[64];
    unsigned long long sig_len;
    if (crypto_sign_detached(signature, &sig_len, (const uint8_t*)challenge, strlen(challenge), sk) != 0) {
        fprintf(stderr, "Erro ao assinar\n");
        return 1;
    }
    
    printf("Signature: ");
    for (int i = 0; i < 64; i++) {
        printf("%02x", signature[i]);
    }
    printf("\n");
    
    // Verificar
    if (crypto_sign_verify_detached(signature, (const uint8_t*)challenge, strlen(challenge), pk) == 0) {
        printf("ASSINATURA VALIDA!\n");
    } else {
        printf("ASSINATURA INVALIDA!\n");
    }
    
    return 0;
}
