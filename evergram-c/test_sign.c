#include <stdio.h>
#include <string.h>
#include <sodium.h>

int main() {
    if (sodium_init() < 0) {
        fprintf(stderr, "Erro ao inicializar libsodium\n");
        return 1;
    }
    
    // Seed da carteira (do identity.json)
    const char* seed_hex = "369366f86c040a6e6d7f94f0905e5a11051e7a316115c5efda8cd14fcfae6c82";
    unsigned char seed[32];
    
    for (int i = 0; i < 32; i++) {
        sscanf(seed_hex + i*2, "%2x", &seed[i]);
    }
    
    printf("Seed bytes: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", seed[i]);
    }
    printf("\n");
    
    // Gerar par de chaves
    unsigned char pk[32], sk[64];
    if (crypto_sign_seed_keypair(pk, sk, seed) != 0) {
        fprintf(stderr, "Erro ao gerar par de chaves\n");
        return 1;
    }
    
    printf("Public key: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", pk[i]);
    }
    printf("\n");
    
    printf("Secret key (64 bytes): ");
    for (int i = 0; i < 64; i++) {
        printf("%02x", sk[i]);
    }
    printf("\n");
    
    // Nonce do servidor (bytes brutos)
    unsigned char nonce[] = {
        0xf8, 0x35, 0x43, 0x77, 0xec, 0x54, 0x9d, 0xa8,
        0xcb, 0xa9, 0xbf, 0xae, 0xe5, 0xc4, 0x28, 0xde,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    // Construir mensagem de desafio
    char nonce_hex[65];
    for (int i = 0; i < 32; i++) {
        sprintf(nonce_hex + i*2, "%02x", nonce[i]);
    }
    
    const char* address = "rB5uP8LszTYj29n6X5or1sWkbp8qNoy5Mr";
    const char* device_id = "c207b3a54bb7b3405681b1b1b7910eb4";
    
    char challenge[512];
    snprintf(challenge, sizeof(challenge), "evergram-auth:%s:%s:%s", address, device_id, nonce_hex);
    
    printf("Challenge string: %s\n", challenge);
    printf("Challenge length: %zu\n", strlen(challenge));
    
    // Assinar
    unsigned char signature[64];
    unsigned long long sig_len;
    if (crypto_sign_detached(signature, &sig_len, (const uint8_t*)challenge, strlen(challenge), sk) != 0) {
        fprintf(stderr, "Erro ao assinar\n");
        return 1;
    }
    
    printf("Signature (%llu bytes): ", sig_len);
    for (int i = 0; i < 64; i++) {
        printf("%02x", signature[i]);
    }
    printf("\n");
    
    // Verificar assinatura
    if (crypto_sign_verify_detached(signature, (const uint8_t*)challenge, strlen(challenge), pk) != 0) {
        fprintf(stderr, "Verificacao falhou!\n");
        return 1;
    }
    
    printf("Verificacao OK!\n");
    return 0;
}
