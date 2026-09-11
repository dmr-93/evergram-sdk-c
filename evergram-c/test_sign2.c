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
    
    // Gerar par de chaves
    unsigned char pk[32], sk[64];
    if (crypto_sign_seed_keypair(pk, sk, seed) != 0) {
        fprintf(stderr, "Erro ao gerar par de chaves\n");
        return 1;
    }
    
    // Nonce do servidor (STRING HEX, não bytes brutos!)
    const char* nonce_str = "f8354377ec549da8cba9bfaee5c428de";  // 32 caracteres hex
    
    const char* address = "rB5uP8LszTYj29n6X5or1sWkbp8qNoy5Mr";
    const char* device_id = "c207b3a54bb7b3405681b1b1b7910eb4";
    
    // Construir mensagem de desafio MESMO FORMATO que handshake.c
    char challenge[512];
    int len = snprintf(challenge, sizeof(challenge), "evergram-auth:%s:%s:%.*s", address, device_id, 32, nonce_str);
    
    printf("Challenge string: %s\n", challenge);
    printf("Challenge length: %d\n", len);
    
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
