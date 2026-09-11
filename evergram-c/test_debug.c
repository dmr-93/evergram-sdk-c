#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

int main() {
    if (sodium_init() < 0) {
        fprintf(stderr, "Erro ao inicializar libsodium\n");
        return 1;
    }
    
    // Seed de exemplo (64 caracteres hex = 32 bytes)
    const char* seed_hex = "04e3400fa93ed67a6ae45f6a986c046bab038ae2b7efddf7fab8725965f9f8b2";
    
    // Converter hex para bytes
    unsigned char seed[32];
    for (int i = 0; i < 32; i++) {
        unsigned int byte;
        sscanf(seed_hex + 2*i, "%2x", &byte);
        seed[i] = (unsigned char)byte;
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
    
    // Mensagem de desafio
    const char* challenge = "evergram-auth:rLXDUCeNRMagbWGWmgUHyv7Fm3fS5KBusj:361f6221ac2441dd2b8e1303348a80e2:bd5e4432a52736d475b2535345782e32";
    printf("Challenge: %s (len=%zu)\n", challenge, strlen(challenge));
    
    // Assinar
    unsigned char signature[64];
    unsigned long long sig_len;
    if (crypto_sign_detached(signature, &sig_len, (const unsigned char*)challenge, strlen(challenge), sk) != 0) {
        fprintf(stderr, "Erro ao assinar\n");
        return 1;
    }
    
    printf("Signature (%llu bytes): ", sig_len);
    for (int i = 0; i < 64; i++) {
        printf("%02x", signature[i]);
    }
    printf("\n");
    
    // Verificar
    if (crypto_sign_verify_detached(signature, (const unsigned char*)challenge, strlen(challenge), pk) != 0) {
        fprintf(stderr, "Verificacao falhou!\n");
        return 1;
    }
    
    printf("Verificacao OK!\n");
    return 0;
}
