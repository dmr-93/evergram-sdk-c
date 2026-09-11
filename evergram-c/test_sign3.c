#include <stdio.h>
#include <string.h>
#include <sodium.h>

int main() {
    if (sodium_init() < 0) {
        fprintf(stderr, "Erro ao inicializar libsodium\n");
        return 1;
    }
    
    // Seed de teste (64 caracteres hex = 32 bytes)
    const char* seed_hex = "6d028a3dfd4db99348621594955e12ddbe5f6e22f9838bb4ace0ed6993f5a275";
    unsigned char seed[32];
    
    // Converter hex para bytes
    for (int i = 0; i < 32; i++) {
        sscanf(seed_hex + i*2, "%2x", &seed[i]);
    }
    
    // Gerar par de chaves a partir da seed
    unsigned char pk[32], sk[64];
    if (crypto_sign_seed_keypair(pk, sk, seed) != 0) {
        fprintf(stderr, "Erro ao gerar par de chaves\n");
        return 1;
    }
    
    // Construir mensagem igual ao handshake.c
    const char* address = "rf1bX9uf64qhsNF8onQTEoi52d5feRN4N2";
    const char* device_id = "db879be3de1fa9c3796f96905a249f56";
    
    // Nonce do server (bytes crus, nao string ASCII)
    unsigned char nonce_bytes[32];
    const char* nonce_ascii = "4a3573943bf0e902e1df7994cc29a9";  // Exemplo
    for (int i = 0; i < 16; i++) {
        sscanf(nonce_ascii + i*2, "%2x", &nonce_bytes[i]);
    }
    
    // Construir challenge: "evergram-auth:{address}:{deviceId}:{nonce_hex}"
    char challenge[512];
    char nonce_hex[65];
    for (int i = 0; i < 16; i++) {
        sprintf(nonce_hex + i*2, "%02x", nonce_bytes[i]);
    }
    snprintf(challenge, sizeof(challenge), "evergram-auth:%s:%s:%s", address, device_id, nonce_hex);
    
    printf("Challenge: %s\n", challenge);
    
    // Assinar com Ed25519 usando sk COMPLETA (64 bytes)
    unsigned char sig[64];
    unsigned long long sig_len;
    
    if (crypto_sign_detached(sig, &sig_len, (const unsigned char*)challenge, strlen(challenge), sk) != 0) {
        fprintf(stderr, "Erro ao assinar\n");
        return 1;
    }
    
    printf("Signature OK (%llu bytes)\n", sig_len);
    
    // Verificar assinatura
    if (crypto_sign_verify_detached(sig, (const unsigned char*)challenge, strlen(challenge), pk) != 0) {
        fprintf(stderr, "Verificacao falhou!\n");
        return 1;
    }
    
    printf("Verificacao OK!\n");
    return 0;
}
