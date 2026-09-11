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
    
    printf("Seed bytes: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", seed[i]);
    }
    printf("\n");
    
    // Gerar par de chaves a partir da seed
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
    
    // Assinar mensagem de teste usando a secret key COMPLETA (64 bytes)
    const char* msg = "evergram-auth:test:nonce123";
    unsigned char sig[64];
    unsigned long long sig_len;
    
    // crypto_sign_detached usa sk de 64 bytes (seed + pk)
    if (crypto_sign_detached(sig, &sig_len, (const unsigned char*)msg, strlen(msg), sk) != 0) {
        fprintf(stderr, "Erro ao assinar\n");
        return 1;
    }
    
    printf("Signature OK (%llu bytes)\n", sig_len);
    
    // Verificar assinatura usando public key
    if (crypto_sign_verify_detached(sig, (const unsigned char*)msg, strlen(msg), pk) != 0) {
        fprintf(stderr, "Verificacao falhou!\n");
        return 1;
    }
    
    printf("Verificacao OK!\n");
    return 0;
}
