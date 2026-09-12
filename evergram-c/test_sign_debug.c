#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

int main() {
    if (sodium_init() < 0) {
        fprintf(stderr, "Erro ao inicializar libsodium\n");
        return 1;
    }
    
    // Seed de 32 bytes em hex
    const char* seed_hex = "b2c5c1d78b6ba563b626cbb2b91d268952ea915f7251671835cf27691e037109";
    unsigned char seed[32];
    sodium_hex2bin(seed, sizeof(seed), seed_hex, strlen(seed_hex), NULL, NULL, NULL);
    
    // Mensagem a ser assinada
    const char* msg_str = "evergram-auth:rK3VUVtsx28Etjn5GTpThv5wbCpzYgA7tj:d5032f64bb2d5c34be351b05a3676cec:4623f7194c68e7824e522fc3db087422";
    printf("Mensagem a assinar: %s\n", msg_str);
    printf("Comprimento: %zu bytes\n\n", strlen(msg_str));
    
    // Converter mensagem para hex
    char msg_hex[1024];
    sodium_bin2hex(msg_hex, sizeof(msg_hex), (unsigned char*)msg_str, strlen(msg_str));
    printf("Mensagem em hex: %s\n\n", msg_hex);
    
    // Derivar par de chaves da seed
    unsigned char pk[32];
    unsigned char sk[64];
    crypto_sign_seed_keypair(pk, sk, seed);
    
    printf("Public key (32 bytes): ");
    for (int i = 0; i < 32; i++) printf("%02x", pk[i]);
    printf("\n\n");
    
    printf("Secret key (64 bytes - primeiros 32): ");
    for (int i = 0; i < 32; i++) printf("%02x", sk[i]);
    printf("\n\n");
    
    // Assinar usando os bytes da mensagem diretamente
    unsigned char sig1[64];
    crypto_sign_detached(sig1, NULL, (unsigned char*)msg_str, strlen(msg_str), sk);
    
    printf("Assinatura 1 (bytes UTF-8): ");
    for (int i = 0; i < 64; i++) printf("%02x", sig1[i]);
    printf("\n\n");
    
    // Assinar usando o hex da mensagem
    unsigned char msg_bytes[256];
    size_t msg_bin_len;
    sodium_hex2bin(msg_bytes, sizeof(msg_bytes), msg_hex, strlen(msg_hex), NULL, &msg_bin_len, NULL);
    
    unsigned char sig2[64];
    crypto_sign_detached(sig2, NULL, msg_bytes, msg_bin_len, sk);
    
    printf("Assinatura 2 (bytes do hex): ");
    for (int i = 0; i < 64; i++) printf("%02x", sig2[i]);
    printf("\n\n");
    
    // Verificar qual assinatura é válida
    int v1 = crypto_sign_verify_detached(sig1, (unsigned char*)msg_str, strlen(msg_str), pk);
    int v2 = crypto_sign_verify_detached(sig2, msg_bytes, msg_bin_len, pk);
    
    printf("Verificacao assinatura 1 (bytes UTF-8): %s\n", v1 == 0 ? "VALIDA" : "INVALIDA");
    printf("Verificacao assinatura 2 (bytes hex): %s\n", v2 == 0 ? "VALIDA" : "INVALIDA");
    
    return 0;
}
