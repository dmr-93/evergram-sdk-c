#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

int main() {
    if (sodium_init() < 0) {
        fprintf(stderr, "Erro ao inicializar libsodium\n");
        return 1;
    }
    
    // Seed de 32 bytes em hex (igual ao identity.json)
    const char* seed_hex = "b2c5c1d78b6ba563b626cbb2b91d268952ea915f7251671835cf27691e037109";
    unsigned char seed[32];
    sodium_hex2bin(seed, sizeof(seed), seed_hex, strlen(seed_hex), NULL, NULL, NULL);
    
    // Nonce recebido do servidor
    const char* nonce = "a76762f77a285d08ae1cf1bf46bf2deb";
    
    // Address e device_id
    const char* address = "rK3VUVtsx28Etjn5GTpThv5wbCpzYgA7tj";
    const char* device_id = "d5032f64bb2d5c34be351b05a3676cec";
    
    // Construir mensagem
    char challenge[512];
    snprintf(challenge, sizeof(challenge), "evergram-auth:%s:%s:%s", address, device_id, nonce);
    printf("Mensagem challenge: %s\n", challenge);
    printf("Comprimento: %zu bytes\n\n", strlen(challenge));
    
    // Converter mensagem para hex
    char msg_hex[1024];
    sodium_bin2hex(msg_hex, sizeof(msg_hex), (unsigned char*)challenge, strlen(challenge));
    printf("Mensagem em hex: %s\n\n", msg_hex);
    
    // Derivar par de chaves Ed25519 da seed
    unsigned char pk[32];
    unsigned char sk[64];
    crypto_sign_seed_keypair(pk, sk, seed);
    
    printf("Public key (32 bytes, sem prefixo): ");
    for (int i = 0; i < 32; i++) printf("%02x", pk[i]);
    printf("\n\n");
    
    printf("Secret key completa (64 bytes): ");
    for (int i = 0; i < 64; i++) printf("%02x", sk[i]);
    printf("\n\n");
    
    // Assinar usando os bytes da mensagem diretamente
    unsigned char sig[64];
    crypto_sign_detached(sig, NULL, (unsigned char*)challenge, strlen(challenge), sk);
    
    printf("Assinatura (64 bytes): ");
    for (int i = 0; i < 64; i++) printf("%02x", sig[i]);
    printf("\n\n");
    
    // Verificar assinatura
    int v = crypto_sign_verify_detached(sig, (unsigned char*)challenge, strlen(challenge), pk);
    printf("Verificacao: %s\n\n", v == 0 ? "VALIDA" : "INVALIDA");
    
    // Agora testar com different derivation - talvez o ripple-keypairs use abordagem diferente
    printf("=== Testando abordagem alternativa ===\n");
    
    // O ripple-keypairs pode estar usando apenas a seed de 16 bytes?
    // Vamos tentar com SHA512 da seed
    unsigned char sha512_hash[64];
    // Usando OpenSSL para SHA512
    #include <openssl/sha.h>
    SHA512(seed, 32, sha512_hash);
    
    printf("SHA512 da seed (primeiros 32 bytes): ");
    for (int i = 0; i < 32; i++) printf("%02x", sha512_hash[i]);
    printf("\n");
    
    // Derivar chaves com SHA512
    unsigned char pk2[32];
    unsigned char sk2[64];
    crypto_sign_seed_keypair(pk2, sk2, sha512_hash);
    
    printf("Public key alternativa: ");
    for (int i = 0; i < 32; i++) printf("%02x", pk2[i]);
    printf("\n");
    
    // Assinar com esta chave
    unsigned char sig2[64];
    crypto_sign_detached(sig2, NULL, (unsigned char*)challenge, strlen(challenge), sk2);
    
    printf("Assinatura alternativa: ");
    for (int i = 0; i < 64; i++) printf("%02x", sig2[i]);
    printf("\n");
    
    int v2 = crypto_sign_verify_detached(sig2, (unsigned char*)challenge, strlen(challenge), pk2);
    printf("Verificacao alternativa: %s\n", v2 == 0 ? "VALIDA" : "INVALIDA");
    
    return 0;
}
