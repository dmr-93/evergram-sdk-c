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
    
    // Public key armazenada no identity.json
    const char* stored_pubkey = "bb46f2625ca4632f1bb72c37fadee58f0719e64a9dc3a4b2df12c3b228a70836";
    
    // Derivar par de chaves Ed25519 da seed
    unsigned char pk[32];
    unsigned char sk[64];
    crypto_sign_seed_keypair(pk, sk, seed);
    
    printf("Public key derivada da seed:\n  ");
    for (int i = 0; i < 32; i++) printf("%02x", pk[i]);
    printf("\n\n");
    
    printf("Public key armazenada:\n  %s\n\n", stored_pubkey);
    
    // Comparar
    char pk_hex[65];
    sodium_bin2hex(pk_hex, sizeof(pk_hex), pk, 32);
    
    if (strcmp(pk_hex, stored_pubkey) == 0) {
        printf("MATCH! As chaves são iguais.\n");
    } else {
        printf("MISMATCH! As chaves são diferentes.\n");
        printf("Isso explica o erro invalid_signed_message_signature!\n");
    }
    
    return 0;
}
