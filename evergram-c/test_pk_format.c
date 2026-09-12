#include <stdio.h>
#include <string.h>
#include <sodium.h>

int main() {
    if (sodium_init() < 0) return 1;
    
    const char* seed_hex = "cf4e51fcb1100bd8e2620d496cfba8777a0b6f2ca65dc739a49d34909ff5cf88";
    
    // Decodificar seed
    unsigned char seed_bytes[32];
    size_t bin_len;
    sodium_hex2bin(seed_bytes, 32, seed_hex, strlen(seed_hex), NULL, &bin_len, NULL);
    
    // Derivar par de chaves
    unsigned char pk[32];
    unsigned char sk[64];
    crypto_sign_seed_keypair(pk, sk, seed_bytes);
    
    // Formato 1: 32 bytes (64 hex chars) - sem prefixo
    char pk_32bytes[65];
    sodium_bin2hex(pk_32bytes, sizeof(pk_32bytes), pk, 32);
    printf("PK 32 bytes (64 hex): %s\n", pk_32bytes);
    
    // Formato 2: 33 bytes (66 hex chars) - com prefixo 0xED
    unsigned char pk_with_prefix[33];
    pk_with_prefix[0] = 0xED;
    memcpy(pk_with_prefix + 1, pk, 32);
    char pk_33bytes[67];
    sodium_bin2hex(pk_33bytes, sizeof(pk_33bytes), pk_with_prefix, 33);
    printf("PK 33 bytes (66 hex): %s\n", pk_33bytes);
    
    // O que está no identity.json?
    printf("\nPK no identity.json:  11287eb07bdd95dfb82b255624c6f3ef598e392c68fd5516b1efab6c841d7838\n");
    printf("Length: 64 chars = 32 bytes (SEM prefixo 0xED)\n");
    
    return 0;
}
