#include <stdio.h>
#include <string.h>
#include <sodium.h>

int main() {
    sodium_init();
    
    // Seed do identity.json
    const char* seed_hex = "cf4e51fcb1100bd8e2620d496cfba8777a0b6f2ca65dc739a49d34909ff5cf88";
    
    // Public key armazenada no identity.json (pubkey)
    const char* stored_pubkey = "11287eb07bdd95dfb82b255624c6f3ef598e392c68fd5516b1efab6c841d7838";
    
    // Decodificar seed
    unsigned char seed_bytes[32];
    size_t bin_len;
    sodium_hex2bin(seed_bytes, 32, seed_hex, strlen(seed_hex), NULL, &bin_len, NULL);
    
    // Derivar par de chaves
    unsigned char pk[32];
    unsigned char sk[64];
    crypto_sign_seed_keypair(pk, sk, seed_bytes);
    
    char derived_pubkey_hex[65];
    sodium_bin2hex(derived_pubkey_hex, sizeof(derived_pubkey_hex), pk, 32);
    
    printf("Seed: %s\n", seed_hex);
    printf("Public key armazenada: %s\n", stored_pubkey);
    printf("Public key derivada:   %s\n", derived_pubkey_hex);
    
    if (strcmp(stored_pubkey, derived_pubkey_hex) == 0) {
        printf("\nOK: Public keys coincidem!\n");
    } else {
        printf("\nERRO: Public keys NÃO coincidem!\n");
    }
    
    return 0;
}
