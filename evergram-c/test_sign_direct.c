#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <openssl/sha.h>

int main() {
    sodium_init();
    
    // Seed do identity.json (64 hex chars = 32 bytes)
    const char* seed_hex = "cf48255fe16b4af10bf50a4bdf1f670033e0fff8f357e7fa7f9cdea9dca49a82";
    
    // Converter seed hex para bytes
    unsigned char seed_bytes[32];
    size_t len;
    sodium_hex2bin(seed_bytes, 32, seed_hex, 64, NULL, &len, NULL);
    
    printf("Seed original (32 bytes): ");
    for(int i=0; i<32; i++) printf("%02x", seed_bytes[i]);
    printf("\n");
    
    // Opção 1: Usar seed diretamente (como faz o ripple-keypairs para seeds de 32 bytes)
    unsigned char pk1[32], sk1[64];
    crypto_sign_seed_keypair(pk1, sk1, seed_bytes);
    
    printf("\nOpcao 1 - Seed direta:\n");
    printf("Public key (32 bytes): ");
    for(int i=0; i<32; i++) printf("%02x", pk1[i]);
    printf("\n");
    
    // Opção 2: Aplicar SHA512 nos primeiros 16 bytes (como faz para seeds de 16 bytes)
    unsigned char sha512_hash[64];
    SHA512(seed_bytes, 16, sha512_hash);
    unsigned char pk2[32], sk2[64];
    crypto_sign_seed_keypair(pk2, sk2, sha512_hash);
    
    printf("\nOpcao 2 - SHA512(16 bytes):\n");
    printf("Public key (32 bytes): ");
    for(int i=0; i<32; i++) printf("%02x", pk2[i]);
    printf("\n");
    
    return 0;
}
