#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

int main() {
    sodium_init();
    
    // Seed do identity.json
    const char* seed_hex = "a4ae5165c6e33b7e8977ee4da783638026eb712820509621a8f63be63e2aa513";
    unsigned char seed[32];
    size_t len;
    sodium_hex2bin(seed, sizeof(seed), seed_hex, strlen(seed_hex), NULL, &len, NULL);
    
    printf("Seed (hex): %s\n", seed_hex);
    printf("Seed (bytes): ");
    for(int i=0; i<32; i++) printf("%02x", seed[i]);
    printf("\n");
    
    // ripple-keypairs usa HMAC-SHA512 com chave "ed25519 seed"
    const char* hmac_key = "ed25519 seed";
    unsigned char hmac_result[64];
    unsigned int hmac_len;
    HMAC(EVP_sha512(), hmac_key, strlen(hmac_key), seed, 32, hmac_result, &hmac_len);
    
    printf("HMAC-SHA512 resultado (64 bytes): ");
    for(int i=0; i<64; i++) printf("%02x", hmac_result[i]);
    printf("\n");
    
    // Primeiros 32 bytes sao usados como seed para Ed25519
    unsigned char ed25519_seed[32];
    memcpy(ed25519_seed, hmac_result, 32);
    
    printf("Ed25519 seed (32 bytes): ");
    for(int i=0; i<32; i++) printf("%02x", ed25519_seed[i]);
    printf("\n");
    
    // Gerar par de chaves
    unsigned char pk[32], sk[64];
    crypto_sign_seed_keypair(pk, sk, ed25519_seed);
    
    printf("Public key: ");
    for(int i=0; i<32; i++) printf("%02x", pk[i]);
    printf("\n");
    
    // Assinar desafio
    const char* challenge = "evergram-auth:rhVvUqMuF5JwKg9cev6WfrkeiahjiedhkM:0d926bfc9b3d87ec70ffe9abe5d1caac:b50ffffd12009fdd1ae0a4cb9d8ac7de";
    printf("Challenge: %s\n", challenge);
    
    unsigned char signed_msg[strlen(challenge) + 64];
    unsigned long long signed_len;
    crypto_sign(signed_msg, &signed_len, (unsigned char*)challenge, strlen(challenge), sk);
    
    // Assinatura sao os ultimos 64 bytes
    unsigned char* sig = signed_msg + strlen(challenge);
    printf("Signature: ");
    for(int i=0; i<64; i++) printf("%02x", sig[i]);
    printf("\n");
    
    return 0;
}
