#include <stdio.h>
#include <string.h>
#include <sodium.h>

int main() {
    if (sodium_init() < 0) return 1;
    
    // Seed do identity.json (64 hex chars = 32 bytes)
    const char* seed_hex = "cf4e51fcb1100bd8e2620d496cfba8777a0b6f2ca65dc739a49d34909ff5cf88";
    
    // Nonce recebido do servidor (exemplo)
    const char* nonce_hex = "61cfd924da74c9d13825a98704fd709d";
    
    // Address e device_id
    const char* address = "r3fbdvnvLzcDqGiGezdH87UQVZDrNK2Gjx";
    const char* device_id = "d58f50052b0ebe57026175807d61877c";
    
    // Construir mensagem: "evergram-auth:{address}:{deviceId}:{nonce}"
    char challenge[512];
    int len = snprintf(challenge, sizeof(challenge), "evergram-auth:%s:%s:%s", address, device_id, nonce_hex);
    
    printf("Mensagem challenge: %s\n", challenge);
    printf("Comprimento: %d\n", len);
    
    // Converter mensagem para hex
    char challenge_hex[1025];
    sodium_bin2hex(challenge_hex, sizeof(challenge_hex), (const unsigned char*)challenge, len);
    printf("Challenge em hex: %s\n\n", challenge_hex);
    
    // Decodificar seed
    unsigned char seed_bytes[32];
    size_t bin_len;
    sodium_hex2bin(seed_bytes, 32, seed_hex, strlen(seed_hex), NULL, &bin_len, NULL);
    
    // Derivar par de chaves Ed25519
    unsigned char pk[32];
    unsigned char sk[64];
    crypto_sign_seed_keypair(pk, sk, seed_bytes);
    
    char pk_hex[65];
    sodium_bin2hex(pk_hex, sizeof(pk_hex), pk, 32);
    printf("Public key derivada: %s\n\n", pk_hex);
    
    // Assinar a mensagem (bytes brutos da mensagem UTF-8, NÃO o hex)
    unsigned char signature[64];
    crypto_sign_detached(signature, NULL, (const unsigned char*)challenge, len, sk);
    
    char signature_hex[129];
    sodium_bin2hex(signature_hex, sizeof(signature_hex), signature, 64);
    printf("Assinatura: %s\n\n", signature_hex);
    
    // Verificar assinatura
    int ret = crypto_sign_verify_detached(signature, (const unsigned char*)challenge, len, pk);
    if (ret == 0) {
        printf("SUCCESS: Assinatura verificada!\n");
    } else {
        printf("ERROR: Verificacao falhou!\n");
    }
    
    return 0;
}
