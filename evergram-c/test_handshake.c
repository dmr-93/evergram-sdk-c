#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

static int hex_to_bytes(const char* hex, uint8_t* out, size_t out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return -1;
    size_t bytes_len = hex_len / 2;
    if (bytes_len > out_len) return -1;
    
    for (size_t i = 0; i < bytes_len; i++) {
        unsigned int byte;
        if (sscanf(hex + 2*i, "%2x", &byte) != 1) {
            return -1;
        }
        out[i] = (uint8_t)byte;
    }
    return (int)bytes_len;
}

int main() {
    if (sodium_init() < 0) {
        fprintf(stderr, "Erro ao inicializar libsodium\n");
        return 1;
    }
    
    // Dados do identity.json
    const char* privkey_hex = "6d028a3dfd4db99348621594955e12ddbe5f6e22f9838bb4ace0ed6993f5a275";
    const char* address = "rf1bX9uf64qhsNF8onQTEoi52d5feRN4N2";
    const char* device_id = "db879be3de1fa9c3796f96905a249f56";
    const char* nonce_str = "bd5e4432a52736d475b2535345782e32";
    
    printf("privkey_hex: %s (len=%zu)\n", privkey_hex, strlen(privkey_hex));
    printf("address: %s\n", address);
    printf("device_id: %s\n", device_id);
    printf("nonce: %s (len=%zu)\n", nonce_str, strlen(nonce_str));
    
    // Converter private_key_hex para seed bytes
    unsigned char seed_bytes[32];
    int seed_len = hex_to_bytes(privkey_hex, seed_bytes, sizeof(seed_bytes));
    printf("seed_len: %d\n", seed_len);
    
    if (seed_len != 32) {
        fprintf(stderr, "Erro: seed_len != 32\n");
        return 1;
    }
    
    // Reconstruir par de chaves
    unsigned char pk[32], sk[64];
    if (crypto_sign_seed_keypair(pk, sk, seed_bytes) != 0) {
        fprintf(stderr, "Erro ao gerar par de chaves\n");
        return 1;
    }
    
    printf("pk: ");
    for (int i = 0; i < 32; i++) printf("%02x", pk[i]);
    printf("\n");
    
    // Construir challenge
    char challenge[512];
    snprintf(challenge, sizeof(challenge), "evergram-auth:%s:%s:%s", address, device_id, nonce_str);
    printf("challenge: %s (len=%zu)\n", challenge, strlen(challenge));
    
    // Assinar
    unsigned char signature[64];
    unsigned long long sig_len;
    int ret = crypto_sign_detached(signature, &sig_len, 
                                   (const unsigned char*)challenge, strlen(challenge), 
                                   sk);
    printf("crypto_sign_detached retornou: %d\n", ret);
    printf("sig_len: %llu\n", sig_len);
    
    if (ret != 0) {
        fprintf(stderr, "Erro ao assinar\n");
        return 1;
    }
    
    printf("signature: ");
    for (int i = 0; i < 64; i++) printf("%02x", signature[i]);
    printf("\n");
    
    // Verificar
    ret = crypto_sign_verify_detached(signature, (const unsigned char*)challenge, strlen(challenge), pk);
    printf("Verificacao: %d (0=OK)\n", ret);
    
    return 0;
}
