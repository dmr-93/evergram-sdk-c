#include <stdio.h>
#include <string.h>
#include <sodium.h>

#define EVERGRAM_SUCCESS 0
#define EVERGRAM_ERR_INVALID_PARAM -1

int evergram_decode_xrpl_seed(const char* seed_hex_or_base58, unsigned char* seed_out, size_t seed_out_size) {
    if (!seed_hex_or_base58 || !seed_out) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }

    size_t input_len = strlen(seed_hex_or_base58);
    printf("Input length: %zu\n", input_len);

    /* Verificar se é seed hexadecimal (64 caracteres = 32 bytes) */
    if (input_len == 64) {
        /* É hex - usar todos os 32 bytes como seed Ed25519 direta */
        size_t bin_len;
        int ret = sodium_hex2bin(seed_out, 32, seed_hex_or_base58, input_len, NULL, &bin_len, NULL);
        printf("sodium_hex2bin result: %d, bin_len: %zu\n", ret, bin_len);
        if (ret != 0) {
            return EVERGRAM_ERR_INVALID_PARAM;
        }
        if (bin_len != 32) {
            return EVERGRAM_ERR_INVALID_PARAM;
        }
        printf("[crypto_xrpl] Seed hexadecimal convertida para 32 bytes: ");
        for (int i = 0; i < 32; i++) {
            printf("%02x", seed_out[i]);
        }
        printf("\n");
        return EVERGRAM_SUCCESS;
    }

    /* Verificar se é seed Base58 (começa com 'sEd') */
    if (input_len < 3 || strncmp(seed_hex_or_base58, "sEd", 3) != 0) {
        printf("Not Base58 seed (doesn't start with sEd)\n");
        return EVERGRAM_ERR_INVALID_PARAM;
    }

    return EVERGRAM_SUCCESS;
}

int main() {
    const char* seed_hex = "e82d7d3fb458c60663578e3de933c2a8a157395e4838596605f2932e563c781e";
    unsigned char seed[32];
    
    printf("Testing seed decoding...\n");
    int ret = evergram_decode_xrpl_seed(seed_hex, seed, sizeof(seed));
    printf("Result: %d\n", ret);
    
    return 0;
}
