#include <stdio.h>
#include <string.h>
#include <sodium.h>

int main() {
    if (sodium_init() < 0) {
        return 1;
    }
    
    // Device pub hex do identity.json do TS
    const char* devicePubHex = "199310e27f1a6f5784002b8fb1d91b8a3ef98a33a2499b39519ae5da543a9366";
    
    // Converter hex para bytes
    unsigned char pub_key[32];
    size_t bin_len;
    if (sodium_hex2bin(pub_key, 32, devicePubHex, strlen(devicePubHex), NULL, &bin_len, NULL) != 0) {
        printf("Erro ao converter hex\n");
        return 1;
    }
    
    printf("Device Pub Hex: %s\n", devicePubHex);
    printf("Bytes da chave publica (%zu bytes): ", bin_len);
    for (size_t i = 0; i < bin_len; i++) {
        printf("%02x", pub_key[i]);
    }
    printf("\n");
    
    // Hash SHA-256 da chave pública
    unsigned char hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(hash, pub_key, bin_len);
    
    printf("SHA256 completo (64 bytes): ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
    
    // TypeScript: slice(0, 32) = 32 caracteres hex = 16 bytes
    char deviceId[33];
    sodium_bin2hex(deviceId, sizeof(deviceId), hash, 16);
    
    printf("Device ID (C - 16 bytes -> 32 hex chars): %s\n", deviceId);
    printf("Device ID length: %zu\n", strlen(deviceId));
    
    return 0;
}
