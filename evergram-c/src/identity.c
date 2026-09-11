#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include "evergram.h"
#include "proto/evergram.pb-c.h"

// Função auxiliar para converter bytes para hex string
static void bytes_to_hex(const unsigned char* bytes, size_t len, char* hex_out, size_t hex_out_size) {
    if (hex_out_size < len * 2 + 1) return;
    for (size_t i = 0; i < len; i++) {
        snprintf(hex_out + (i * 2), 3, "%02x", bytes[i]);
    }
    hex_out[len * 2] = '\0';
}

// Implementação de evergram_generate_wallet
int evergram_generate_wallet(evergram_wallet_t* wallet) {
    if (!wallet) return EVERGRAM_ERR_INVALID_PARAM;
    
    if (sodium_init() < 0) {
        return EVERGRAM_ERR_CRYPTO;
    }
    
    // Gerar seed aleatória
    unsigned char seed[crypto_sign_SEEDBYTES];
    randombytes_buf(seed, sizeof(seed));
    
    // Gerar par de chaves Ed25519 para XRPL a partir da seed
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    
    if (crypto_sign_seed_keypair(pk, sk, seed) != 0) {
        return EVERGRAM_ERR_CRYPTO;
    }
    
    // Converter para hex strings
    bytes_to_hex(seed, sizeof(seed), wallet->seed, sizeof(wallet->seed));
    bytes_to_hex(pk, sizeof(pk), wallet->public_key_hex, sizeof(wallet->public_key_hex));
    bytes_to_hex(sk, sizeof(sk), wallet->private_key_hex, sizeof(wallet->private_key_hex));
    
    // Gerar endereço clássico da Ripple (simplificado - baseado no public key)
    // Em produção, precisaria do algoritmo real de encoding da Ripple com checksum
    snprintf(wallet->address, sizeof(wallet->address), "r");
    for (int i = 0; i < 8; i++) {
        snprintf(wallet->address + 1 + (i * 2), 3, "%02X", pk[i]);
    }
    strcat(wallet->address, "...");
    
    return EVERGRAM_SUCCESS;
}

// Implementação de evergram_generate_device
int evergram_generate_device(evergram_device_t* device) {
    if (!device) return EVERGRAM_ERR_INVALID_PARAM;
    
    if (sodium_init() < 0) {
        return EVERGRAM_ERR_CRYPTO;
    }
    
    // Gerar par de chaves Curve25519 para ECDH
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    
    if (crypto_box_keypair(pk, sk) != 0) {
        return EVERGRAM_ERR_CRYPTO;
    }
    
    // Converter chaves para hex
    bytes_to_hex(pk, sizeof(pk), device->pub_hex, sizeof(device->pub_hex));
    bytes_to_hex(sk, sizeof(sk), device->priv_hex, sizeof(device->priv_hex));
    
    // Derivar device_id a partir da chave pública (hash simplificado)
    unsigned char hash[32];
    crypto_hash_sha256(hash, pk, sizeof(pk));
    bytes_to_hex(hash, EVERGRAM_DEVICE_ID_LEN / 2, device->device_id, sizeof(device->device_id));
    
    return EVERGRAM_SUCCESS;
}

// Função auxiliar para salvar wallet em arquivo
int evergram_save_wallet(const evergram_wallet_t* wallet, const char* filename) {
    if (!wallet || !filename) return EVERGRAM_ERR_INVALID_PARAM;
    
    FILE* f = fopen(filename, "wb");
    if (!f) return EVERGRAM_ERR_NETWORK;
    
    fwrite(wallet, sizeof(evergram_wallet_t), 1, f);
    fclose(f);
    
    return EVERGRAM_SUCCESS;
}

// Função auxiliar para carregar wallet de arquivo
int evergram_load_wallet(evergram_wallet_t* wallet, const char* filename) {
    if (!wallet || !filename) return EVERGRAM_ERR_INVALID_PARAM;
    
    FILE* f = fopen(filename, "rb");
    if (!f) return EVERGRAM_ERR_NETWORK;
    
    size_t read = fread(wallet, sizeof(evergram_wallet_t), 1, f);
    fclose(f);
    
    if (read != 1) return EVERGRAM_ERR_PROTO;
    
    return EVERGRAM_SUCCESS;
}

// Função auxiliar para salvar device em arquivo
int evergram_save_device(const evergram_device_t* device, const char* filename) {
    if (!device || !filename) return EVERGRAM_ERR_INVALID_PARAM;
    
    FILE* f = fopen(filename, "wb");
    if (!f) return EVERGRAM_ERR_NETWORK;
    
    fwrite(device, sizeof(evergram_device_t), 1, f);
    fclose(f);
    
    return EVERGRAM_SUCCESS;
}

// Função auxiliar para carregar device de arquivo
int evergram_load_device(evergram_device_t* device, const char* filename) {
    if (!device || !filename) return EVERGRAM_ERR_INVALID_PARAM;
    
    FILE* f = fopen(filename, "rb");
    if (!f) return EVERGRAM_ERR_NETWORK;
    
    size_t read = fread(device, sizeof(evergram_device_t), 1, f);
    fclose(f);
    
    if (read != 1) return EVERGRAM_ERR_PROTO;
    
    return EVERGRAM_SUCCESS;
}
