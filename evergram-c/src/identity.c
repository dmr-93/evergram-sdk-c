#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include "evergram.h"
#include "proto/evergram.pb-c.h"

// Alfabeto Base58 para XRPL (começa com 'r')
static const char* BASE58_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

// Função auxiliar para converter bytes para hex string
static void bytes_to_hex(const unsigned char* bytes, size_t len, char* hex_out, size_t hex_out_size) {
    if (hex_out_size < len * 2 + 1) return;
    for (size_t i = 0; i < len; i++) {
        snprintf(hex_out + (i * 2), 3, "%02x", bytes[i]);
    }
    hex_out[len * 2] = '\0';
}

// Função para codificar em Base58
static int base58_encode(const unsigned char* input, size_t input_len, char* output, size_t output_size) {
    if (input_len == 0) {
        output[0] = '\0';
        return 0;
    }
    
    // Contar zeros à esquerda
    size_t zeros = 0;
    while (zeros < input_len && input[zeros] == 0) {
        zeros++;
    }
    
    // Buffer para o número em base58
    unsigned char b58[input_len * 2];
    memset(b58, 0, sizeof(b58));
    size_t b58_len = 0;
    
    // Converter para base58
    for (size_t i = zeros; i < input_len; i++) {
        int carry = input[i];
        for (size_t j = 0; j < b58_len || carry; j++) {
            carry += b58[j] * 256;
            b58[j] = carry % 58;
            carry /= 58;
            if (j >= b58_len) b58_len++;
        }
    }
    
    // Verificar tamanho do output
    if (output_size < zeros + b58_len + 1) {
        return -1;
    }
    
    // Adicionar zeros à esquerda como 'r' (alfabeto XRPL)
    size_t out_idx = 0;
    for (size_t i = 0; i < zeros; i++) {
        output[out_idx++] = BASE58_ALPHABET[0];  // 'r' para XRPL
    }
    
    // Converter para string
    for (size_t i = 0; i < b58_len; i++) {
        output[out_idx++] = BASE58_ALPHABET[b58[b58_len - 1 - i]];
    }
    
    output[out_idx] = '\0';
    return out_idx;
}

// Calcular checksum (SHA256 duplo + primeiros 4 bytes)
static void xrpl_checksum(const unsigned char* data, size_t len, unsigned char* checksum) {
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    unsigned char hash2[SHA256_DIGEST_LENGTH];
    
    SHA256(data, len, hash1);
    SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);
    
    memcpy(checksum, hash2, 4);
}

// Gerar endereço XRPL a partir da chave pública Ed25519
static int xrpl_address_from_pubkey(const unsigned char* pubkey, size_t pubkey_len, char* address, size_t addr_size) {
    unsigned char ripemd[RIPEMD160_DIGEST_LENGTH];
    unsigned char payload[1 + RIPEMD160_DIGEST_LENGTH + 4];  // prefix + RIPEMD160 + checksum
    
    // Passo 1: SHA256 da chave pública
    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
    SHA256(pubkey, pubkey_len, sha256_hash);
    
    // Passo 2: RIPEMD160 do SHA256
    RIPEMD160(sha256_hash, SHA256_DIGEST_LENGTH, ripemd);
    
    // Passo 3: Adicionar prefixo (0x00 para XRPL mainnet)
    payload[0] = 0x00;  // Version byte para XRPL
    memcpy(payload + 1, ripemd, RIPEMD160_DIGEST_LENGTH);
    
    // Passo 4: Calcular checksum
    xrpl_checksum(payload, 1 + RIPEMD160_DIGEST_LENGTH, payload + 1 + RIPEMD160_DIGEST_LENGTH);
    
    // Passo 5: Codificar em Base58
    return base58_encode(payload, sizeof(payload), address, addr_size);
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
    
    // Gerar endereço XRPL no formato Base58 correto (ex: rNPvaf8QNuUFh9xoRTj48BdoodWSywywdw)
    if (xrpl_address_from_pubkey(pk, sizeof(pk), wallet->address, sizeof(wallet->address)) <= 0) {
        return EVERGRAM_ERR_CRYPTO;
    }
    
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
