/**
 * @file crypto_xrpl.c
 * @brief Implementação de criptografia XRPL compatível com ripple-keypairs
 * 
 * Este arquivo reimplementa a lógica exata do ripple-keypairs para garantir
 * compatibilidade total com o servidor Evergram.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <sodium.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/ripemd.h>
#include "evergram.h"

/* Alfabeto Base58 para XRPL */
static const char* BASE58_ALPHABET_XRPL = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

/* Prefixos de seed XRPL */
static const unsigned char ED25519_SEED_PREFIX[] = {0x21};  // 'sEd' prefix

/**
 * @brief Decodifica string Base58 para bytes
 */
static int base58_decode(const char* input, unsigned char* output, size_t* output_len, size_t max_output_len) {
    if (!input || !output || !output_len) {
        return -1;
    }
    
    size_t input_len = strlen(input);
    if (input_len == 0) {
        *output_len = 0;
        return 0;
    }
    
    /* Contar zeros à esquerda */
    size_t zeros = 0;
    while (zeros < input_len && input[zeros] == BASE58_ALPHABET_XRPL[0]) {
        zeros++;
    }
    
    /* Buffer para conversão */
    unsigned char b256[input_len];
    memset(b256, 0, sizeof(b256));
    size_t b256_len = 0;
    
    /* Converter de base58 para base256 */
    for (size_t i = zeros; i < input_len; i++) {
        /* Encontrar índice no alfabeto */
        int carry = -1;
        for (int j = 0; j < 58; j++) {
            if (BASE58_ALPHABET_XRPL[j] == input[i]) {
                carry = j;
                break;
            }
        }
        if (carry < 0) {
            return -1;  /* Caractere inválido */
        }
        
        /* Multiplicar por 58 e adicionar carry */
        for (size_t j = 0; j < b256_len || carry; j++) {
            carry += b256[j] * 58;
            b256[j] = carry % 256;
            carry /= 256;
            if (j >= b256_len) {
                b256_len++;
            }
        }
    }
    
    /* Adicionar zeros à esquerda */
    size_t out_idx = 0;
    for (size_t i = 0; i < zeros && out_idx < max_output_len; i++) {
        output[out_idx++] = 0;
    }
    
    /* Copiar bytes convertidos (em ordem reversa) */
    for (size_t i = 0; i < b256_len && out_idx < max_output_len; i++) {
        output[out_idx++] = b256[b256_len - 1 - i];
    }
    
    *output_len = out_idx;
    return 0;
}

/**
 * @brief Codifica bytes para string Base58
 */
static int base58_encode(const unsigned char* input, size_t input_len, char* output, size_t max_output_len) {
    if (!input || !output) {
        return -1;
    }
    
    if (input_len == 0) {
        output[0] = '\0';
        return 0;
    }
    
    /* Contar zeros à esquerda */
    size_t zeros = 0;
    while (zeros < input_len && input[zeros] == 0) {
        zeros++;
    }
    
    /* Buffer para conversão */
    unsigned char b58[input_len * 2];
    memset(b58, 0, sizeof(b58));
    size_t b58_len = 0;
    
    /* Converter de base256 para base58 */
    for (size_t i = zeros; i < input_len; i++) {
        int carry = input[i];
        for (size_t j = 0; j < b58_len || carry; j++) {
            carry += b58[j] * 256;
            b58[j] = carry % 58;
            carry /= 58;
            if (j >= b58_len) {
                b58_len++;
            }
        }
    }
    
    /* Verificar tamanho do output */
    if (max_output_len < zeros + b58_len + 1) {
        return -1;
    }
    
    /* Adicionar zeros à esquerda como 'r' */
    size_t out_idx = 0;
    for (size_t i = 0; i < zeros; i++) {
        output[out_idx++] = BASE58_ALPHABET_XRPL[0];
    }
    
    /* Converter para string */
    for (size_t i = 0; i < b58_len; i++) {
        output[out_idx++] = BASE58_ALPHABET_XRPL[b58[b58_len - 1 - i]];
    }
    
    output[out_idx] = '\0';
    return out_idx;
}

/**
 * @brief Calcula checksum SHA256 duplo (primeiros 4 bytes)
 */
static void xrpl_checksum(const unsigned char* data, size_t len, unsigned char* checksum) {
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    unsigned char hash2[SHA256_DIGEST_LENGTH];
    
    SHA256(data, len, hash1);
    SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);
    
    memcpy(checksum, hash2, 4);
}

/**
 * @brief Decodifica seed XRPL (formato sEd...) para bytes puros
 * 
 * O ripple-keypairs usa seeds no formato Base58Check com prefixo de 3 bytes:
 * - 0x21, 0xE1, 0x4B para Ed25519 (total 3 bytes)
 * - Seguido por 16 bytes de seed + 4 bytes checksum = 23 bytes totais
 * Esta função decodifica a seed e valida o checksum
 */
int evergram_decode_xrpl_seed(const char* seed_hex_or_base58, unsigned char* seed_out, size_t seed_out_size) {
    if (!seed_hex_or_base58 || !seed_out) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    size_t input_len = strlen(seed_hex_or_base58);
    
    /* Verificar se é seed hexadecimal (64 caracteres) */
    if (input_len == 64) {
        /* É hex, converter diretamente */
        size_t bin_len;
        if (sodium_hex2bin(seed_out, seed_out_size, seed_hex_or_base58, input_len, NULL, &bin_len, NULL) != 0) {
            return EVERGRAM_ERR_INVALID_PARAM;
        }
        if (bin_len != 32) {
            return EVERGRAM_ERR_INVALID_PARAM;
        }
        return EVERGRAM_SUCCESS;
    }
    
    /* Verificar se é seed Base58 (começa com 'sEd') */
    if (input_len < 3 || strncmp(seed_hex_or_base58, "sEd", 3) != 0) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    /* Decodificar Base58 */
    unsigned char decoded[100];
    size_t decoded_len = 0;
    
    if (base58_decode(seed_hex_or_base58, decoded, &decoded_len, sizeof(decoded)) != 0) {
        fprintf(stderr, "[crypto_xrpl] Erro ao decodificar Base58\\n");
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    printf("[crypto_xrpl] Seed Base58 decodificada (%zu bytes): ", decoded_len);
    for (size_t i = 0; i < decoded_len; i++) {
        printf("%02x ", decoded[i]);
    }
    printf("\\n");
    
    /* Validar estrutura: prefix (3) + seed (16) + checksum (4) = 23 bytes */
    /* O ripple-keypairs usa 16 bytes de seed, não 32! */
    if (decoded_len != 23) {
        fprintf(stderr, "[crypto_xrpl] Seed deve ter 23 bytes (3 prefix + 16 seed + 4 checksum), tem %zu\\n", decoded_len);
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    /* Validar prefixo (0x21, 0xE1, 0x4B para Ed25519) */
    if (decoded[0] != 0x21 || decoded[1] != 0xE1 || decoded[2] != 0x4B) {
        fprintf(stderr, "[crypto_xrpl] Prefixo invalido: %02x %02x %02x (esperado 21 E1 4B)\\n", decoded[0], decoded[1], decoded[2]);
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    /* Validar checksum */
    unsigned char expected_checksum[4];
    xrpl_checksum(decoded, 19, expected_checksum);  /* prefix (3) + seed (16) = 19 bytes */
    
    if (memcmp(decoded + 19, expected_checksum, 4) != 0) {
        fprintf(stderr, "[crypto_xrpl] Checksum invalido\\n");
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    /* Copiar seed (16 bytes após o prefixo de 3 bytes) */
    /* Precisamos expandir para 32 bytes preenchendo com zeros à direita */
    memset(seed_out, 0, 32);
    memcpy(seed_out, decoded + 3, 16);  /* Copiar 16 bytes da seed */
    
    printf("[crypto_xrpl] Seed expandida (32 bytes): ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", seed_out[i]);
    }
    printf("\\n");
    
    return EVERGRAM_SUCCESS;
}

/**
 * @brief Deriva par de chaves Ed25519 a partir de uma seed (igual ao ripple-keypairs)
 * 
 * O ripple-keypairs usa a seed de 16 bytes diretamente, preenchendo com zeros
 * à direita para formar 32 bytes, sem HMAC!
 * 
 * IMPORTANTE: As chaves no formato XRPL têm 33 bytes (66 hex chars):
 * - Byte 0: 0xED (prefixo para Ed25519)
 * - Bytes 1-32: chave pública/privada real
 */
int evergram_derive_keypair_from_seed(const unsigned char* seed, size_t seed_len,
                                       unsigned char* public_key, unsigned char* private_key) {
    if (!seed || !public_key || !private_key) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    if (seed_len != 16) {
        fprintf(stderr, "[crypto_xrpl] Seed deve ter 16 bytes, tem %zu\\n", seed_len);
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    /* 
     * ripple-keypairs usa a seed de 16 bytes diretamente,
     * preenchendo com zeros à direita para formar 32 bytes
     * NÃO usa HMAC-SHA512!
     */
    unsigned char ed25519_seed[32];
    memcpy(ed25519_seed, seed, 16);
    memset(ed25519_seed + 16, 0, 16);  /* Preencher com zeros à direita */
    
    printf("[crypto_xrpl] Seed Ed25519 (32 bytes com padding): ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", ed25519_seed[i]);
    }
    printf("\\n");
    
    /* Gerar par de chaves Ed25519 a partir da seed */
    unsigned char pk_raw[32];
    unsigned char sk_raw[64];
    
    if (crypto_sign_seed_keypair(pk_raw, sk_raw, ed25519_seed) != 0) {
        return EVERGRAM_ERR_CRYPTO;
    }
    
    /* 
     * Adicionar prefixo 0xED para formato XRPL (ripple-keypairs compatible)
     * Public key: ED + 32 bytes = 33 bytes
     * Private key: ED + 32 bytes (a seed Ed25519 de 32 bytes) = 33 bytes
     */
    public_key[0] = 0xED;
    memcpy(public_key + 1, pk_raw, 32);
    
    private_key[0] = 0xED;
    memcpy(private_key + 1, ed25519_seed, 32);  /* Usa a seed com padding, não a secret key completa */
    
    return EVERGRAM_SUCCESS;
}

/**
 * @brief Gera wallet XRPL compatível com ripple-keypairs
 */
int evergram_generate_wallet_xrpl(evergram_wallet_t* wallet) {
    if (!wallet) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    if (sodium_init() < 0) {
        return EVERGRAM_ERR_CRYPTO;
    }
    
    /* Gerar seed aleatória de 32 bytes */
    unsigned char seed[32];
    randombytes_buf(seed, sizeof(seed));
    
    /* Derivar par de chaves no formato XRPL (33 bytes cada com prefixo 0xED) */
    unsigned char pk[33];  // 1 byte prefix + 32 bytes chave
    unsigned char sk[33];  // 1 byte prefix + 32 bytes seed derivada
    
    if (evergram_derive_keypair_from_seed(seed, 32, pk, sk) != EVERGRAM_SUCCESS) {
        return EVERGRAM_ERR_CRYPTO;
    }
    
    /* Converter seed para hex */
    sodium_bin2hex(wallet->seed, sizeof(wallet->seed), seed, 32);
    
    /* Converter chaves para hex (66 caracteres = 33 bytes) */
    sodium_bin2hex(wallet->public_key_hex, sizeof(wallet->public_key_hex), pk, 33);
    sodium_bin2hex(wallet->private_key_hex, sizeof(wallet->private_key_hex), sk, 33);
    
    /* Gerar endereço XRPL a partir da chave pública (usando apenas os 32 bytes após o prefixo ED) */
    /* SHA256 da chave pública (apenas 32 bytes de dados, sem o prefixo ED) */
    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
    SHA256(pk + 1, 32, sha256_hash);  // Pula o prefixo 0xED
    
    /* RIPEMD160 do SHA256 */
    unsigned char ripemd[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160(sha256_hash, SHA256_DIGEST_LENGTH, ripemd);
    
    /* Payload: prefix (0x00) + RIPEMD160 + checksum */
    unsigned char payload[1 + RIPEMD160_DIGEST_LENGTH + 4];
    payload[0] = 0x00;
    memcpy(payload + 1, ripemd, RIPEMD160_DIGEST_LENGTH);
    xrpl_checksum(payload, 1 + RIPEMD160_DIGEST_LENGTH, payload + 1 + RIPEMD160_DIGEST_LENGTH);
    
    /* Codificar em Base58 */
    if (base58_encode(payload, sizeof(payload), wallet->address, sizeof(wallet->address)) <= 0) {
        return EVERGRAM_ERR_CRYPTO;
    }
    
    return EVERGRAM_SUCCESS;
}

/**
 * @brief Assina mensagem usando chave privada derivada de seed XRPL
 * 
 * Esta função replica exatamente o comportamento do sign() do ripple-keypairs
 */

/**
 * @brief Assina mensagem usando chave privada derivada de seed XRPL
 * 
 * Esta função replica exatamente o comportamento do sign() do ripple-keypairs
 * Usa crypto_sign_detached para obter apenas a assinatura (64 bytes)
 */
int evergram_sign_with_xrpl_seed(const char* message_hex, const char* private_key_hex,
                                  char* signature_hex, size_t signature_hex_size) {
    if (!message_hex || !private_key_hex || !signature_hex) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    /* Decodificar mensagem hex para bytes */
    size_t msg_len = strlen(message_hex);
    if (msg_len % 2 != 0) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    unsigned char message[msg_len / 2];
    size_t bin_msg_len;
    if (sodium_hex2bin(message, sizeof(message), message_hex, msg_len, NULL, &bin_msg_len, NULL) != 0) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    printf("[crypto_xrpl] Mensagem para assinar (%zu bytes): ", bin_msg_len);
    for (size_t i = 0; i < bin_msg_len && i < 50; i++) {
        printf("%02x ", message[i]);
    }
    printf("\n");
    
    /* Decodificar seed privada (pode ser hex ou Base58) */
    unsigned char seed[32];
    int ret = evergram_decode_xrpl_seed(private_key_hex, seed, sizeof(seed));
    if (ret != EVERGRAM_SUCCESS) {
        fprintf(stderr, "[crypto_xrpl] Erro ao decodificar seed: %d\n", ret);
        return ret;
    }
    
    printf("[crypto_xrpl] Seed decodificada (32 bytes): ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", seed[i]);
    }
    printf("\n");
    
    /* Aplicar HMAC-SHA512 para derivar a seed Ed25519 (como faz o ripple-keypairs) */
    const char* hmac_key = "ed25519 seed";
    unsigned char hmac_result[64];
    unsigned int hmac_len;
    HMAC(EVP_sha512(), hmac_key, strlen(hmac_key), seed, 32, hmac_result, &hmac_len);
    
    printf("[crypto_xrpl] HMAC-SHA512 resultado (64 bytes): ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", hmac_result[i]);
    }
    printf("...\n");
    
    /* Usar primeiros 32 bytes como seed para Ed25519 */
    unsigned char ed25519_seed[32];
    memcpy(ed25519_seed, hmac_result, 32);
    
    /* Derivar par de chaves da seed Ed25519 */
    unsigned char pk[32];
    unsigned char sk[64];
    
    ret = crypto_sign_seed_keypair(pk, sk, ed25519_seed);
    if (ret != 0) {
        fprintf(stderr, "[crypto_xrpl] Erro ao gerar par de chaves Ed25519\n");
        return EVERGRAM_ERR_CRYPTO;
    }
    
    printf("[crypto_xrpl] Public key derivada (32 bytes): ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", pk[i]);
    }
    printf("...\n");
    
    printf("[crypto_xrpl] Secret key derivada (64 bytes): ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", sk[i]);
    }
    printf("...\n");
    
    /* Assinar mensagem usando crypto_sign_detached para obter apenas a assinatura */
    unsigned char signature[64];
    if (crypto_sign_detached(signature, NULL, message, bin_msg_len, sk) != 0) {
        fprintf(stderr, "[crypto_xrpl] Erro ao assinar mensagem\n");
        return EVERGRAM_ERR_CRYPTO;
    }
    
    printf("[crypto_xrpl] Assinatura gerada (64 bytes): ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", signature[i]);
    }
    printf("...\n");
    
    /* Verificar assinatura com a public key (apenas para debug) */
    if (crypto_sign_verify_detached(signature, message, bin_msg_len, pk) != 0) {
        fprintf(stderr, "[crypto_xrpl] ERRO: Verificacao da assinatura falhou!\n");
        return EVERGRAM_ERR_CRYPTO;
    }
    printf("[crypto_xrpl] Assinatura verificada com sucesso!\n");
    
    /* Converter assinatura para hex */
    if (signature_hex_size < 129) {
        return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }
    
    sodium_bin2hex(signature_hex, signature_hex_size, signature, 64);
    
    return EVERGRAM_SUCCESS;
}
