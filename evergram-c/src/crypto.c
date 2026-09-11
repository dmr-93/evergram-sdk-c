/**
 * @file crypto.c
 * @brief Implementação de criptografia usando libsodium para Evergram SDK C
 */

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "evergram.h"

/* Constantes criptográficas */
#define EVERGRAM_BOX_PUBLICKEYBYTES crypto_box_PUBLICKEYBYTES
#define EVERGRAM_BOX_SECRETKEYBYTES crypto_box_SECRETKEYBYTES
#define EVERGRAM_BOX_NONCEBYTES crypto_box_NONCEBYTES

/* Estrutura interna para contexto criptográfico */
typedef struct {
    unsigned char device_publickey[EVERGRAM_BOX_PUBLICKEYBYTES];
    unsigned char device_secretkey[EVERGRAM_BOX_SECRETKEYBYTES];
    unsigned char server_publickey[EVERGRAM_BOX_PUBLICKEYBYTES];
    unsigned char shared_key[crypto_secretbox_KEYBYTES];
    bool keys_initialized;
} evergram_crypto_context_t;

/**
 * @brief Inicializa a biblioteca libsodium
 * @return EVERGRAM_SUCCESS se sucesso, erro caso contrário
 */
evergram_error_t evergram_crypto_init(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "[Evergram] Falha ao inicializar libsodium\n");
        return EVERGRAM_ERR_CRYPTO;
    }
    return EVERGRAM_SUCCESS;
}

/**
 * @brief Gera um par de chaves para dispositivo
 * @param public_key Buffer para chave pública (tamanho: EVERGRAM_DEVICE_KEY_LEN)
 * @param secret_key Buffer para chave secreta (tamanho: EVERGRAM_DEVICE_KEY_LEN)
 * @return EVERGRAM_SUCCESS se sucesso, erro caso contrário
 */
evergram_error_t evergram_generate_device_keys(unsigned char *public_key, 
                                                unsigned char *secret_key) {
    if (!public_key || !secret_key) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    if (crypto_box_keypair(public_key, secret_key) != 0) {
        fprintf(stderr, "[Evergram] Falha ao gerar par de chaves do dispositivo\n");
        return EVERGRAM_ERR_CRYPTO;
    }
    
    return EVERGRAM_SUCCESS;
}

/**
 * @brief Deriva um ID de dispositivo a partir da chave pública (versão interna binária)
 */
static evergram_error_t evergram_derive_device_id_bin(const unsigned char *public_key, 
                                                       unsigned char *device_id) {
    if (!public_key || !device_id) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    /* Hash SHA-256 da chave pública para criar o ID */
    unsigned char hash[crypto_hash_sha256_BYTES];
    if (crypto_hash_sha256(hash, public_key, EVERGRAM_DEVICE_KEY_LEN) != 0) {
        return EVERGRAM_ERR_CRYPTO;
    }
    
    /* Copia os primeiros 16 bytes como ID do dispositivo */
    memcpy(device_id, hash, EVERGRAM_DEVICE_ID_LEN);
    
    return EVERGRAM_SUCCESS;
}

/**
 * @brief Deriva device_id a partir da chave pública (API pública - hex string)
 */
int evergram_derive_device_id(const char* device_pub_hex, char* device_id_out) {
    if (!device_pub_hex || !device_id_out) {
        return (int)EVERGRAM_ERR_INVALID_PARAM;
    }
    
    /* Converte hex para binário */
    unsigned char pub_key[EVERGRAM_DEVICE_KEY_LEN];
    if (evergram_hex_to_key(device_pub_hex, pub_key) != EVERGRAM_SUCCESS) {
        return (int)EVERGRAM_ERR_INVALID_PARAM;
    }
    
    /* Deriva ID em binário */
    unsigned char device_id_bin[EVERGRAM_DEVICE_ID_LEN];
    if (evergram_derive_device_id_bin(pub_key, device_id_bin) != EVERGRAM_SUCCESS) {
        return (int)EVERGRAM_ERR_CRYPTO;
    }
    
    /* Converte ID binário para hex string */
    sodium_bin2hex(device_id_out, EVERGRAM_MAX_DEVICE_ID_LEN, 
                   device_id_bin, EVERGRAM_DEVICE_ID_LEN);
    
    return (int)EVERGRAM_SUCCESS;
}

/**
 * @brief Criptografa uma mensagem usando crypto_secretbox
 * @param plaintext Dados originais
 * @param plaintext_len Tamanho dos dados originais
 * @param nonce Nonce (tamanho: EVERGRAM_NONCE_LEN)
 * @param shared_key Chave compartilhada (tamanho: crypto_secretbox_KEYBYTES)
 * @param ciphertext Buffer de saída para dados criptografados
 * @param ciphertext_len Ponteiro para tamanho do ciphertext de saída
 * @return EVERGRAM_SUCCESS se sucesso, erro caso contrário
 */
evergram_error_t evergram_encrypt_message(const unsigned char *plaintext,
                                           size_t plaintext_len,
                                           const unsigned char *nonce,
                                           const unsigned char *shared_key,
                                           unsigned char *ciphertext,
                                           size_t *ciphertext_len) {
    if (!plaintext || !nonce || !shared_key || !ciphertext || !ciphertext_len) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    /* Verifica tamanho mínimo */
    if (*ciphertext_len < plaintext_len + EVERGRAM_MAC_BYTES) {
        return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }
    
    /* Criptografa usando crypto_secretbox_easy */
    if (crypto_secretbox_easy(ciphertext, plaintext, plaintext_len, nonce, shared_key) != 0) {
        fprintf(stderr, "[Evergram] Falha ao criptografar mensagem\n");
        return EVERGRAM_ERR_CRYPTO;
    }
    
    *ciphertext_len = plaintext_len + EVERGRAM_MAC_BYTES;
    return EVERGRAM_SUCCESS;
}

/**
 * @brief Descriptografa uma mensagem usando crypto_secretbox_open
 * @param ciphertext Dados criptografados
 * @param ciphertext_len Tamanho dos dados criptografados
 * @param nonce Nonce (tamanho: EVERGRAM_NONCE_LEN)
 * @param shared_key Chave compartilhada
 * @param plaintext Buffer de saída para dados descriptografados
 * @param plaintext_len Ponteiro para tamanho do plaintext de saída
 * @return EVERGRAM_SUCCESS se sucesso, erro caso contrário
 */
evergram_error_t evergram_decrypt_message(const unsigned char *ciphertext,
                                           size_t ciphertext_len,
                                           const unsigned char *nonce,
                                           const unsigned char *shared_key,
                                           unsigned char *plaintext,
                                           size_t *plaintext_len) {
    if (!ciphertext || !nonce || !shared_key || !plaintext || !plaintext_len) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    /* Verifica tamanho mínimo */
    if (ciphertext_len <= EVERGRAM_MAC_BYTES) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    /* Verifica buffer de saída */
    size_t max_plaintext_len = ciphertext_len - EVERGRAM_MAC_BYTES;
    if (*plaintext_len < max_plaintext_len) {
        return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }
    
    /* Descriptografa usando crypto_secretbox_open_easy */
    if (crypto_secretbox_open_easy(plaintext, ciphertext, ciphertext_len, nonce, shared_key) != 0) {
        fprintf(stderr, "[Evergram] Falha ao descriptografar mensagem (autenticação falhou)\n");
        return EVERGRAM_ERR_CRYPTO;
    }
    
    *plaintext_len = max_plaintext_len;
    return EVERGRAM_SUCCESS;
}

/**
 * @brief Gera um nonce aleatório seguro
 * @param nonce Buffer de saída (tamanho: EVERGRAM_NONCE_LEN)
 * @return EVERGRAM_SUCCESS se sucesso, erro caso contrário
 */
evergram_error_t evergram_generate_nonce(unsigned char *nonce) {
    if (!nonce) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    randombytes_buf(nonce, EVERGRAM_MAX_NONCE_LEN);
    return EVERGRAM_SUCCESS;
}

/**
 * @brief Assina uma mensagem com a chave secreta do dispositivo
 */
evergram_error_t evergram_sign_message(const unsigned char *message,
                                        size_t message_len,
                                        const unsigned char *secret_key,
                                        unsigned char *signature,
                                        size_t *signature_len) {
    if (!message || !secret_key || !signature || !signature_len) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    /* Verifica buffer de saída */
    if (*signature_len < crypto_sign_BYTES) {
        return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }
    
    /* Assina usando crypto_sign */
    unsigned long long signed_msg_len;
    unsigned char *signed_msg = malloc(message_len + crypto_sign_BYTES);
    if (!signed_msg) {
        return EVERGRAM_ERR_MEMORY;
    }
    
    if (crypto_sign(signed_msg, &signed_msg_len, message, message_len, secret_key) != 0) {
        free(signed_msg);
        fprintf(stderr, "[Evergram] Falha ao assinar mensagem\n");
        return EVERGRAM_ERR_CRYPTO;
    }
    
    /* Extrai apenas a assinatura (primeiros crypto_sign_BYTES bytes) */
    memcpy(signature, signed_msg, crypto_sign_BYTES);
    *signature_len = crypto_sign_BYTES;
    
    free(signed_msg);
    return EVERGRAM_SUCCESS;
}

/**
 * @brief Verifica a assinatura de uma mensagem
 */
evergram_error_t evergram_verify_signature(const unsigned char *message,
                                            size_t message_len,
                                            const unsigned char *signature,
                                            size_t signature_len,
                                            const unsigned char *public_key) {
    if (!message || !signature || !public_key) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    if (signature_len != crypto_sign_BYTES) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    /* Prepara mensagem assinada */
    unsigned char *signed_msg = malloc(signature_len + message_len);
    if (!signed_msg) {
        return EVERGRAM_ERR_MEMORY;
    }
    memcpy(signed_msg, signature, crypto_sign_BYTES);
    memcpy(signed_msg + crypto_sign_BYTES, message, message_len);
    
    unsigned long long verified_msg_len;
    unsigned char *verified_msg = malloc(message_len);
    if (!verified_msg) {
        free(signed_msg);
        return EVERGRAM_ERR_MEMORY;
    }
    
    /* Verifica usando crypto_sign_open */
    int ret = crypto_sign_open(verified_msg, &verified_msg_len, signed_msg, 
                               signature_len + message_len, public_key);
    free(signed_msg);
    
    if (ret != 0) {
        free(verified_msg);
        fprintf(stderr, "[Evergram] Assinatura inválida\n");
        return EVERGRAM_ERR_CRYPTO;
    }
    
    /* Verifica se o conteúdo bate */
    if (verified_msg_len != message_len || memcmp(verified_msg, message, message_len) != 0) {
        free(verified_msg);
        return EVERGRAM_ERR_CRYPTO;
    }
    
    free(verified_msg);
    return EVERGRAM_SUCCESS;
}

/**
 * @brief Converte chave pública para formato hexadecimal
 * @param key Chave pública binária
 * @param hex_output Buffer de saída para string hex
 * @return EVERGRAM_SUCCESS se sucesso, erro caso contrário
 */
evergram_error_t evergram_key_to_hex(const unsigned char *key, char *hex_output) {
    if (!key || !hex_output) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    sodium_bin2hex(hex_output, EVERGRAM_DEVICE_KEY_LEN * 2 + 1, 
                   key, EVERGRAM_DEVICE_KEY_LEN);
    
    return EVERGRAM_SUCCESS;
}

/**
 * @brief Converte string hexadecimal para chave binária
 * @param hex_input String hexadecimal
 * @param key_output Buffer de saída para chave binária
 * @return EVERGRAM_SUCCESS se sucesso, erro caso contrário
 */
evergram_error_t evergram_hex_to_key(const char *hex_input, unsigned char *key_output) {
    if (!hex_input || !key_output) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    if (sodium_hex2bin(key_output, EVERGRAM_DEVICE_KEY_LEN, hex_input, 
                       strlen(hex_input), NULL, NULL, NULL) != 0) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    return EVERGRAM_SUCCESS;
}

/**
 * @brief Gera um timestamp Unix em milissegundos
 * @return Timestamp atual em ms
 */
uint64_t evergram_get_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

/**
 * @brief Converte bytes para string hexadecimal
 * @param bytes Buffer de entrada
 * @param len Número de bytes
 * @param out Buffer de saída (deve ter espaço para 2*len + 1)
 * @param out_len Tamanho do buffer de saída
 * @return EVERGRAM_SUCCESS se sucesso, erro caso contrário
 */
evergram_error_t evergram_bytes_to_hex(const uint8_t* bytes, size_t len, char* out, size_t out_len) {
    if (!bytes || !out) {
        return EVERGRAM_ERR_INVALID_PARAM;
    }
    
    /* Verifica se buffer de saída é grande o suficiente */
    if (out_len < len * 2 + 1) {
        return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }
    
    sodium_bin2hex(out, out_len, bytes, len);
    return EVERGRAM_SUCCESS;
}

/**
 * @brief Converte string hexadecimal para bytes
 * @param hex String hex de entrada
 * @param out Buffer de saída
 * @param out_len Tamanho do buffer de saída
 * @return Número de bytes escritos ou erro negativo
 */
int evergram_hex_to_bytes(const char* hex, uint8_t* out, size_t out_len) {
    if (!hex || !out) {
        return (int)EVERGRAM_ERR_INVALID_PARAM;
    }
    
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) {
        return (int)EVERGRAM_ERR_INVALID_PARAM;
    }
    
    size_t bytes_len = hex_len / 2;
    if (bytes_len > out_len) {
        return (int)EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }
    
    size_t bin_len;
    if (sodium_hex2bin(out, out_len, hex, hex_len, NULL, &bin_len, NULL) != 0) {
        return (int)EVERGRAM_ERR_INVALID_PARAM;
    }
    
    return (int)bytes_len;
}
