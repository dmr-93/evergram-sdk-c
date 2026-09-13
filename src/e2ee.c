#include "e2ee.h"

#include <sodium.h>
#include <stdlib.h>
#include <string.h>

#include "base64.h"
#include "log.h"

/* A sealed chat key is 32 bytes plus the Poly1305 tag. */
#define SEALED_KEY_BYTES (E2EE_KEY_BYTES + crypto_box_MACBYTES)
#define SEALED_CIPHERTEXT_MAX 128

static evergram_status_t decode_exact(const char *text, uint8_t *out, size_t out_size,
                                      size_t expected_len) {
    size_t len = 0;
    evergram_status_t status = base64_decode(text, out, out_size, &len);
    if (status != EVERGRAM_OK) {
        return status;
    }
    if (len != expected_len) {
        sodium_memzero(out, out_size);
        return EVERGRAM_ERR_ENCODING;
    }
    return EVERGRAM_OK;
}

evergram_status_t e2ee_open_sealed_key(const char *ciphertext_b64, const char *nonce_b64,
                                       const char *ephemeral_pubkey_b64,
                                       const char *device_private_key_hex,
                                       uint8_t out_key[E2EE_KEY_BYTES]) {
    if (ciphertext_b64 == NULL || nonce_b64 == NULL || ephemeral_pubkey_b64 == NULL ||
        device_private_key_hex == NULL || out_key == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (strlen(device_private_key_hex) != 2u * crypto_box_SECRETKEYBYTES) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    uint8_t ciphertext[SEALED_CIPHERTEXT_MAX];
    uint8_t nonce[E2EE_NONCE_BYTES];
    uint8_t ephemeral_pubkey[crypto_box_PUBLICKEYBYTES];
    uint8_t device_secret[crypto_box_SECRETKEYBYTES];
    uint8_t opened[SEALED_CIPHERTEXT_MAX];
    evergram_status_t status = EVERGRAM_OK;

    status = decode_exact(ciphertext_b64, ciphertext, sizeof(ciphertext), SEALED_KEY_BYTES);
    if (status != EVERGRAM_OK) {
        goto cleanup;
    }
    status = decode_exact(nonce_b64, nonce, sizeof(nonce), E2EE_NONCE_BYTES);
    if (status != EVERGRAM_OK) {
        goto cleanup;
    }
    status = decode_exact(ephemeral_pubkey_b64, ephemeral_pubkey, sizeof(ephemeral_pubkey),
                          crypto_box_PUBLICKEYBYTES);
    if (status != EVERGRAM_OK) {
        goto cleanup;
    }
    if (sodium_hex2bin(device_secret, sizeof(device_secret), device_private_key_hex,
                       2u * sizeof(device_secret), NULL, NULL, NULL) != 0) {
        status = EVERGRAM_ERR_ENCODING;
        goto cleanup;
    }

    /* The ciphertext length must be the decoded size, not the buffer size. */
    if (crypto_box_open_easy(opened, ciphertext, SEALED_KEY_BYTES, nonce, ephemeral_pubkey,
                             device_secret) != 0) {
        EG_WARN("sealed chat key did not open with this device");
        status = EVERGRAM_ERR_CRYPTO;
        goto cleanup;
    }

    memcpy(out_key, opened, E2EE_KEY_BYTES);

cleanup:
    sodium_memzero(ciphertext, sizeof(ciphertext));
    sodium_memzero(opened, sizeof(opened));
    sodium_memzero(device_secret, sizeof(device_secret));
    return status;
}

evergram_status_t e2ee_encrypt(const uint8_t key[E2EE_KEY_BYTES], const char *plaintext,
                               char *nonce_b64, size_t nonce_b64_size, char *ciphertext_b64,
                               size_t ciphertext_b64_size) {
    if (key == NULL || plaintext == NULL || nonce_b64 == NULL || ciphertext_b64 == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (nonce_b64_size < E2EE_NONCE_B64_SIZE) {
        return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }

    size_t plaintext_len = strlen(plaintext);
    if (ciphertext_b64_size < E2EE_CIPHERTEXT_B64_SIZE(plaintext_len)) {
        return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }

    uint8_t nonce[E2EE_NONCE_BYTES];
    uint8_t *box = malloc(plaintext_len + E2EE_MAC_BYTES);
    if (box == NULL) {
        return EVERGRAM_ERR_NO_MEMORY;
    }

    randombytes_buf(nonce, sizeof(nonce));
    crypto_secretbox_easy(box, (const uint8_t *)plaintext, plaintext_len, nonce, key);

    evergram_status_t status =
        base64_encode(nonce, sizeof(nonce), nonce_b64, nonce_b64_size);
    if (status == EVERGRAM_OK) {
        status = base64_encode(box, plaintext_len + E2EE_MAC_BYTES, ciphertext_b64,
                               ciphertext_b64_size);
    }

    sodium_memzero(box, plaintext_len + E2EE_MAC_BYTES);
    free(box);
    return status;
}

evergram_status_t e2ee_decrypt(const uint8_t key[E2EE_KEY_BYTES], const char *nonce_b64,
                               const char *ciphertext_b64, char *plaintext, size_t plaintext_size,
                               size_t *plaintext_len) {
    if (key == NULL || nonce_b64 == NULL || ciphertext_b64 == NULL || plaintext == NULL ||
        plaintext_len == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    *plaintext_len = 0;

    uint8_t nonce[E2EE_NONCE_BYTES];
    evergram_status_t status = decode_exact(nonce_b64, nonce, sizeof(nonce), E2EE_NONCE_BYTES);
    if (status != EVERGRAM_OK) {
        return status;
    }

    size_t box_max = BASE64_DECODED_MAX(strlen(ciphertext_b64));
    if (box_max <= E2EE_MAC_BYTES) {
        return EVERGRAM_ERR_ENCODING;
    }

    uint8_t *box = malloc(box_max);
    if (box == NULL) {
        return EVERGRAM_ERR_NO_MEMORY;
    }

    size_t box_len = 0;
    status = base64_decode(ciphertext_b64, box, box_max, &box_len);
    if (status != EVERGRAM_OK) {
        goto cleanup;
    }
    if (box_len <= E2EE_MAC_BYTES) {
        status = EVERGRAM_ERR_ENCODING;
        goto cleanup;
    }

    size_t opened_len = box_len - E2EE_MAC_BYTES;
    if (plaintext_size < opened_len + 1u) {
        status = EVERGRAM_ERR_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    if (crypto_secretbox_open_easy((uint8_t *)plaintext, box, box_len, nonce, key) != 0) {
        /* Tampered tag or wrong key: never expose partial plaintext. */
        sodium_memzero(plaintext, plaintext_size);
        status = EVERGRAM_ERR_CRYPTO;
        goto cleanup;
    }

    plaintext[opened_len] = '\0';
    *plaintext_len = opened_len;

cleanup:
    sodium_memzero(box, box_max);
    free(box);
    return status;
}
