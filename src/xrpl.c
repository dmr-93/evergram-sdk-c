#include "xrpl.h"

#include <openssl/evp.h>
#include <sodium.h>
#include <stdbool.h>
#include <string.h>

#include "base58.h"

#define ED25519_KEY_PREFIX 0xED
#define RIPEMD160_BYTES 20
#define RIPPLE_SEED_PREFIX_LEN 3
#define RIPPLE_SEED_ENTROPY_LEN 16
#define RIPPLE_SEED_TEXT_LEN 64
#define ED_PREFIXED_KEY_TEXT_LEN 66
#define SECRET_KEY_TEXT_LEN 128

/* Base58Check version of an ed25519 family seed ("sEd..."). */
#define RIPPLE_SEED_VERSION_0 0x01
#define RIPPLE_SEED_VERSION_1 0xE1
#define RIPPLE_SEED_VERSION_2 0x4B

static bool ripemd160(const uint8_t *data, size_t len, uint8_t out[RIPEMD160_BYTES]) {
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (context == NULL) {
        return false;
    }

    unsigned int written = 0;
    bool ok = EVP_DigestInit_ex(context, EVP_ripemd160(), NULL) == 1 &&
              EVP_DigestUpdate(context, data, len) == 1 &&
              EVP_DigestFinal_ex(context, out, &written) == 1 && written == RIPEMD160_BYTES;

    EVP_MD_CTX_free(context);
    return ok;
}

static evergram_status_t hex_to_bytes(const char *hex, uint8_t *out, size_t out_size) {
    size_t written = 0;
    if (sodium_hex2bin(out, out_size, hex, strlen(hex), NULL, &written, NULL) != 0) {
        return EVERGRAM_ERR_ENCODING;
    }
    return written == out_size ? EVERGRAM_OK : EVERGRAM_ERR_ENCODING;
}

static bool has_ed_prefix(const char *hex) {
    return (hex[0] == 'E' || hex[0] == 'e') && (hex[1] == 'D' || hex[1] == 'd');
}

evergram_status_t xrpl_seed_from_text(const char *seed_text, uint8_t out[XRPL_SEED_BYTES]) {
    if (seed_text == NULL || out == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    if (strlen(seed_text) == RIPPLE_SEED_TEXT_LEN) {
        return hex_to_bytes(seed_text, out, XRPL_SEED_BYTES);
    }

    uint8_t decoded[BASE58_DECODED_MAX];
    size_t decoded_len = 0;
    evergram_status_t status = base58check_decode(seed_text, decoded, sizeof(decoded), &decoded_len);
    if (status != EVERGRAM_OK) {
        return status;
    }
    if (decoded_len != RIPPLE_SEED_PREFIX_LEN + RIPPLE_SEED_ENTROPY_LEN) {
        sodium_memzero(decoded, sizeof(decoded));
        return EVERGRAM_ERR_ENCODING;
    }
    if (decoded[0] != RIPPLE_SEED_VERSION_0 || decoded[1] != RIPPLE_SEED_VERSION_1 ||
        decoded[2] != RIPPLE_SEED_VERSION_2) {
        sodium_memzero(decoded, sizeof(decoded));
        return EVERGRAM_ERR_ENCODING;
    }

    uint8_t digest[crypto_hash_sha512_BYTES];
    crypto_hash_sha512(digest, decoded + RIPPLE_SEED_PREFIX_LEN, RIPPLE_SEED_ENTROPY_LEN);
    memcpy(out, digest, XRPL_SEED_BYTES);

    sodium_memzero(decoded, sizeof(decoded));
    sodium_memzero(digest, sizeof(digest));
    return EVERGRAM_OK;
}

evergram_status_t xrpl_public_key_from_seed(const uint8_t seed[XRPL_SEED_BYTES],
                                            uint8_t out[XRPL_PUBLIC_KEY_BYTES]) {
    if (seed == NULL || out == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    uint8_t secret[crypto_sign_SECRETKEYBYTES];
    out[0] = ED25519_KEY_PREFIX;
    bool ok = crypto_sign_seed_keypair(out + 1, secret, seed) == 0;
    sodium_memzero(secret, sizeof(secret));

    return ok ? EVERGRAM_OK : EVERGRAM_ERR_CRYPTO;
}

evergram_status_t xrpl_address_from_public_key(const uint8_t *public_key, size_t public_key_len,
                                               char *address, size_t address_size) {
    if (public_key == NULL || address == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (public_key_len != XRPL_PUBLIC_KEY_BYTES || public_key[0] != ED25519_KEY_PREFIX) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    uint8_t sha[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(sha, public_key, public_key_len);

    uint8_t ripe[RIPEMD160_BYTES];
    if (!ripemd160(sha, sizeof(sha), ripe)) {
        return EVERGRAM_ERR_CRYPTO;
    }

    uint8_t payload[1 + RIPEMD160_BYTES];
    payload[0] = XRPL_ACCOUNT_VERSION;
    memcpy(payload + 1, ripe, RIPEMD160_BYTES);

    return base58check_encode(payload, sizeof(payload), address, address_size);
}

static evergram_status_t sign_with_seed(const uint8_t seed[XRPL_SEED_BYTES], const uint8_t *message,
                                        size_t message_len, char *signature_hex,
                                        size_t signature_hex_size) {
    uint8_t public_key[crypto_sign_PUBLICKEYBYTES];
    uint8_t secret[crypto_sign_SECRETKEYBYTES];
    uint8_t signature[crypto_sign_BYTES];
    evergram_status_t status = EVERGRAM_OK;

    if (signature_hex_size < 2u * XRPL_SIGNATURE_BYTES + 1u) {
        return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }
    if (crypto_sign_seed_keypair(public_key, secret, seed) != 0) {
        status = EVERGRAM_ERR_CRYPTO;
        goto cleanup;
    }
    if (crypto_sign_detached(signature, NULL, message, message_len, secret) != 0) {
        status = EVERGRAM_ERR_CRYPTO;
        goto cleanup;
    }
    if (crypto_sign_verify_detached(signature, message, message_len, public_key) != 0) {
        status = EVERGRAM_ERR_CRYPTO;
        goto cleanup;
    }

    sodium_bin2hex(signature_hex, signature_hex_size, signature, sizeof(signature));

cleanup:
    sodium_memzero(secret, sizeof(secret));
    return status;
}

evergram_status_t xrpl_sign(const char *private_key_hex, const uint8_t *message,
                            size_t message_len, char *signature_hex,
                            size_t signature_hex_size) {
    if (private_key_hex == NULL || signature_hex == NULL || (message == NULL && message_len > 0)) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (signature_hex_size < 2u * XRPL_SIGNATURE_BYTES + 1u) {
        return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }

    size_t key_len = strlen(private_key_hex);
    if (key_len == ED_PREFIXED_KEY_TEXT_LEN || key_len == RIPPLE_SEED_TEXT_LEN) {
        const char *seed_hex = private_key_hex;
        if (key_len == ED_PREFIXED_KEY_TEXT_LEN) {
            if (!has_ed_prefix(private_key_hex)) {
                return EVERGRAM_ERR_ENCODING;
            }
            seed_hex = private_key_hex + 2;
        }

        uint8_t seed[XRPL_SEED_BYTES];
        evergram_status_t status = hex_to_bytes(seed_hex, seed, sizeof(seed));
        if (status == EVERGRAM_OK) {
            status = sign_with_seed(seed, message, message_len, signature_hex, signature_hex_size);
        }
        sodium_memzero(seed, sizeof(seed));
        return status;
    }

    if (key_len != SECRET_KEY_TEXT_LEN) {
        return EVERGRAM_ERR_ENCODING;
    }

    uint8_t secret[crypto_sign_SECRETKEYBYTES];
    uint8_t signature[crypto_sign_BYTES];
    evergram_status_t status = hex_to_bytes(private_key_hex, secret, sizeof(secret));
    if (status != EVERGRAM_OK) {
        goto cleanup;
    }
    if (crypto_sign_detached(signature, NULL, message, message_len, secret) != 0) {
        status = EVERGRAM_ERR_CRYPTO;
        goto cleanup;
    }
    /* libsodium stores the public key in the second half of the secret key. */
    if (crypto_sign_verify_detached(signature, message, message_len,
                                    secret + crypto_sign_SEEDBYTES) != 0) {
        status = EVERGRAM_ERR_CRYPTO;
        goto cleanup;
    }

    sodium_bin2hex(signature_hex, signature_hex_size, signature, sizeof(signature));

cleanup:
    sodium_memzero(secret, sizeof(secret));
    return status;
}
