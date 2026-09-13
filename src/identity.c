#include "identity.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>

#include "log.h"
#include "xrpl.h"

#define DEVICE_ID_HEX_CHARS 32

evergram_status_t identity_device_id_from_public_key(const uint8_t *public_key,
                                                     size_t public_key_len, char *device_id,
                                                     size_t device_id_size) {
    if (public_key == NULL || device_id == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (device_id_size < DEVICE_ID_HEX_CHARS + 1u) {
        return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }

    uint8_t hash[crypto_hash_sha256_BYTES];
    char hash_hex[2u * crypto_hash_sha256_BYTES + 1u];

    crypto_hash_sha256(hash, public_key, public_key_len);
    sodium_bin2hex(hash_hex, sizeof(hash_hex), hash, sizeof(hash));
    memcpy(device_id, hash_hex, DEVICE_ID_HEX_CHARS);
    device_id[DEVICE_ID_HEX_CHARS] = '\0';

    sodium_memzero(hash, sizeof(hash));
    sodium_memzero(hash_hex, sizeof(hash_hex));
    return EVERGRAM_OK;
}

evergram_status_t identity_wallet_from_seed(const uint8_t seed[XRPL_SEED_BYTES],
                                            evergram_wallet_t *out) {
    if (seed == NULL || out == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    uint8_t public_key[XRPL_PUBLIC_KEY_BYTES];
    char seed_hex[2u * XRPL_SEED_BYTES + 1u];
    evergram_status_t status;

    status = xrpl_public_key_from_seed(seed, public_key);
    if (status != EVERGRAM_OK) {
        return status;
    }

    status = xrpl_address_from_public_key(public_key, sizeof(public_key), out->address,
                                          sizeof(out->address));
    if (status != EVERGRAM_OK) {
        sodium_memzero(public_key, sizeof(public_key));
        return status;
    }

    sodium_bin2hex(out->seed, sizeof(out->seed), seed, XRPL_SEED_BYTES);
    sodium_bin2hex(seed_hex, sizeof(seed_hex), seed, XRPL_SEED_BYTES);
    /* The 0xED prefix is what makes the gateway read this as an ed25519 key. */
    sodium_bin2hex(out->public_key_hex, sizeof(out->public_key_hex), public_key,
                   sizeof(public_key));

    int written = snprintf(out->private_key_hex, sizeof(out->private_key_hex), "ED%s", seed_hex);
    sodium_memzero(seed_hex, sizeof(seed_hex));
    sodium_memzero(public_key, sizeof(public_key));
    if (written < 0 || (size_t)written >= sizeof(out->private_key_hex)) {
        return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }

    return EVERGRAM_OK;
}

evergram_status_t evergram_wallet_generate(evergram_wallet_t *out) {
    if (out == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (sodium_init() < 0) {
        return EVERGRAM_ERR_CRYPTO;
    }

    memset(out, 0, sizeof(*out));

    uint8_t seed[XRPL_SEED_BYTES];
    randombytes_buf(seed, sizeof(seed));

    evergram_status_t status = identity_wallet_from_seed(seed, out);
    sodium_memzero(seed, sizeof(seed));

    if (status != EVERGRAM_OK) {
        evergram_wallet_wipe(out);
    } else {
        EG_DEBUG("generated wallet %s", out->address);
    }
    return status;
}

evergram_status_t evergram_device_generate(evergram_device_t *out) {
    if (out == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (sodium_init() < 0) {
        return EVERGRAM_ERR_CRYPTO;
    }

    memset(out, 0, sizeof(*out));

    uint8_t public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t secret_key[crypto_box_SECRETKEYBYTES];

    if (crypto_box_keypair(public_key, secret_key) != 0) {
        return EVERGRAM_ERR_CRYPTO;
    }

    sodium_bin2hex(out->public_key_hex, sizeof(out->public_key_hex), public_key,
                   sizeof(public_key));
    sodium_bin2hex(out->private_key_hex, sizeof(out->private_key_hex), secret_key,
                   sizeof(secret_key));

    evergram_status_t status =
        identity_device_id_from_public_key(public_key, sizeof(public_key), out->device_id,
                                           sizeof(out->device_id));

    sodium_memzero(secret_key, sizeof(secret_key));
    sodium_memzero(public_key, sizeof(public_key));

    if (status != EVERGRAM_OK) {
        evergram_device_wipe(out);
    } else {
        EG_DEBUG("generated device %s", out->device_id);
    }
    return status;
}

void evergram_wallet_wipe(evergram_wallet_t *wallet) {
    if (wallet != NULL) {
        sodium_memzero(wallet, sizeof(*wallet));
    }
}

void evergram_device_wipe(evergram_device_t *device) {
    if (device != NULL) {
        sodium_memzero(device, sizeof(*device));
    }
}

evergram_status_t evergram_wallet_from_regular_key(const char *account_address,
                                                   const char *regular_key_seed,
                                                   evergram_wallet_t *out) {
    if (account_address == NULL || regular_key_seed == NULL || out == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (account_address[0] == '\0' || strlen(account_address) >= sizeof(out->address)) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (strlen(regular_key_seed) >= sizeof(out->seed)) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (sodium_init() < 0) {
        return EVERGRAM_ERR_CRYPTO;
    }

    memset(out, 0, sizeof(*out));

    uint8_t seed[XRPL_SEED_BYTES];
    uint8_t public_key[XRPL_PUBLIC_KEY_BYTES];
    evergram_status_t status = xrpl_seed_from_text(regular_key_seed, seed);
    if (status != EVERGRAM_OK) {
        return status;
    }

    status = xrpl_public_key_from_seed(seed, public_key);
    if (status == EVERGRAM_OK) {
        sodium_bin2hex(out->public_key_hex, sizeof(out->public_key_hex), public_key,
                       sizeof(public_key));
        sodium_bin2hex(out->private_key_hex + 2, sizeof(out->private_key_hex) - 2u, seed,
                       sizeof(seed));
        out->private_key_hex[0] = 'E';
        out->private_key_hex[1] = 'D';
        /* The address is the account being authenticated as, deliberately NOT
         * derived from this key: that is what a RegularKey authorises. */
        snprintf(out->address, sizeof(out->address), "%s", account_address);
        snprintf(out->seed, sizeof(out->seed), "%s", regular_key_seed);
    }

    sodium_memzero(seed, sizeof(seed));
    sodium_memzero(public_key, sizeof(public_key));
    if (status != EVERGRAM_OK) {
        evergram_wallet_wipe(out);
    }
    return status;
}
