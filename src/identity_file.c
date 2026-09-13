#include <fcntl.h>
#include <sodium.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "evergram.h"
#include "identity.h"
#include "log.h"
#include "xrpl.h"

/*
 * Identity file: "key=value" lines, one record per key. The same keys are read
 * and written, so files produced by evergram-c keep working.
 *
 * Secrets never leave this module: the line buffer is wiped before returning.
 */

#define IDENTITY_LINE_MAX 512
#define IDENTITY_PATH_MAX 512
#define IDENTITY_FILE_MODE 0600 /* owner read/write only */

typedef struct {
    const char *key;
    char *destination;
    size_t destination_size;
    bool *seen;
} identity_field_t;

/* Returns the value part of "key=value", or NULL when the line is unrelated. */
static const char *value_for(const char *line, const char *key) {
    size_t key_len = strlen(key);
    if (strncmp(line, key, key_len) != 0 || line[key_len] != '=') {
        return NULL;
    }
    return line + key_len + 1;
}

static evergram_status_t copy_value(char *destination, size_t destination_size,
                                    const char *value) {
    size_t len = strlen(value);
    if (len >= destination_size) {
        return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(destination, value, len + 1);
    return EVERGRAM_OK;
}

/* Rebuilds the canonical encodings when an older file omits them. */
static evergram_status_t fill_derived_fields(evergram_wallet_t *wallet, bool have_public_key,
                                             bool have_private_key) {
    uint8_t seed[XRPL_SEED_BYTES];
    evergram_status_t status = xrpl_seed_from_text(wallet->seed, seed);
    if (status != EVERGRAM_OK) {
        return status;
    }

    if (!have_public_key) {
        uint8_t public_key[XRPL_PUBLIC_KEY_BYTES];
        status = xrpl_public_key_from_seed(seed, public_key);
        if (status == EVERGRAM_OK) {
            sodium_bin2hex(wallet->public_key_hex, sizeof(wallet->public_key_hex), public_key,
                           sizeof(public_key));
        }
        sodium_memzero(public_key, sizeof(public_key));
    }

    if (status == EVERGRAM_OK && !have_private_key) {
        int written = snprintf(wallet->private_key_hex, sizeof(wallet->private_key_hex), "ED%s",
                               wallet->seed);
        if (written < 0 || (size_t)written >= sizeof(wallet->private_key_hex)) {
            status = EVERGRAM_ERR_BUFFER_TOO_SMALL;
        }
    }

    sodium_memzero(seed, sizeof(seed));
    return status;
}

evergram_status_t evergram_identity_load(const char *path, evergram_wallet_t *wallet,
                                         evergram_device_t *device) {
    if (path == NULL || wallet == NULL || device == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    memset(wallet, 0, sizeof(*wallet));
    memset(device, 0, sizeof(*device));

    FILE *file = fopen(path, "r");
    if (file == NULL) {
        return EVERGRAM_ERR_IO;
    }

    bool have_seed = false;
    bool have_address = false;
    bool have_public_key = false;
    bool have_private_key = false;
    bool have_device_public = false;
    bool have_device_private = false;
    bool have_device_id = false;

    identity_field_t fields[] = {
        {"seed", wallet->seed, sizeof(wallet->seed), &have_seed},
        {"address", wallet->address, sizeof(wallet->address), &have_address},
        {"pubkey", wallet->public_key_hex, sizeof(wallet->public_key_hex), &have_public_key},
        {"privkey", wallet->private_key_hex, sizeof(wallet->private_key_hex), &have_private_key},
        {"device_pub", device->public_key_hex, sizeof(device->public_key_hex),
         &have_device_public},
        {"device_priv", device->private_key_hex, sizeof(device->private_key_hex),
         &have_device_private},
        {"device_id", device->device_id, sizeof(device->device_id), &have_device_id},
    };
    const size_t field_count = sizeof(fields) / sizeof(fields[0]);

    char line[IDENTITY_LINE_MAX];
    evergram_status_t status = EVERGRAM_OK;

    while (status == EVERGRAM_OK && fgets(line, sizeof(line), file) != NULL) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }

        for (size_t i = 0; i < field_count; i++) {
            const char *value = value_for(line, fields[i].key);
            if (value == NULL) {
                continue;
            }
            status = copy_value(fields[i].destination, fields[i].destination_size, value);
            if (status == EVERGRAM_OK) {
                *fields[i].seen = true;
            }
            break;
        }
    }

    if (ferror(file) != 0 && status == EVERGRAM_OK) {
        status = EVERGRAM_ERR_IO;
    }
    fclose(file);
    sodium_memzero(line, sizeof(line));

    if (status != EVERGRAM_OK) {
        goto fail;
    }
    if (!have_seed || !have_address || !have_device_id || !have_device_public) {
        EG_ERROR("identity %s is missing required fields", path);
        status = EVERGRAM_ERR_IO;
        goto fail;
    }

    status = fill_derived_fields(wallet, have_public_key, have_private_key);
    if (status != EVERGRAM_OK) {
        goto fail;
    }

    EG_DEBUG("loaded identity %s (address %s)", path, wallet->address);
    (void)have_device_private;
    return EVERGRAM_OK;

fail:
    evergram_wallet_wipe(wallet);
    evergram_device_wipe(device);
    return status;
}

evergram_status_t evergram_identity_save(const char *path, const evergram_wallet_t *wallet,
                                         const evergram_device_t *device) {
    if (path == NULL || wallet == NULL || device == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    char temporary[IDENTITY_PATH_MAX];
    int written = snprintf(temporary, sizeof(temporary), "%s.tmp", path);
    if (written < 0 || (size_t)written >= sizeof(temporary)) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    /* 0600 from creation: no window where secrets are world readable. */
    int descriptor = open(temporary, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                          IDENTITY_FILE_MODE);
    if (descriptor < 0) {
        return EVERGRAM_ERR_IO;
    }

    FILE *file = fdopen(descriptor, "w");
    if (file == NULL) {
        close(descriptor);
        unlink(temporary);
        return EVERGRAM_ERR_IO;
    }

    int result = fprintf(file,
                         "seed=%s\n"
                         "address=%s\n"
                         "pubkey=%s\n"
                         "privkey=%s\n"
                         "device_pub=%s\n"
                         "device_priv=%s\n"
                         "device_id=%s\n",
                         wallet->seed, wallet->address, wallet->public_key_hex,
                         wallet->private_key_hex, device->public_key_hex,
                         device->private_key_hex, device->device_id);

    bool ok = result > 0 && fflush(file) == 0;
    if (fclose(file) != 0) {
        ok = false;
    }
    if (ok && rename(temporary, path) != 0) {
        ok = false;
    }
    if (!ok) {
        unlink(temporary);
        return EVERGRAM_ERR_IO;
    }

    EG_DEBUG("saved identity %s", path);
    return EVERGRAM_OK;
}
