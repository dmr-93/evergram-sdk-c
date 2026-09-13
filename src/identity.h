#ifndef EVERGRAM_IDENTITY_H
#define EVERGRAM_IDENTITY_H

#include <stddef.h>
#include <stdint.h>

#include "evergram.h"
#include "xrpl.h"

/*
 * Identity helpers. Implemented in identity.c; declared in the public header.
 * This header exists so internal modules can share the derivation helpers.
 */

/* Fills the wallet fields from a raw ed25519 seed. Public key and address are
 * derived; the seed is stored as 64 hex chars. */
evergram_status_t identity_wallet_from_seed(const uint8_t seed[XRPL_SEED_BYTES],
                                            evergram_wallet_t *out);

/* Derives device_id = SHA256(public_key)[:16] as 32 hex chars. */
evergram_status_t identity_device_id_from_public_key(const uint8_t *public_key,
                                                     size_t public_key_len, char *device_id,
                                                     size_t device_id_size);

#endif /* EVERGRAM_IDENTITY_H */
