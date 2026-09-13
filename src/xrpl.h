#ifndef EVERGRAM_XRPL_H
#define EVERGRAM_XRPL_H

#include <stddef.h>
#include <stdint.h>

#include "evergram/status.h"

/*
 * XRPL (ed25519) key handling, byte-compatible with ripple-keypairs.
 *
 *   public key  = 0xED || 32-byte ed25519 key      (66 hex chars)
 *   private key = 0xED || 32-byte ed25519 seed     (66 hex chars)
 *   address     = base58check(0x00 || RIPEMD160(SHA256(0xED || public key)))
 *
 * The 0xED prefix selects ed25519 for the gateway; a bare 32-byte key is read
 * as secp256k1 and rejected, which is why it is required here too.
 */

#define XRPL_SEED_BYTES 32
#define XRPL_PUBLIC_KEY_BYTES 33
#define XRPL_SIGNATURE_BYTES 64

/* Address version byte: XRPL addresses (r...) are version 0. */
#define XRPL_ACCOUNT_VERSION 0x00

/* Accepts 64 hex chars (raw seed, used as-is) or a base58 "sEd..." seed whose
 * 16-byte entropy is expanded with SHA-512, exactly like ripple-keypairs. */
evergram_status_t xrpl_seed_from_text(const char *seed_text, uint8_t out[XRPL_SEED_BYTES]);

evergram_status_t xrpl_public_key_from_seed(const uint8_t seed[XRPL_SEED_BYTES],
                                            uint8_t out[XRPL_PUBLIC_KEY_BYTES]);

/* Rejects keys without the 0xED prefix so an address can never be derived from
 * a differently-hashed representation of the same key. */
evergram_status_t xrpl_address_from_public_key(const uint8_t *public_key, size_t public_key_len,
                                               char *address, size_t address_size);

/* private_key_hex accepts 66 chars ("ED" + seed), 64 chars (raw seed) or 128
 * chars (libsodium secret key). Produces 128 lowercase hex chars plus NUL. */
evergram_status_t xrpl_sign(const char *private_key_hex, const uint8_t *message,
                            size_t message_len, char *signature_hex, size_t signature_hex_size);

#endif /* EVERGRAM_XRPL_H */
