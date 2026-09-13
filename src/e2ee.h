#ifndef EVERGRAM_E2EE_H
#define EVERGRAM_E2EE_H

#include <stddef.h>
#include <stdint.h>

#include "evergram/status.h"
#include "evergram/types.h"

/*
 * End-to-end encryption, matching the tweetnacl usage of the TypeScript SDK.
 *
 *   chat key : random 32-byte secret; the gateway seals one copy per device
 *              with nacl.box (X25519 + XSalsa20-Poly1305), so only the device's
 *              own secret key can open it
 *   messages : nacl.secretbox with a fresh 24-byte nonce; both the nonce and
 *              the ciphertext travel base64 encoded
 *
 * The library never logs, stores, or transmits key material in the clear.
 */

#define E2EE_KEY_BYTES 32
_Static_assert(E2EE_KEY_BYTES == EVERGRAM_SYM_KEY_SIZE,
               "public and internal key sizes must agree");
#define E2EE_NONCE_BYTES 24
#define E2EE_MAC_BYTES 16

/* Output size required to hold the base64 of a secretbox ciphertext. */
#define E2EE_CIPHERTEXT_B64_SIZE(plaintext_bytes)                                                  \
    (4u * (((plaintext_bytes) + E2EE_MAC_BYTES + 2u) / 3u) + 1u)

/* Output size required to hold the base64 of a nonce. */
#define E2EE_NONCE_B64_SIZE (4u * ((E2EE_NONCE_BYTES + 2u) / 3u) + 1u)

/*
 * Opens one sealed copy of a chat key with the device's X25519 secret key.
 * All three inputs are base64, exactly as they arrive in SymKeyEncrypted.
 * Fails closed with EVERGRAM_ERR_CRYPTO on a bad tag or wrong device key.
 */
evergram_status_t e2ee_open_sealed_key(const char *ciphertext_b64, const char *nonce_b64,
                                       const char *ephemeral_pubkey_b64,
                                       const char *device_private_key_hex,
                                       uint8_t out_key[E2EE_KEY_BYTES]);

/* secretbox with a fresh random nonce. Both outputs are base64. */
evergram_status_t e2ee_encrypt(const uint8_t key[E2EE_KEY_BYTES], const char *plaintext,
                               char *nonce_b64, size_t nonce_b64_size, char *ciphertext_b64,
                               size_t ciphertext_b64_size);

/*
 * Decrypts a base64 nonce/ciphertext pair. Fails closed: malformed base64, a
 * wrong length, or a tampered tag all return WITHOUT writing a partial
 * plaintext. On success `*plaintext_len` excludes the terminator.
 */
evergram_status_t e2ee_decrypt(const uint8_t key[E2EE_KEY_BYTES], const char *nonce_b64,
                               const char *ciphertext_b64, char *plaintext, size_t plaintext_size,
                               size_t *plaintext_len);

#endif /* EVERGRAM_E2EE_H */
