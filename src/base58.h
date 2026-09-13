#ifndef EVERGRAM_BASE58_H
#define EVERGRAM_BASE58_H

#include <stddef.h>
#include <stdint.h>

#include "evergram/status.h"

/*
 * Base58 with the XRPL alphabet ("rpshnaf39w...").
 *
 * Inputs are bounded: encode accepts up to BASE58_DECODED_MAX bytes and decode
 * up to BASE58_ENCODED_MAX characters. Callers that need more must chunk the
 * data themselves. No allocation happens here.
 */

#define BASE58_ENCODED_MAX 192
#define BASE58_DECODED_MAX 128

/* Writes a NUL-terminated string. out_size must include the terminator. */
evergram_status_t base58_encode(const uint8_t *data, size_t len, char *out, size_t out_size);

/* Sets *out_len to the number of bytes written. Leading 'r' maps to 0x00. */
evergram_status_t base58_decode(const char *text, uint8_t *out, size_t out_size, size_t *out_len);

/* Appends the four-byte double-SHA256 checksum before encoding. */
evergram_status_t base58check_encode(const uint8_t *payload, size_t len, char *out,
                                     size_t out_size);

/* Verifies and strips the trailing checksum. */
evergram_status_t base58check_decode(const char *text, uint8_t *out, size_t out_size,
                                     size_t *out_len);

#endif /* EVERGRAM_BASE58_H */
