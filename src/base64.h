#ifndef EVERGRAM_BASE64_H
#define EVERGRAM_BASE64_H

#include <stddef.h>
#include <stdint.h>

#include "evergram/status.h"

/*
 * Standard base64 with padding, matching Buffer.toString("base64") and
 * Buffer.from(x, "base64") in the TypeScript SDK. Decoding also accepts
 * unpadded input.
 */

/* Output size required by base64_encode, terminator included. */
#define BASE64_ENCODED_SIZE(byte_count) (4u * (((byte_count) + 2u) / 3u) + 1u)

/* Upper bound for the decoded size of a base64 string. */
#define BASE64_DECODED_MAX(char_count) ((((char_count) + 3u) / 4u) * 3u)

evergram_status_t base64_encode(const uint8_t *data, size_t len, char *out, size_t out_size);

evergram_status_t base64_decode(const char *text, uint8_t *out, size_t out_size, size_t *out_len);

#endif /* EVERGRAM_BASE64_H */
