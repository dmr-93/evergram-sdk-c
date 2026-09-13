#include "base58.h"

#include <sodium.h>
#include <string.h>

#define BASE58_CHECKSUM_SIZE 4u

static const char BASE58_ALPHABET[] = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

static int alphabet_index(char character) {
    const char *found = strchr(BASE58_ALPHABET, character);
    if (found == NULL || character == '\0') {
        return -1;
    }
    return (int)(found - BASE58_ALPHABET);
}

static void checksum(const uint8_t *payload, size_t len, uint8_t out[BASE58_CHECKSUM_SIZE]) {
    uint8_t first[crypto_hash_sha256_BYTES];
    uint8_t second[crypto_hash_sha256_BYTES];

    crypto_hash_sha256(first, payload, len);
    crypto_hash_sha256(second, first, sizeof(first));
    memcpy(out, second, BASE58_CHECKSUM_SIZE);
}

evergram_status_t base58_encode(const uint8_t *data, size_t len, char *out, size_t out_size) {
    if (out == NULL || (data == NULL && len > 0)) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (len > BASE58_DECODED_MAX) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (len == 0) {
        if (out_size < 1) {
            return EVERGRAM_ERR_BUFFER_TOO_SMALL;
        }
        out[0] = '\0';
        return EVERGRAM_OK;
    }

    size_t zeros = 0;
    while (zeros < len && data[zeros] == 0) {
        zeros++;
    }

    uint8_t digits[BASE58_ENCODED_MAX];
    memset(digits, 0, sizeof(digits));
    size_t digits_len = 0;

    for (size_t i = zeros; i < len; i++) {
        unsigned int carry = data[i];
        for (size_t j = 0; j < digits_len; j++) {
            carry += (unsigned int)digits[j] << 8;
            digits[j] = (uint8_t)(carry % 58u);
            carry /= 58u;
        }
        while (carry > 0) {
            if (digits_len >= sizeof(digits)) {
                return EVERGRAM_ERR_INVALID_ARG;
            }
            digits[digits_len] = (uint8_t)(carry % 58u);
            digits_len++;
            carry /= 58u;
        }
    }

    size_t total = zeros + digits_len;
    if (total + 1 > out_size) {
        return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }

    size_t position = 0;
    for (size_t i = 0; i < zeros; i++) {
        out[position] = BASE58_ALPHABET[0];
        position++;
    }
    for (size_t i = 0; i < digits_len; i++) {
        out[position] = BASE58_ALPHABET[digits[digits_len - 1 - i]];
        position++;
    }
    out[position] = '\0';
    return EVERGRAM_OK;
}

evergram_status_t base58_decode(const char *text, uint8_t *out, size_t out_size, size_t *out_len) {
    if (text == NULL || out == NULL || out_len == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    *out_len = 0;

    size_t text_len = strnlen(text, BASE58_ENCODED_MAX + 1u);
    if (text_len > BASE58_ENCODED_MAX) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (text_len == 0) {
        return EVERGRAM_OK;
    }

    size_t zeros = 0;
    while (zeros < text_len && text[zeros] == BASE58_ALPHABET[0]) {
        zeros++;
    }

    uint8_t bytes[BASE58_DECODED_MAX];
    memset(bytes, 0, sizeof(bytes));
    size_t bytes_len = 0;

    for (size_t i = zeros; i < text_len; i++) {
        int value = alphabet_index(text[i]);
        if (value < 0) {
            return EVERGRAM_ERR_ENCODING;
        }

        unsigned int carry = (unsigned int)value;
        for (size_t j = 0; j < bytes_len; j++) {
            carry += (unsigned int)bytes[j] * 58u;
            bytes[j] = (uint8_t)(carry & 0xFFu);
            carry >>= 8;
        }
        while (carry > 0) {
            if (bytes_len >= sizeof(bytes)) {
                return EVERGRAM_ERR_INVALID_ARG;
            }
            bytes[bytes_len] = (uint8_t)(carry & 0xFFu);
            bytes_len++;
            carry >>= 8;
        }
    }

    size_t total = zeros + bytes_len;
    if (total > out_size) {
        return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }

    memset(out, 0, zeros);
    for (size_t i = 0; i < bytes_len; i++) {
        out[zeros + i] = bytes[bytes_len - 1 - i];
    }
    *out_len = total;
    return EVERGRAM_OK;
}

evergram_status_t base58check_encode(const uint8_t *payload, size_t len, char *out,
                                     size_t out_size) {
    if (payload == NULL || out == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (len > BASE58_DECODED_MAX - BASE58_CHECKSUM_SIZE) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    uint8_t buffer[BASE58_DECODED_MAX];
    memcpy(buffer, payload, len);
    checksum(payload, len, buffer + len);

    return base58_encode(buffer, len + BASE58_CHECKSUM_SIZE, out, out_size);
}

evergram_status_t base58check_decode(const char *text, uint8_t *out, size_t out_size,
                                     size_t *out_len) {
    if (out_len == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    *out_len = 0;

    uint8_t buffer[BASE58_DECODED_MAX];
    size_t buffer_len = 0;
    evergram_status_t status = base58_decode(text, buffer, sizeof(buffer), &buffer_len);
    if (status != EVERGRAM_OK) {
        return status;
    }
    if (buffer_len <= BASE58_CHECKSUM_SIZE) {
        return EVERGRAM_ERR_ENCODING;
    }

    size_t payload_len = buffer_len - BASE58_CHECKSUM_SIZE;
    uint8_t expected[BASE58_CHECKSUM_SIZE];
    checksum(buffer, payload_len, expected);
    if (sodium_memcmp(expected, buffer + payload_len, BASE58_CHECKSUM_SIZE) != 0) {
        return EVERGRAM_ERR_ENCODING;
    }
    if (payload_len > out_size) {
        return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }

    memcpy(out, buffer, payload_len);
    *out_len = payload_len;
    return EVERGRAM_OK;
}
