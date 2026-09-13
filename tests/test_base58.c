#include <string.h>

#include "base58.h"
#include "test.h"

#define KNOWN_ADDRESS "rMibrQV7rCNq5bMkaWx9wZkF9vt23fw2yB"

static void test_address_roundtrip(void) {
    uint8_t decoded[BASE58_DECODED_MAX];
    size_t len = 0;

    CHECK_EQ_INT(base58_decode(KNOWN_ADDRESS, decoded, sizeof(decoded), &len), EVERGRAM_OK);
    CHECK_EQ_INT(len, 25); /* version byte + 20-byte hash + 4-byte checksum */
    CHECK_EQ_INT(decoded[0], 0x00);

    char encoded[BASE58_ENCODED_MAX];
    CHECK_EQ_INT(base58_encode(decoded, len, encoded, sizeof(encoded)), EVERGRAM_OK);
    CHECK_EQ_STR(encoded, KNOWN_ADDRESS);
}

static void test_checksum_roundtrip(void) {
    uint8_t payload[21];
    for (size_t i = 0; i < sizeof(payload); i++) {
        payload[i] = (uint8_t)(i * 7u + 1u);
    }

    char encoded[BASE58_ENCODED_MAX];
    CHECK_EQ_INT(base58check_encode(payload, sizeof(payload), encoded, sizeof(encoded)),
                 EVERGRAM_OK);

    uint8_t decoded[BASE58_DECODED_MAX];
    size_t len = 0;
    CHECK_EQ_INT(base58check_decode(encoded, decoded, sizeof(decoded), &len), EVERGRAM_OK);
    CHECK_EQ_INT(len, sizeof(payload));
    CHECK_EQ_INT(memcmp(decoded, payload, sizeof(payload)), 0);
}

static void test_checksum_rejected(void) {
    uint8_t payload[21] = {0};
    char encoded[BASE58_ENCODED_MAX];
    CHECK_EQ_INT(base58check_encode(payload, sizeof(payload), encoded, sizeof(encoded)),
                 EVERGRAM_OK);

    size_t len = strlen(encoded);
    CHECK(len > 0);
    encoded[len - 1] = (encoded[len - 1] == 'r') ? 's' : 'r';

    uint8_t decoded[BASE58_DECODED_MAX];
    size_t decoded_len = 0;
    CHECK_EQ_INT(base58check_decode(encoded, decoded, sizeof(decoded), &decoded_len),
                 EVERGRAM_ERR_ENCODING);
}

static void test_invalid_characters(void) {
    uint8_t decoded[BASE58_DECODED_MAX];
    size_t len = 0;
    /* 0, O, I and l are deliberately absent from the XRPL alphabet. */
    CHECK_EQ_INT(base58_decode("0OIl", decoded, sizeof(decoded), &len), EVERGRAM_ERR_ENCODING);
}

static void test_leading_zero_bytes(void) {
    const uint8_t data[3] = {0x00, 0x00, 0x00};
    char encoded[BASE58_ENCODED_MAX];
    CHECK_EQ_INT(base58_encode(data, sizeof(data), encoded, sizeof(encoded)), EVERGRAM_OK);
    CHECK_EQ_STR(encoded, "rrr");
}

static void test_empty_input(void) {
    char encoded[BASE58_ENCODED_MAX];
    CHECK_EQ_INT(base58_encode(NULL, 0, encoded, sizeof(encoded)), EVERGRAM_OK);
    CHECK_EQ_STR(encoded, "");

    uint8_t decoded[BASE58_DECODED_MAX];
    size_t len = 123;
    CHECK_EQ_INT(base58_decode("", decoded, sizeof(decoded), &len), EVERGRAM_OK);
    CHECK_EQ_INT(len, 0);
}

static void test_buffer_too_small(void) {
    const uint8_t data[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    char small[4];
    CHECK_EQ_INT(base58_encode(data, sizeof(data), small, sizeof(small)),
                 EVERGRAM_ERR_BUFFER_TOO_SMALL);
}

static void test_oversized_input_rejected(void) {
    uint8_t big[BASE58_DECODED_MAX + 1] = {0};
    char encoded[BASE58_ENCODED_MAX * 2];
    CHECK_EQ_INT(base58_encode(big, sizeof(big), encoded, sizeof(encoded)),
                 EVERGRAM_ERR_INVALID_ARG);
}

static const test_case_t TESTS[] = {
    {"base58: address roundtrip", test_address_roundtrip},
    {"base58: checksum roundtrip", test_checksum_roundtrip},
    {"base58: checksum rejected when corrupted", test_checksum_rejected},
    {"base58: invalid characters rejected", test_invalid_characters},
    {"base58: leading zero bytes become 'r'", test_leading_zero_bytes},
    {"base58: empty input", test_empty_input},
    {"base58: small output buffer", test_buffer_too_small},
    {"base58: oversized input rejected", test_oversized_input_rejected},
};

const test_case_t *base58_tests(size_t *count) {
    *count = sizeof(TESTS) / sizeof(TESTS[0]);
    return TESTS;
}
