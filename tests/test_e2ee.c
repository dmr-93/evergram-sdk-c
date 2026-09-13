#include <sodium.h>
#include <stdio.h>
#include <string.h>

#include "base64.h"
#include "e2ee.h"
#include "e2ee_vectors.h"
#include "test.h"

/* The vectors come from tweetnacl, so passing these tests means byte
 * compatibility with the TypeScript SDK's E2EE, not merely self-consistency. */

static void key_from_hex(const char *hex, uint8_t key[E2EE_KEY_BYTES]) {
    CHECK_EQ_INT(sodium_hex2bin(key, E2EE_KEY_BYTES, hex, 2u * E2EE_KEY_BYTES, NULL, NULL, NULL),
                 0);
}

static void test_base64_matches_known_vector(void) {
    const uint8_t data[] = {'h', 'e', 'l', 'l', 'o'};
    char encoded[16];

    CHECK_EQ_INT(base64_encode(data, sizeof(data), encoded, sizeof(encoded)), EVERGRAM_OK);
    CHECK_EQ_STR(encoded, "aGVsbG8=");
}

static void test_base64_roundtrip(void) {
    const uint8_t data[] = {0x00, 0x01, 0x02, 0xFD, 0xFE, 0xFF};
    char encoded[BASE64_ENCODED_SIZE(sizeof(data))];
    uint8_t decoded[16];
    size_t len = 0;

    CHECK_EQ_INT(base64_encode(data, sizeof(data), encoded, sizeof(encoded)), EVERGRAM_OK);
    CHECK_EQ_INT(base64_decode(encoded, decoded, sizeof(decoded), &len), EVERGRAM_OK);
    CHECK_EQ_INT(len, sizeof(data));
    CHECK_EQ_INT(memcmp(decoded, data, sizeof(data)), 0);
}

static void test_base64_accepts_unpadded(void) {
    uint8_t decoded[16];
    size_t len = 0;

    CHECK_EQ_INT(base64_decode("aGVsbG8", decoded, sizeof(decoded), &len), EVERGRAM_OK);
    CHECK_EQ_INT(len, 5);
    CHECK_EQ_INT(memcmp(decoded, "hello", 5), 0);
}

static void test_base64_rejects_invalid_and_small(void) {
    uint8_t decoded[16];
    size_t len = 0;

    CHECK_EQ_INT(base64_decode("!!!!", decoded, sizeof(decoded), &len), EVERGRAM_ERR_ENCODING);
    CHECK_EQ_INT(base64_decode("aGVsbG8=", decoded, 2, &len), EVERGRAM_ERR_ENCODING);

    char small[2];
    const uint8_t data[] = {1, 2, 3};
    CHECK_EQ_INT(base64_encode(data, sizeof(data), small, sizeof(small)),
                 EVERGRAM_ERR_BUFFER_TOO_SMALL);
}

static void test_decrypt_matches_tweetnacl(void) {
    uint8_t key[E2EE_KEY_BYTES];
    char plaintext[128];
    size_t len = 0;

    key_from_hex(VECTOR_SYM_KEY_HEX, key);
    CHECK_EQ_INT(e2ee_decrypt(key, VECTOR_MESSAGE_NONCE_B64, VECTOR_MESSAGE_CIPHERTEXT_B64,
                              plaintext, sizeof(plaintext), &len),
                 EVERGRAM_OK);
    CHECK_EQ_STR(plaintext, VECTOR_MESSAGE_PLAINTEXT);
    CHECK_EQ_INT(len, VECTOR_MESSAGE_PLAINTEXT_BYTES);
}

static void test_decrypt_fails_closed_on_tamper(void) {
    uint8_t key[E2EE_KEY_BYTES];
    char plaintext[128];
    size_t len = 0;
    char tampered[128];

    key_from_hex(VECTOR_SYM_KEY_HEX, key);

    snprintf(tampered, sizeof(tampered), "%s", VECTOR_MESSAGE_CIPHERTEXT_B64);
    tampered[0] = (tampered[0] == 'A') ? 'B' : 'A';

    memset(plaintext, 'X', sizeof(plaintext));
    CHECK_EQ_INT(e2ee_decrypt(key, VECTOR_MESSAGE_NONCE_B64, tampered, plaintext,
                              sizeof(plaintext), &len),
                 EVERGRAM_ERR_CRYPTO);
    CHECK_EQ_INT(plaintext[0], '\0'); /* never expose partial plaintext */
    CHECK_EQ_INT(len, 0);

    uint8_t wrong_key[E2EE_KEY_BYTES];
    memset(wrong_key, 0xAB, sizeof(wrong_key));
    CHECK_EQ_INT(e2ee_decrypt(wrong_key, VECTOR_MESSAGE_NONCE_B64,
                              VECTOR_MESSAGE_CIPHERTEXT_B64, plaintext, sizeof(plaintext), &len),
                 EVERGRAM_ERR_CRYPTO);
}

static void test_decrypt_rejects_malformed(void) {
    uint8_t key[E2EE_KEY_BYTES];
    char plaintext[128];
    size_t len = 0;

    key_from_hex(VECTOR_SYM_KEY_HEX, key);

    CHECK_EQ_INT(e2ee_decrypt(key, "AAAA", VECTOR_MESSAGE_CIPHERTEXT_B64, plaintext,
                              sizeof(plaintext), &len),
                 EVERGRAM_ERR_ENCODING);
    CHECK_EQ_INT(e2ee_decrypt(key, VECTOR_MESSAGE_NONCE_B64, "!!!", plaintext,
                              sizeof(plaintext), &len),
                 EVERGRAM_ERR_ENCODING);
    CHECK_EQ_INT(e2ee_decrypt(key, VECTOR_MESSAGE_NONCE_B64, VECTOR_MESSAGE_CIPHERTEXT_B64,
                              plaintext, 4, &len),
                 EVERGRAM_ERR_BUFFER_TOO_SMALL);
}

static void test_encrypt_roundtrip(void) {
    uint8_t key[E2EE_KEY_BYTES];
    const char *message = "mensagem com acentos: olá, ção";
    char nonce_b64[E2EE_NONCE_B64_SIZE];
    char ciphertext_b64[E2EE_CIPHERTEXT_B64_SIZE(128)];
    char plaintext[128];
    size_t len = 0;

    key_from_hex(VECTOR_SYM_KEY_HEX, key);

    CHECK_EQ_INT(e2ee_encrypt(key, message, nonce_b64, sizeof(nonce_b64), ciphertext_b64,
                              sizeof(ciphertext_b64)),
                 EVERGRAM_OK);
    CHECK_EQ_INT(e2ee_decrypt(key, nonce_b64, ciphertext_b64, plaintext, sizeof(plaintext), &len),
                 EVERGRAM_OK);
    CHECK_EQ_STR(plaintext, message);
    CHECK_EQ_INT(len, strlen(message));
}

static void test_encrypt_requires_room(void) {
    uint8_t key[E2EE_KEY_BYTES];
    char nonce_b64[E2EE_NONCE_B64_SIZE];
    char ciphertext_b64[E2EE_CIPHERTEXT_B64_SIZE(128)];
    char tiny_nonce[4];
    char tiny_ciphertext[8];

    key_from_hex(VECTOR_SYM_KEY_HEX, key);

    CHECK_EQ_INT(e2ee_encrypt(key, "x", tiny_nonce, sizeof(tiny_nonce), ciphertext_b64,
                              sizeof(ciphertext_b64)),
                 EVERGRAM_ERR_BUFFER_TOO_SMALL);
    CHECK_EQ_INT(e2ee_encrypt(key, "xxxxxxxxxxxxxxxxxxxx", nonce_b64, sizeof(nonce_b64),
                              tiny_ciphertext, sizeof(tiny_ciphertext)),
                 EVERGRAM_ERR_BUFFER_TOO_SMALL);
}

static void test_open_sealed_key_matches_tweetnacl(void) {
    uint8_t key[E2EE_KEY_BYTES];
    char hex[2u * E2EE_KEY_BYTES + 1u];

    CHECK_EQ_INT(e2ee_open_sealed_key(VECTOR_SEALED_CIPHERTEXT_B64, VECTOR_SEALED_NONCE_B64,
                                      VECTOR_EPHEMERAL_PUBLIC_KEY_B64,
                                      VECTOR_DEVICE_PRIVATE_KEY_HEX, key),
                 EVERGRAM_OK);

    sodium_bin2hex(hex, sizeof(hex), key, sizeof(key));
    CHECK_EQ_STR(hex, VECTOR_SYM_KEY_HEX);
}

static void test_open_sealed_key_requires_own_device(void) {
    uint8_t key[E2EE_KEY_BYTES];
    const char *other_device = "0000000000000000000000000000000000000000000000000000000000000001";

    CHECK_EQ_INT(e2ee_open_sealed_key(VECTOR_SEALED_CIPHERTEXT_B64, VECTOR_SEALED_NONCE_B64,
                                      VECTOR_EPHEMERAL_PUBLIC_KEY_B64, other_device, key),
                 EVERGRAM_ERR_CRYPTO);
}

static void test_open_sealed_key_rejects_malformed(void) {
    uint8_t key[E2EE_KEY_BYTES];

    CHECK_EQ_INT(e2ee_open_sealed_key("not base64!", VECTOR_SEALED_NONCE_B64,
                                      VECTOR_EPHEMERAL_PUBLIC_KEY_B64,
                                      VECTOR_DEVICE_PRIVATE_KEY_HEX, key),
                 EVERGRAM_ERR_ENCODING);
    CHECK_EQ_INT(e2ee_open_sealed_key(VECTOR_SEALED_CIPHERTEXT_B64, "AAAA",
                                      VECTOR_EPHEMERAL_PUBLIC_KEY_B64,
                                      VECTOR_DEVICE_PRIVATE_KEY_HEX, key),
                 EVERGRAM_ERR_ENCODING);
    CHECK_EQ_INT(e2ee_open_sealed_key(VECTOR_SEALED_CIPHERTEXT_B64, VECTOR_SEALED_NONCE_B64,
                                      VECTOR_EPHEMERAL_PUBLIC_KEY_B64, "abc", key),
                 EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(e2ee_open_sealed_key(NULL, VECTOR_SEALED_NONCE_B64,
                                      VECTOR_EPHEMERAL_PUBLIC_KEY_B64,
                                      VECTOR_DEVICE_PRIVATE_KEY_HEX, key),
                 EVERGRAM_ERR_INVALID_ARG);
}

static const test_case_t TESTS[] = {
    {"e2ee: base64 matches known vector", test_base64_matches_known_vector},
    {"e2ee: base64 roundtrip", test_base64_roundtrip},
    {"e2ee: base64 accepts unpadded input", test_base64_accepts_unpadded},
    {"e2ee: base64 rejects invalid and small buffers", test_base64_rejects_invalid_and_small},
    {"e2ee: decrypt matches tweetnacl vector", test_decrypt_matches_tweetnacl},
    {"e2ee: decrypt fails closed on tamper", test_decrypt_fails_closed_on_tamper},
    {"e2ee: decrypt rejects malformed input", test_decrypt_rejects_malformed},
    {"e2ee: encrypt/decrypt roundtrip", test_encrypt_roundtrip},
    {"e2ee: encrypt requires room", test_encrypt_requires_room},
    {"e2ee: sealed key matches tweetnacl vector", test_open_sealed_key_matches_tweetnacl},
    {"e2ee: sealed key requires the owning device", test_open_sealed_key_requires_own_device},
    {"e2ee: sealed key rejects malformed input", test_open_sealed_key_rejects_malformed},
};

const test_case_t *e2ee_tests(size_t *count) {
    *count = sizeof(TESTS) / sizeof(TESTS[0]);
    return TESTS;
}
