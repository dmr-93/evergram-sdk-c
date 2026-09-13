#include <sodium.h>
#include <string.h>

#include "evergram.h"
#include "test.h"
#include "xrpl.h"

/* Vectors captured from a live session against the staging gateway. */
#define SEED_HEX "db7fc7a261e8082cc0f3fdb3b3f15f95bb727ba9b533246eb4d46ec70604ea96"
#define PRIVATE_KEY_HEX "ED" SEED_HEX
#define PUBLIC_KEY_HEX "edb9f94de51cf7d0c15b4f4675444d5e2b3d1a02f8b923b1680485c4bd70a69e56"
#define ADDRESS "rMibrQV7rCNq5bMkaWx9wZkF9vt23fw2yB"
#define CHALLENGE                                                                                  \
    "evergram-auth:rMibrQV7rCNq5bMkaWx9wZkF9vt23fw2yB:389a5006d4ad24cd5f35cbcd2cf7fb70:"          \
    "b41bb8079d1e57b48490999a13a3aa33"
#define SIGNATURE_HEX                                                                              \
    "4d1912d4fad495264f294e20908ae2b3300132b8e98d17b87c776375a8283220"                             \
    "7fe03e395a78e0d03aedfae436de796be9ce55d5e412c67f3c34cead9ab5af0a"

/* ripple-keypairs vector for 16-byte entropy 000102030405060708090a0b0c0d0e0f. */
#define SED_SEED "sEdSJHdnVumf99WfaHTnU8DaQkx5Q4n"
#define SED_ED25519_SEED_HEX "daa295beed4e2ee94c24015b56af626b4f21ef9f44f2b3d40fc41c90900a6bf1"
#define SED_PUBLIC_KEY_HEX "ed951bf8b3b7c8aa4bc1b91790fc1b3ff7155cd729c2e6f038a93f5f3b9035dd85"

static void bytes_to_hex(const uint8_t *data, size_t len, char *out) {
    sodium_bin2hex(out, len * 2u + 1u, data, len);
}

static void test_seed_from_hex(void) {
    uint8_t seed[XRPL_SEED_BYTES];
    char hex[2u * XRPL_SEED_BYTES + 1u];

    CHECK_EQ_INT(xrpl_seed_from_text(SEED_HEX, seed), EVERGRAM_OK);
    bytes_to_hex(seed, sizeof(seed), hex);
    CHECK_EQ_STR(hex, SEED_HEX);
}

static void test_seed_from_base58(void) {
    uint8_t seed[XRPL_SEED_BYTES];
    char hex[2u * XRPL_SEED_BYTES + 1u];

    CHECK_EQ_INT(xrpl_seed_from_text(SED_SEED, seed), EVERGRAM_OK);
    bytes_to_hex(seed, sizeof(seed), hex);
    CHECK_EQ_STR(hex, SED_ED25519_SEED_HEX);
}

static void test_seed_rejects_garbage(void) {
    uint8_t seed[XRPL_SEED_BYTES];

    CHECK_EQ_INT(xrpl_seed_from_text("not-a-seed", seed), EVERGRAM_ERR_ENCODING);
    CHECK_EQ_INT(xrpl_seed_from_text("sEdINVALID", seed), EVERGRAM_ERR_ENCODING);
    CHECK_EQ_INT(xrpl_seed_from_text("", seed), EVERGRAM_ERR_ENCODING);
}

static void test_public_key_has_ed_prefix(void) {
    uint8_t seed[XRPL_SEED_BYTES];
    uint8_t public_key[XRPL_PUBLIC_KEY_BYTES];
    char hex[2u * XRPL_PUBLIC_KEY_BYTES + 1u];

    CHECK_EQ_INT(xrpl_seed_from_text(SEED_HEX, seed), EVERGRAM_OK);
    CHECK_EQ_INT(xrpl_public_key_from_seed(seed, public_key), EVERGRAM_OK);
    CHECK_EQ_INT(public_key[0], 0xED);

    bytes_to_hex(public_key, sizeof(public_key), hex);
    CHECK_EQ_STR(hex, PUBLIC_KEY_HEX);
}

static void test_base58_seed_derives_same_key(void) {
    uint8_t seed[XRPL_SEED_BYTES];
    uint8_t public_key[XRPL_PUBLIC_KEY_BYTES];
    char hex[2u * XRPL_PUBLIC_KEY_BYTES + 1u];

    CHECK_EQ_INT(xrpl_seed_from_text(SED_SEED, seed), EVERGRAM_OK);
    CHECK_EQ_INT(xrpl_public_key_from_seed(seed, public_key), EVERGRAM_OK);
    bytes_to_hex(public_key, sizeof(public_key), hex);
    CHECK_EQ_STR(hex, SED_PUBLIC_KEY_HEX);
}

static void test_address_derivation(void) {
    uint8_t seed[XRPL_SEED_BYTES];
    uint8_t public_key[XRPL_PUBLIC_KEY_BYTES];
    char address[EVERGRAM_ADDRESS_SIZE];

    CHECK_EQ_INT(xrpl_seed_from_text(SEED_HEX, seed), EVERGRAM_OK);
    CHECK_EQ_INT(xrpl_public_key_from_seed(seed, public_key), EVERGRAM_OK);
    CHECK_EQ_INT(xrpl_address_from_public_key(public_key, sizeof(public_key), address,
                                              sizeof(address)),
                 EVERGRAM_OK);
    CHECK_EQ_STR(address, ADDRESS);
}

static void test_address_requires_ed_prefix(void) {
    char address[EVERGRAM_ADDRESS_SIZE];

    uint8_t bare[XRPL_SEED_BYTES] = {0};
    CHECK_EQ_INT(xrpl_address_from_public_key(bare, sizeof(bare), address, sizeof(address)),
                 EVERGRAM_ERR_INVALID_ARG);

    uint8_t wrong_prefix[XRPL_PUBLIC_KEY_BYTES] = {0};
    wrong_prefix[0] = 0x02; /* secp256k1 compressed */
    CHECK_EQ_INT(xrpl_address_from_public_key(wrong_prefix, sizeof(wrong_prefix), address,
                                              sizeof(address)),
                 EVERGRAM_ERR_INVALID_ARG);
}

static void test_signature_matches_gateway_vector(void) {
    char signature[2u * XRPL_SIGNATURE_BYTES + 1u];

    CHECK_EQ_INT(xrpl_sign(PRIVATE_KEY_HEX, (const uint8_t *)CHALLENGE, strlen(CHALLENGE),
                           signature, sizeof(signature)),
                 EVERGRAM_OK);
    CHECK_EQ_STR(signature, SIGNATURE_HEX);
}

static void test_all_private_key_forms_agree(void) {
    char from_prefixed[2u * XRPL_SIGNATURE_BYTES + 1u];
    char from_raw_seed[2u * XRPL_SIGNATURE_BYTES + 1u];
    char from_secret_key[2u * XRPL_SIGNATURE_BYTES + 1u];

    CHECK_EQ_INT(xrpl_sign(PRIVATE_KEY_HEX, (const uint8_t *)CHALLENGE, strlen(CHALLENGE),
                           from_prefixed, sizeof(from_prefixed)),
                 EVERGRAM_OK);
    CHECK_EQ_INT(xrpl_sign(SEED_HEX, (const uint8_t *)CHALLENGE, strlen(CHALLENGE), from_raw_seed,
                           sizeof(from_raw_seed)),
                 EVERGRAM_OK);

    uint8_t seed[XRPL_SEED_BYTES];
    uint8_t public_key[crypto_sign_PUBLICKEYBYTES];
    uint8_t secret_key[crypto_sign_SECRETKEYBYTES];
    CHECK_EQ_INT(sodium_hex2bin(seed, sizeof(seed), SEED_HEX, strlen(SEED_HEX), NULL, NULL, NULL),
                 0);
    crypto_sign_seed_keypair(public_key, secret_key, seed);

    char secret_hex[2u * crypto_sign_SECRETKEYBYTES + 1u];
    bytes_to_hex(secret_key, sizeof(secret_key), secret_hex);
    CHECK_EQ_INT(xrpl_sign(secret_hex, (const uint8_t *)CHALLENGE, strlen(CHALLENGE),
                           from_secret_key, sizeof(from_secret_key)),
                 EVERGRAM_OK);

    CHECK_EQ_STR(from_prefixed, SIGNATURE_HEX);
    CHECK_EQ_STR(from_raw_seed, SIGNATURE_HEX);
    CHECK_EQ_STR(from_secret_key, SIGNATURE_HEX);

    memset(secret_key, 0, sizeof(secret_key));
    memset(secret_hex, 0, sizeof(secret_hex));
}

static void test_sign_rejects_bad_keys(void) {
    char signature[2u * XRPL_SIGNATURE_BYTES + 1u];

    CHECK_EQ_INT(xrpl_sign("abcd", (const uint8_t *)"x", 1, signature, sizeof(signature)),
                 EVERGRAM_ERR_ENCODING);
    CHECK_EQ_INT(xrpl_sign("EDzz", (const uint8_t *)"x", 1, signature, sizeof(signature)),
                 EVERGRAM_ERR_ENCODING);
}

static void test_sign_requires_room(void) {
    char small[10];
    CHECK_EQ_INT(xrpl_sign(PRIVATE_KEY_HEX, (const uint8_t *)"x", 1, small, sizeof(small)),
                 EVERGRAM_ERR_BUFFER_TOO_SMALL);
}

static const test_case_t TESTS[] = {
    {"xrpl: seed from 64 hex chars", test_seed_from_hex},
    {"xrpl: seed from base58 sEd", test_seed_from_base58},
    {"xrpl: malformed seeds rejected", test_seed_rejects_garbage},
    {"xrpl: public key carries the 0xED prefix", test_public_key_has_ed_prefix},
    {"xrpl: base58 seed derives the same key", test_base58_seed_derives_same_key},
    {"xrpl: address derivation", test_address_derivation},
    {"xrpl: address rejects unprefixed keys", test_address_requires_ed_prefix},
    {"xrpl: signature matches gateway vector", test_signature_matches_gateway_vector},
    {"xrpl: every private key form agrees", test_all_private_key_forms_agree},
    {"xrpl: malformed private keys rejected", test_sign_rejects_bad_keys},
    {"xrpl: small signature buffer rejected", test_sign_requires_room},
};

const test_case_t *xrpl_tests(size_t *count) {
    *count = sizeof(TESTS) / sizeof(TESTS[0]);
    return TESTS;
}
