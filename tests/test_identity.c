#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "identity.h"
#include "test.h"
#include "evergram.h"
#include "xrpl.h"

#define TEST_PATH "build/test_identity.json"
#define LEGACY_PATH "build/test_identity_legacy.json"

static void test_wallet_generate(void) {
    evergram_wallet_t wallet;
    CHECK_EQ_INT(evergram_wallet_generate(&wallet), EVERGRAM_OK);

    CHECK_EQ_INT(strlen(wallet.seed), 64);
    CHECK_EQ_INT(strlen(wallet.public_key_hex), 66);
    CHECK_EQ_INT(strlen(wallet.private_key_hex), 66);
    CHECK_EQ_INT(wallet.address[0], 'r');
    CHECK(strlen(wallet.address) >= 25 && strlen(wallet.address) <= 35);

    /* The stored public key must reproduce the stored address. */
    uint8_t public_key[XRPL_PUBLIC_KEY_BYTES];
    CHECK_EQ_INT(sodium_hex2bin(public_key, sizeof(public_key), wallet.public_key_hex, 66, NULL,
                                NULL, NULL),
                 0);
    char address[EVERGRAM_ADDRESS_SIZE];
    CHECK_EQ_INT(xrpl_address_from_public_key(public_key, sizeof(public_key), address,
                                              sizeof(address)),
                 EVERGRAM_OK);
    CHECK_EQ_STR(address, wallet.address);

    evergram_wallet_t other;
    CHECK_EQ_INT(evergram_wallet_generate(&other), EVERGRAM_OK);
    CHECK(strcmp(wallet.seed, other.seed) != 0);

    evergram_wallet_wipe(&other);
    evergram_wallet_wipe(&wallet);
}

static void test_device_generate(void) {
    evergram_device_t device;
    CHECK_EQ_INT(evergram_device_generate(&device), EVERGRAM_OK);

    CHECK_EQ_INT(strlen(device.device_id), 32);
    CHECK_EQ_INT(strlen(device.public_key_hex), 64);
    CHECK_EQ_INT(strlen(device.private_key_hex), 64);

    uint8_t public_key[32];
    CHECK_EQ_INT(sodium_hex2bin(public_key, sizeof(public_key), device.public_key_hex, 64, NULL,
                                NULL, NULL),
                 0);

    char derived[EVERGRAM_DEVICE_ID_SIZE];
    CHECK_EQ_INT(identity_device_id_from_public_key(public_key, sizeof(public_key), derived,
                                                    sizeof(derived)),
                 EVERGRAM_OK);
    CHECK_EQ_STR(device.device_id, derived);

    evergram_device_wipe(&device);
}

static void test_save_load_roundtrip(void) {
    evergram_wallet_t wallet;
    evergram_device_t device;
    CHECK_EQ_INT(evergram_wallet_generate(&wallet), EVERGRAM_OK);
    CHECK_EQ_INT(evergram_device_generate(&device), EVERGRAM_OK);

    CHECK_EQ_INT(evergram_identity_save(TEST_PATH, &wallet, &device), EVERGRAM_OK);

    struct stat info;
    CHECK_EQ_INT(stat(TEST_PATH, &info), 0);
    CHECK_EQ_INT((int)(info.st_mode & 0777u), 0600);

    evergram_wallet_t loaded_wallet;
    evergram_device_t loaded_device;
    CHECK_EQ_INT(evergram_identity_load(TEST_PATH, &loaded_wallet, &loaded_device), EVERGRAM_OK);
    CHECK_EQ_STR(loaded_wallet.seed, wallet.seed);
    CHECK_EQ_STR(loaded_wallet.address, wallet.address);
    CHECK_EQ_STR(loaded_wallet.public_key_hex, wallet.public_key_hex);
    CHECK_EQ_STR(loaded_wallet.private_key_hex, wallet.private_key_hex);
    CHECK_EQ_STR(loaded_device.device_id, device.device_id);
    CHECK_EQ_STR(loaded_device.public_key_hex, device.public_key_hex);
    CHECK_EQ_STR(loaded_device.private_key_hex, device.private_key_hex);

    evergram_wallet_wipe(&wallet);
    evergram_device_wipe(&device);
    evergram_wallet_wipe(&loaded_wallet);
    evergram_device_wipe(&loaded_device);
    unlink(TEST_PATH);
}

static void test_legacy_file_is_completed(void) {
    evergram_wallet_t wallet;
    evergram_device_t device;
    CHECK_EQ_INT(evergram_wallet_generate(&wallet), EVERGRAM_OK);
    CHECK_EQ_INT(evergram_device_generate(&device), EVERGRAM_OK);

    /* Older files carry no pubkey/privkey; both must be rebuilt from the seed. */
    FILE *file = fopen(LEGACY_PATH, "w");
    CHECK(file != NULL);
    if (file != NULL) {
        fprintf(file, "seed=%s\naddress=%s\ndevice_pub=%s\ndevice_id=%s\n", wallet.seed,
                wallet.address, device.public_key_hex, device.device_id);
        fclose(file);
    }

    evergram_wallet_t loaded;
    evergram_device_t loaded_device;
    CHECK_EQ_INT(evergram_identity_load(LEGACY_PATH, &loaded, &loaded_device), EVERGRAM_OK);

    char expected_private[EVERGRAM_HEX_KEY_SIZE];
    snprintf(expected_private, sizeof(expected_private), "ED%s", wallet.seed);
    CHECK_EQ_STR(loaded.private_key_hex, expected_private);
    CHECK_EQ_STR(loaded.public_key_hex, wallet.public_key_hex);

    evergram_wallet_wipe(&wallet);
    evergram_device_wipe(&device);
    evergram_wallet_wipe(&loaded);
    evergram_device_wipe(&loaded_device);
    unlink(LEGACY_PATH);
}

static void test_missing_fields_rejected(void) {
    FILE *file = fopen(LEGACY_PATH, "w");
    CHECK(file != NULL);
    if (file != NULL) {
        fprintf(file, "seed=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n");
        fclose(file);
    }

    evergram_wallet_t wallet;
    evergram_device_t device;
    CHECK_EQ_INT(evergram_identity_load(LEGACY_PATH, &wallet, &device), EVERGRAM_ERR_IO);
    unlink(LEGACY_PATH);
}

static void test_missing_file_rejected(void) {
    evergram_wallet_t wallet;
    evergram_device_t device;
    CHECK_EQ_INT(evergram_identity_load("build/absent-identity.json", &wallet, &device),
                 EVERGRAM_ERR_IO);
}

/* The address is the account being authenticated as, never derived from the key. */
static void test_regular_key_wallet(void) {
    const char *seed = "db7fc7a261e8082cc0f3fdb3b3f15f95bb727ba9b533246eb4d46ec70604ea96";
    const char *account = "rSomeOtherAccountAddressForRegularKey";

    evergram_wallet_t wallet;
    CHECK_EQ_INT(evergram_wallet_from_regular_key(account, seed, &wallet), EVERGRAM_OK);
    CHECK_EQ_STR(wallet.address, account);
    CHECK_EQ_STR(wallet.seed, seed);
    /* Public key comes from the RegularKey seed the account points at. */
    CHECK_EQ_STR(wallet.public_key_hex,
                 "edb9f94de51cf7d0c15b4f4675444d5e2b3d1a02f8b923b1680485c4bd70a69e56");
    CHECK_EQ_INT(wallet.private_key_hex[0], 'E');
    CHECK_EQ_INT(wallet.private_key_hex[1], 'D');
    CHECK_EQ_STR(wallet.private_key_hex + 2, seed);

    /* The address must NOT be the one derived from this key. */
    uint8_t public_key[XRPL_PUBLIC_KEY_BYTES];
    CHECK_EQ_INT(sodium_hex2bin(public_key, sizeof(public_key), wallet.public_key_hex, 66, NULL,
                                NULL, NULL),
                 0);
    char derived[EVERGRAM_ADDRESS_SIZE];
    CHECK_EQ_INT(xrpl_address_from_public_key(public_key, sizeof(public_key), derived,
                                              sizeof(derived)),
                 EVERGRAM_OK);
    CHECK(strcmp(derived, wallet.address) != 0);

    evergram_wallet_wipe(&wallet);
}

static void test_regular_key_rejects_bad_input(void) {
    evergram_wallet_t wallet;
    CHECK_EQ_INT(evergram_wallet_from_regular_key(NULL, "x", &wallet), EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(evergram_wallet_from_regular_key("rAddr", NULL, &wallet),
                 EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(evergram_wallet_from_regular_key("", "x", &wallet), EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(evergram_wallet_from_regular_key("rAddr", "not-a-seed", &wallet),
                 EVERGRAM_ERR_ENCODING);
}

static const test_case_t TESTS[] = {
    {"identity: wallet generation", test_wallet_generate},
    {"identity: device generation", test_device_generate},
    {"identity: save/load roundtrip with 0600", test_save_load_roundtrip},
    {"identity: legacy file completion", test_legacy_file_is_completed},
    {"identity: missing fields rejected", test_missing_fields_rejected},
    {"identity: missing file rejected", test_missing_file_rejected},
    {"identity: regular-key wallet", test_regular_key_wallet},
    {"identity: regular-key rejects bad input", test_regular_key_rejects_bad_input},
};

const test_case_t *identity_tests(size_t *count) {
    *count = sizeof(TESTS) / sizeof(TESTS[0]);
    return TESTS;
}
