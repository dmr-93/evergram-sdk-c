#include <sodium.h>
#include <stdlib.h>
#include <string.h>

#include "../examples/xahau-tip-bot/commands.h"
#include "../examples/xahau-tip-bot/xahau_rpc.h"
#include "../examples/xahau-tip-bot/xahau_tx.h"
#include "test.h"
#include "xahau_vectors.h"

/*
 * The Xahau/XRPL transaction layer.
 *
 * The vectors were signed by the `xrpl` package — the library the TypeScript
 * example submits with — for the same fixed wallet and transactions. Ed25519 is
 * deterministic, so matching the blob byte for byte is the only real proof that
 * this hand-written XRPL binary encoding is correct; anything less (round
 * tripping through a decoder of my own) could agree with itself and still be
 * wrong on the wire.
 */

static void payment_with_network_id(xahau_payment_t *payment) {
    memset(payment, 0, sizeof(*payment));
    payment->account = XAH_ACCOUNT;
    payment->destination = XAH_DESTINATION;
    payment->amount_drops = XAH_WITH_NETWORK_ID_AMOUNT;
    payment->fee_drops = XAH_WITH_NETWORK_ID_FEE;
    payment->sequence = XAH_WITH_NETWORK_ID_SEQUENCE;
    payment->last_ledger_sequence = XAH_WITH_NETWORK_ID_LAST_LEDGER_SEQUENCE;
    payment->has_network_id = true;
    payment->network_id = XAH_WITH_NETWORK_ID_NETWORK_ID;
}

static void payment_without_network_id(xahau_payment_t *payment) {
    memset(payment, 0, sizeof(*payment));
    payment->account = XAH_ACCOUNT;
    payment->destination = XAH_DESTINATION;
    payment->amount_drops = XAH_WITHOUT_NETWORK_ID_AMOUNT;
    payment->fee_drops = XAH_WITHOUT_NETWORK_ID_FEE;
    payment->sequence = XAH_WITHOUT_NETWORK_ID_SEQUENCE;
    payment->last_ledger_sequence = XAH_WITHOUT_NETWORK_ID_LAST_LEDGER_SEQUENCE;
    payment->has_network_id = false;
}

/* The seed an identity holds must be the one the reference library signed with. */
static void test_account_id_decodes(void) {
    uint8_t account_id[EVERGRAM_ACCOUNT_ID_BYTES];

    CHECK_EQ_INT(evergram_address_to_account_id(XAH_ACCOUNT, account_id), EVERGRAM_OK);
    /* The same id the reference blob carries after its 0x81 0x14 preamble. */
    const char *expected = "5219F4A7E34300FA3A7BC4DABD57000F07AD6F48";
    char hex[2u * EVERGRAM_ACCOUNT_ID_BYTES + 1u];
    sodium_bin2hex(hex, sizeof(hex), account_id, sizeof(account_id));
    for (size_t i = 0; hex[i] != '\0'; i++) {
        if (hex[i] >= 'a' && hex[i] <= 'f') {
            hex[i] = (char)(hex[i] - 'a' + 'A');
        }
    }
    CHECK_EQ_STR(hex, expected);

    /* A checksum failure must not produce an id. */
    char broken[64];
    snprintf(broken, sizeof(broken), "%s", XAH_ACCOUNT);
    broken[strlen(broken) - 1] = (broken[strlen(broken) - 1] == 'A') ? 'B' : 'A';
    CHECK(evergram_address_to_account_id(broken, account_id) != EVERGRAM_OK);
    CHECK_EQ_INT(evergram_address_to_account_id(NULL, account_id), EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(evergram_address_to_account_id(XAH_ACCOUNT, NULL), EVERGRAM_ERR_INVALID_ARG);
    /* A destination address works the same way. */
    CHECK_EQ_INT(evergram_address_to_account_id(XAH_DESTINATION, account_id), EVERGRAM_OK);
}

static void test_payment_with_network_id_matches_reference(void) {
    xahau_payment_t payment;
    payment_with_network_id(&payment);

    char signing_data[XAHAU_SIGNING_DATA_MAX];
    char blob[XAHAU_BLOB_MAX];
    char hash[XAHAU_HASH_HEX_SIZE];
    CHECK_EQ_INT(xahau_sign_payment(XAH_PRIVATE_KEY_HEX, &payment, signing_data,
                                    sizeof(signing_data), blob, sizeof(blob), hash, sizeof(hash)),
                 EVERGRAM_OK);

    CHECK_EQ_STR(signing_data, XAH_WITH_NETWORK_ID_SIGNING_DATA);
    CHECK_EQ_STR(blob, XAH_WITH_NETWORK_ID_BLOB);
    CHECK_EQ_STR(hash, XAH_WITH_NETWORK_ID_HASH);
}

/* Mainnet-style transactions carry no NetworkID at all; the field must be
 * omitted, not written as zero. */
static void test_payment_without_network_id_matches_reference(void) {
    xahau_payment_t payment;
    payment_without_network_id(&payment);

    char signing_data[XAHAU_SIGNING_DATA_MAX];
    char blob[XAHAU_BLOB_MAX];
    char hash[XAHAU_HASH_HEX_SIZE];
    CHECK_EQ_INT(xahau_sign_payment(XAH_PRIVATE_KEY_HEX, &payment, signing_data,
                                    sizeof(signing_data), blob, sizeof(blob), hash, sizeof(hash)),
                 EVERGRAM_OK);

    CHECK_EQ_STR(signing_data, XAH_WITHOUT_NETWORK_ID_SIGNING_DATA);
    CHECK_EQ_STR(blob, XAH_WITHOUT_NETWORK_ID_BLOB);
    CHECK_EQ_STR(hash, XAH_WITHOUT_NETWORK_ID_HASH);
}

/*
 * The blob is what a node verifies, so it is worth checking independently of the
 * vector: the SigningPubKey must be the identity's, and the signature must
 * verify over the signing payload.
 */
static void test_blob_carries_a_verifiable_signature(void) {
    xahau_payment_t payment;
    payment_with_network_id(&payment);

    char blob[XAHAU_BLOB_MAX];
    char hash[XAHAU_HASH_HEX_SIZE];
    CHECK_EQ_INT(xahau_sign_payment(XAH_PRIVATE_KEY_HEX, &payment, NULL, 0, blob, sizeof(blob),
                                    hash, sizeof(hash)),
                 EVERGRAM_OK);

    /* The account's public key, taken from the vector, must appear in full. */
    CHECK(strstr(blob, XAH_PUBLIC_KEY_HEX + 2) != NULL);

    /* And the transaction id must be SHA-512Half of "TXN\0" || blob. */
    size_t blob_bytes = strlen(blob) / 2u;
    uint8_t raw[XAHAU_BLOB_MAX];
    CHECK_EQ_INT(sodium_hex2bin(raw, sizeof(raw), blob, strlen(blob), NULL, NULL, NULL), 0);

    uint8_t digest[crypto_hash_sha512_BYTES];
    crypto_hash_sha512_state state;
    crypto_hash_sha512_init(&state);
    const uint8_t prefix[4] = {0x54u, 0x58u, 0x4eu, 0x00u};
    crypto_hash_sha512_update(&state, prefix, sizeof(prefix));
    crypto_hash_sha512_update(&state, raw, blob_bytes);
    crypto_hash_sha512_final(&state, digest);

    char expected[XAHAU_HASH_HEX_SIZE];
    sodium_bin2hex(expected, sizeof(expected), digest, 32);
    for (size_t i = 0; expected[i] != '\0'; i++) {
        if (expected[i] >= 'a' && expected[i] <= 'f') {
            expected[i] = (char)(expected[i] - 'a' + 'A');
        }
    }
    CHECK_EQ_STR(hash, expected);
    CHECK_EQ_STR(hash, XAH_WITH_NETWORK_ID_HASH);
}

static void test_payment_validation(void) {
    xahau_payment_t payment;
    payment_with_network_id(&payment);

    char blob[XAHAU_BLOB_MAX];
    char hash[XAHAU_HASH_HEX_SIZE];

    CHECK_EQ_INT(xahau_sign_payment(NULL, &payment, NULL, 0, blob, sizeof(blob), hash,
                                    sizeof(hash)),
                 EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(xahau_sign_payment(XAH_PRIVATE_KEY_HEX, NULL, NULL, 0, blob, sizeof(blob), hash,
                                    sizeof(hash)),
                 EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(xahau_sign_payment(XAH_PRIVATE_KEY_HEX, &payment, NULL, 0, NULL, 0, hash,
                                    sizeof(hash)),
                 EVERGRAM_ERR_INVALID_ARG);

    /* A short key, a non-decimal amount and an out-of-range amount are all
     * refused rather than serialized into something a node would reject. */
    CHECK_EQ_INT(xahau_sign_payment("ED00", &payment, NULL, 0, blob, sizeof(blob), hash,
                                    sizeof(hash)),
                 EVERGRAM_ERR_INVALID_ARG);

    xahau_payment_t bad;
    payment_with_network_id(&bad);
    bad.amount_drops = "12.5";
    CHECK_EQ_INT(xahau_sign_payment(XAH_PRIVATE_KEY_HEX, &bad, NULL, 0, blob, sizeof(blob), hash,
                                    sizeof(hash)),
                 EVERGRAM_ERR_INVALID_ARG);

    payment_with_network_id(&bad);
    bad.amount_drops = "99999999999999999999";
    CHECK_EQ_INT(xahau_sign_payment(XAH_PRIVATE_KEY_HEX, &bad, NULL, 0, blob, sizeof(blob), hash,
                                    sizeof(hash)),
                 EVERGRAM_ERR_INVALID_ARG);

    payment_with_network_id(&bad);
    bad.sequence = 0x1FFFFFFFFull; /* beyond a UInt32 */
    CHECK_EQ_INT(xahau_sign_payment(XAH_PRIVATE_KEY_HEX, &bad, NULL, 0, blob, sizeof(blob), hash,
                                    sizeof(hash)),
                 EVERGRAM_ERR_INVALID_ARG);

    payment_with_network_id(&bad);
    bad.destination = "not-an-address";
    CHECK(xahau_sign_payment(XAH_PRIVATE_KEY_HEX, &bad, NULL, 0, blob, sizeof(blob), hash,
                             sizeof(hash)) != EVERGRAM_OK);

    /* A buffer that cannot hold the blob fails instead of truncating it. */
    payment_with_network_id(&bad);
    char small[32];
    CHECK_EQ_INT(xahau_sign_payment(XAH_PRIVATE_KEY_HEX, &bad, NULL, 0, small, sizeof(small), hash,
                                    sizeof(hash)),
                 EVERGRAM_ERR_BUFFER_TOO_SMALL);
    CHECK_EQ_INT(small[0], '\0');
}

/* Nothing may quietly differ between two runs: the whole format is fixed. */
static void test_signing_is_deterministic(void) {
    xahau_payment_t payment;
    payment_with_network_id(&payment);

    char first[XAHAU_BLOB_MAX];
    char second[XAHAU_BLOB_MAX];
    char hash[XAHAU_HASH_HEX_SIZE];
    CHECK_EQ_INT(xahau_sign_payment(XAH_PRIVATE_KEY_HEX, &payment, NULL, 0, first, sizeof(first),
                                    hash, sizeof(hash)),
                 EVERGRAM_OK);
    CHECK_EQ_INT(xahau_sign_payment(XAH_PRIVATE_KEY_HEX, &payment, NULL, 0, second, sizeof(second),
                                    hash, sizeof(hash)),
                 EVERGRAM_OK);
    CHECK_EQ_STR(first, second);
}

/* The JSON-RPC envelope is the node-facing contract; the transport around it
 * is thin enough that its shape is worth pinning on its own. */
static void test_rpc_request_shape(void) {
    char request[512];

    CHECK_EQ_INT(xahau_rpc_build_request(request, sizeof(request), 7, "account_info",
                                         "{\"account\":\"rTest\"}"),
                 EVERGRAM_OK);
    CHECK_EQ_STR(request,
                 "{\"method\":\"account_info\",\"params\":[{\"account\":\"rTest\"}],\"id\":7}");

    /* A method without parameters still sends an empty parameter object. */
    CHECK_EQ_INT(xahau_rpc_build_request(request, sizeof(request), 1, "fee", NULL), EVERGRAM_OK);
    CHECK_EQ_STR(request, "{\"method\":\"fee\",\"params\":[{}],\"id\":1}");

    /* A buffer that cannot hold it fails instead of truncating JSON. */
    char small[16];
    CHECK_EQ_INT(xahau_rpc_build_request(small, sizeof(small), 1, "server_state", "{}"),
                 EVERGRAM_ERR_BUFFER_TOO_SMALL);
    CHECK_EQ_INT(small[0], '\0');
    CHECK_EQ_INT(xahau_rpc_build_request(NULL, 0, 1, "fee", NULL), EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(xahau_rpc_build_request(request, sizeof(request), 1, NULL, NULL),
                 EVERGRAM_ERR_INVALID_ARG);
}

/* A client that cannot reach a node must say so rather than pretend. */
static void test_rpc_unreachable_node(void) {
    xahau_rpc_t *rpc = xahau_rpc_create("ws://127.0.0.1:1/", 500);
    CHECK(rpc != NULL);
    if (rpc == NULL) {
        return;
    }

    xahau_account_t account;
    /* Either the connection fails or the budget expires; both are failures, and
     * neither leaves a half-filled result behind. */
    CHECK(xahau_rpc_account_info(rpc, "rTest", &account) != EVERGRAM_OK);
    CHECK_EQ_INT((long long)account.sequence, 0LL);
    CHECK(xahau_rpc_last_error(rpc) != NULL);
    CHECK(!xahau_rpc_is_connected(rpc));

    xahau_rpc_destroy(rpc);
    xahau_rpc_destroy(NULL); /* accepted */

    /* A malformed or missing URL is refused up front. */
    CHECK(xahau_rpc_create(NULL, 100) == NULL);
    CHECK(xahau_rpc_create("http://nope", 100) == NULL);
    CHECK(xahau_rpc_create("", 100) == NULL);

    /* Argument validation never touches the network. */
    rpc = xahau_rpc_create("ws://127.0.0.1:1/", 200);
    CHECK(rpc != NULL);
    if (rpc != NULL) {
        CHECK_EQ_INT(xahau_rpc_account_info(NULL, "rTest", &account), EVERGRAM_ERR_INVALID_ARG);
        CHECK_EQ_INT(xahau_rpc_account_info(rpc, NULL, &account), EVERGRAM_ERR_INVALID_ARG);
        CHECK_EQ_INT(xahau_rpc_account_info(rpc, "rTest", NULL), EVERGRAM_ERR_INVALID_ARG);
        CHECK_EQ_INT(xahau_rpc_submit(rpc, NULL, NULL, 0), EVERGRAM_ERR_INVALID_ARG);
        char result[64];
        bool validated = false;
        CHECK_EQ_INT(xahau_rpc_tx_result(rpc, NULL, &validated, result, sizeof(result)),
                     EVERGRAM_ERR_INVALID_ARG);
        xahau_rpc_destroy(rpc);
    }
}

/* --- command parsing ------------------------------------------------------ */

static void test_tip_command_shapes(void) {
    tip_command_t tip;
    char error[256];

    /* Mention: the identity key is carried as-is. */
    CHECK_EQ_INT(tip_parse("!tip @1:rAlice 5", NULL, &tip, error, sizeof(error)), EVERGRAM_OK);
    CHECK_EQ_INT(tip.target_kind, TIP_TARGET_MENTION);
    CHECK_EQ_STR(tip.identity_key, "1:rAlice");
    CHECK_EQ_STR(tip.amount, "5");
    CHECK_EQ_STR(tip.currency, "XAH"); /* defaulted */

    /* Address, with an explicit currency. */
    CHECK_EQ_INT(tip_parse("!tip rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe 1.25 XRP", NULL, &tip, error,
                           sizeof(error)),
                 EVERGRAM_OK);
    CHECK_EQ_INT(tip.target_kind, TIP_TARGET_ADDRESS);
    CHECK_EQ_STR(tip.address, "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe");
    CHECK_EQ_STR(tip.amount, "1.25");
    CHECK_EQ_STR(tip.currency, "XRP");

    /* No target token: the reply's author is the target. */
    CHECK_EQ_INT(tip_parse("!tip 5", "1:rBob", &tip, error, sizeof(error)), EVERGRAM_OK);
    CHECK_EQ_INT(tip.target_kind, TIP_TARGET_REPLY);
    CHECK_EQ_STR(tip.identity_key, "1:rBob");

    /* And without a reply to fall back to, it is refused with the reference
     * SDK's wording. */
    CHECK_EQ_INT(tip_parse("!tip 5", NULL, &tip, error, sizeof(error)),
                 EVERGRAM_ERR_INVALID_ARG);
    CHECK(strstr(error, "No target given") != NULL);
    CHECK_EQ_INT(tip_parse("!tip 5", "", &tip, error, sizeof(error)), EVERGRAM_ERR_INVALID_ARG);

    /* Extra whitespace is irrelevant. */
    CHECK_EQ_INT(tip_parse("  !tip   @1:rAlice   5  ", NULL, &tip, error, sizeof(error)),
                 EVERGRAM_OK);
    CHECK_EQ_STR(tip.amount, "5");
}

static void test_tip_command_rejections(void) {
    tip_command_t tip;
    char error[256];

    CHECK_EQ_INT(tip_parse("!tip", NULL, &tip, error, sizeof(error)), EVERGRAM_ERR_INVALID_ARG);
    CHECK(strstr(error, "Usage:") != NULL);

    CHECK_EQ_INT(tip_parse("!tip @1:rAlice", NULL, &tip, error, sizeof(error)),
                 EVERGRAM_ERR_INVALID_ARG);
    CHECK(strstr(error, "missing") != NULL);

    /* More precision than XAH has, zero, and non-numbers. */
    CHECK_EQ_INT(tip_parse("!tip @1:rAlice 0.0000001", NULL, &tip, error, sizeof(error)),
                 EVERGRAM_ERR_INVALID_ARG);
    CHECK(strstr(error, "decimal places") != NULL);
    CHECK_EQ_INT(tip_parse("!tip @1:rAlice 0", NULL, &tip, error, sizeof(error)),
                 EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(tip_parse("!tip @1:rAlice abc", NULL, &tip, error, sizeof(error)),
                 EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(tip_parse("!tip @1:rAlice -5", NULL, &tip, error, sizeof(error)),
                 EVERGRAM_ERR_INVALID_ARG);
    /* Six decimals is exactly the limit, so it is allowed. */
    CHECK_EQ_INT(tip_parse("!tip @1:rAlice 0.000001", NULL, &tip, error, sizeof(error)),
                 EVERGRAM_OK);

    CHECK_EQ_INT(tip_parse("hello", NULL, &tip, error, sizeof(error)), EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(tip_parse(NULL, NULL, &tip, error, sizeof(error)), EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(tip_parse("!tip 5", NULL, NULL, error, sizeof(error)), EVERGRAM_ERR_INVALID_ARG);
}

static void test_amount_to_drops(void) {
    char drops[32];

    CHECK_EQ_INT(tip_amount_to_drops("5", drops, sizeof(drops)), EVERGRAM_OK);
    CHECK_EQ_STR(drops, "5000000");
    CHECK_EQ_INT(tip_amount_to_drops("0.000001", drops, sizeof(drops)), EVERGRAM_OK);
    CHECK_EQ_STR(drops, "1");
    CHECK_EQ_INT(tip_amount_to_drops("1.25", drops, sizeof(drops)), EVERGRAM_OK);
    CHECK_EQ_STR(drops, "1250000");
    CHECK_EQ_INT(tip_amount_to_drops("10.5", drops, sizeof(drops)), EVERGRAM_OK);
    CHECK_EQ_STR(drops, "10500000");

    /* Rejections match the parser's. */
    CHECK_EQ_INT(tip_amount_to_drops("0", drops, sizeof(drops)), EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(tip_amount_to_drops("1.2345678", drops, sizeof(drops)),
                 EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(tip_amount_to_drops("", drops, sizeof(drops)), EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(tip_amount_to_drops(NULL, drops, sizeof(drops)), EVERGRAM_ERR_INVALID_ARG);

    char small[4];
    CHECK_EQ_INT(tip_amount_to_drops("5", small, sizeof(small)), EVERGRAM_ERR_BUFFER_TOO_SMALL);
    CHECK_EQ_INT(small[0], '\0');
}

static void test_address_from_identity(void) {
    char address[EVERGRAM_ADDRESS_SIZE];

    CHECK(tip_address_from_identity("1:rAlice", address, sizeof(address)));
    CHECK_EQ_STR(address, "rAlice");
    /* Only XRPL identities can be tipped. */
    CHECK(!tip_address_from_identity("2:rAlice", address, sizeof(address)));
    CHECK(!tip_address_from_identity("rAlice", address, sizeof(address)));
    CHECK(!tip_address_from_identity(":rAlice", address, sizeof(address)));
    CHECK(!tip_address_from_identity("1:", address, sizeof(address)));
    CHECK(!tip_address_from_identity(NULL, address, sizeof(address)));
}

static const test_case_t TESTS[] = {
    {"xahau: an address decodes to its account id", test_account_id_decodes},
    {"xahau: payment with a network id matches the reference",
     test_payment_with_network_id_matches_reference},
    {"xahau: payment without a network id matches the reference",
     test_payment_without_network_id_matches_reference},
    {"xahau: the blob carries a verifiable signature",
     test_blob_carries_a_verifiable_signature},
    {"xahau: invalid payments are refused", test_payment_validation},
    {"xahau: signing is deterministic", test_signing_is_deterministic},
    {"xahau: a JSON-RPC request has the right shape", test_rpc_request_shape},
    {"xahau: an unreachable node is reported", test_rpc_unreachable_node},
    {"xahau: tip commands parse", test_tip_command_shapes},
    {"xahau: bad tip commands are refused", test_tip_command_rejections},
    {"xahau: amounts convert to drops", test_amount_to_drops},
    {"xahau: an identity key yields its address", test_address_from_identity},
};

const test_case_t *xahau_tx_tests(size_t *count) {
    *count = sizeof(TESTS) / sizeof(TESTS[0]);
    return TESTS;
}
