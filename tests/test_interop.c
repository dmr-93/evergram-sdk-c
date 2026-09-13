#include <sodium.h>
#include <stdio.h>
#include <string.h>

#include "e2ee.h"
#include "evergram.h"
#include "interop_vectors.h"
#include "relay.h"
#include <strings.h>

#include "test.h"
#include "xrpl.h"

/*
 * TypeScript <-> C interoperability.
 *
 * Every value in interop_vectors.h was produced by the reference TypeScript SDK
 * itself (see tools/gen_interop_vectors.mjs, which loads the SDK's own sources),
 * so these cases fail the moment this port stops agreeing with it on the wire:
 *
 *   - XRPL key derivation and address encoding from the same seed;
 *   - the authentication signature over the gateway's challenge string;
 *   - opening the chat key the gateway seals for a device (nacl.box);
 *   - decrypting a message the reference SDK sent (nacl.secretbox);
 *   - the payment/audio envelopes, byte for byte, in both directions;
 *   - a visitor-room relay frame.
 *
 * The threat model is trivial (fixed keys), so the only assertion that needs a
 * comment is the signature: ed25519 is deterministic, which is why the two
 * implementations must produce the exact same bytes rather than merely verify.
 */

static void unhex(const char *hex, uint8_t *out, size_t bytes) {
    CHECK_EQ_INT(sodium_hex2bin(out, bytes, hex, 2u * bytes, NULL, NULL, NULL), 0);
}

/* The same seed must produce the same keypair and address in both SDKs. */
static void test_wallet_derivation_matches(void) {
    evergram_wallet_t wallet;
    memset(&wallet, 0, sizeof(wallet));

    CHECK_EQ_INT(evergram_wallet_from_seed(INTEROP_WALLET_SEED, &wallet), EVERGRAM_OK);
    CHECK_EQ_STR(wallet.address, INTEROP_WALLET_ADDRESS);

    /*
     * The key material must be identical; the reference SDK writes hex in upper
     * case and this port in lower case, which XRPL treats as the same value
     * (every comparison the protocol makes is on bytes, not on the text).
     */
    CHECK_EQ_INT(strcasecmp(wallet.public_key_hex, INTEROP_AUTH_PUBLIC_KEY_HEX), 0);
    CHECK_EQ_INT((long long)strlen(wallet.public_key_hex), 66LL);
    CHECK_EQ_INT(strncasecmp(wallet.public_key_hex, "ED", 2), 0);

    evergram_wallet_wipe(&wallet);

    /* A nonsense seed is rejected rather than silently producing a wallet. */
    evergram_wallet_t invalid;
    memset(&invalid, 0, sizeof(invalid));
    CHECK(evergram_wallet_from_seed("not-a-seed", &invalid) != EVERGRAM_OK);
    CHECK(evergram_wallet_from_seed(NULL, &invalid) == EVERGRAM_ERR_INVALID_ARG);
}

/*
 * Both SDKs sign the raw challenge string with ed25519, so the signatures are
 * byte-identical: this is the exact proof the gateway's auth check relies on.
 */
static void test_auth_signature_matches(void) {
    evergram_wallet_t wallet;
    memset(&wallet, 0, sizeof(wallet));
    CHECK_EQ_INT(evergram_wallet_from_seed(INTEROP_WALLET_SEED, &wallet), EVERGRAM_OK);

    char signature_hex[2u * XRPL_SIGNATURE_BYTES + 1u];
    CHECK_EQ_INT(xrpl_sign(wallet.private_key_hex, (const uint8_t *)INTEROP_CHALLENGE,
                           strlen(INTEROP_CHALLENGE), signature_hex, sizeof(signature_hex)),
                 EVERGRAM_OK);
    CHECK_EQ_INT(strcasecmp(signature_hex, INTEROP_AUTH_SIGNATURE_HEX), 0);

    /* And the reference SDK's signature verifies against the derived key, which
     * is what the gateway does before looking at the account at all. */
    /* libsodium wants the bare 32-byte key: the leading 0xED is XRPL's marker,
     * not part of what ed25519 verifies against. */
    uint8_t prefixed_key[33];
    uint8_t signature[XRPL_SIGNATURE_BYTES];
    unhex(INTEROP_AUTH_PUBLIC_KEY_HEX, prefixed_key, sizeof(prefixed_key));
    unhex(INTEROP_AUTH_SIGNATURE_HEX, signature, sizeof(signature));
    CHECK_EQ_INT(prefixed_key[0], 0xed);
    CHECK_EQ_INT(crypto_sign_verify_detached(signature, (const uint8_t *)INTEROP_CHALLENGE,
                                             strlen(INTEROP_CHALLENGE), prefixed_key + 1),
                 0);

    evergram_wallet_wipe(&wallet);
}

/* The chat key the gateway sealed for this device must open in C. */
static void test_sealed_chat_key_opens(void) {
    uint8_t expected[E2EE_KEY_BYTES];
    uint8_t opened[E2EE_KEY_BYTES];
    unhex(INTEROP_SYM_KEY_HEX, expected, sizeof(expected));

    CHECK_EQ_INT(e2ee_open_sealed_key(INTEROP_SEALED_CIPHERTEXT_B64, INTEROP_SEALED_NONCE_B64,
                                      INTEROP_EPHEMERAL_PUBLIC_KEY_B64,
                                      INTEROP_DEVICE_PRIVATE_KEY_HEX, opened),
                 EVERGRAM_OK);
    CHECK_EQ_INT(sodium_memcmp(expected, opened, sizeof(expected)), 0);

    sodium_memzero(expected, sizeof(expected));
    sodium_memzero(opened, sizeof(opened));
}

/* A message the reference SDK encrypted must decrypt here, byte for byte. */
static void test_reference_message_decrypts(void) {
    uint8_t key[E2EE_KEY_BYTES];
    unhex(INTEROP_SYM_KEY_HEX, key, sizeof(key));

    char plaintext[512];
    size_t length = 0;
    CHECK_EQ_INT(e2ee_decrypt(key, INTEROP_MESSAGE_NONCE_B64, INTEROP_MESSAGE_CIPHERTEXT_B64,
                              plaintext, sizeof(plaintext), &length),
                 EVERGRAM_OK);
    CHECK_EQ_STR(plaintext, INTEROP_MESSAGE_PLAINTEXT);
    CHECK_EQ_INT((long long)length, (long long)strlen(INTEROP_MESSAGE_PLAINTEXT));

    /* A tampered ciphertext must fail closed, not return a partial body. */
    char tampered[sizeof(INTEROP_MESSAGE_CIPHERTEXT_B64)];
    snprintf(tampered, sizeof(tampered), "%s", INTEROP_MESSAGE_CIPHERTEXT_B64);
    tampered[0] = (tampered[0] == 'A') ? 'B' : 'A';
    plaintext[0] = '\0';
    CHECK(e2ee_decrypt(key, INTEROP_MESSAGE_NONCE_B64, tampered, plaintext, sizeof(plaintext),
                       &length) != EVERGRAM_OK);

    sodium_memzero(key, sizeof(key));
}

/*
 * The envelope builders must produce exactly what the reference SDK produces,
 * field order included: a peer running either SDK has to read the other's
 * messages, and a byte comparison is the strongest possible statement of that.
 */
static void test_payment_envelopes_match_byte_for_byte(void) {
    char built[EVERGRAM_PAYMENT_CONTENT_SIZE];

    evergram_payment_request_t request;
    memset(&request, 0, sizeof(request));
    snprintf(request.request_id, sizeof(request.request_id), "%s",
             "11111111-2222-4333-8444-555555555555");
    snprintf(request.amount, sizeof(request.amount), "%s", "10.5");
    snprintf(request.currency, sizeof(request.currency), "%s", "XAH");
    snprintf(request.currency_id, sizeof(request.currency_id), "%s", "EVR_XAHAU");
    request.has_note = true;
    snprintf(request.note, sizeof(request.note), "%s", "for the group");
    snprintf(request.to, sizeof(request.to), "%s", "rRequesterAddress");
    snprintf(request.to_identity_key, sizeof(request.to_identity_key), "%s",
             "1:rRequesterAddress");

    CHECK_EQ_INT(evergram_payment_request_build(&request, built, sizeof(built)), EVERGRAM_OK);
    CHECK_EQ_STR(built, INTEROP_PAYMENT_REQUEST);

    /* And the reference SDK's own envelope parses into the same fields. */
    evergram_content_t parsed;
    CHECK_EQ_INT(evergram_message_content_parse(INTEROP_PAYMENT_REQUEST, &parsed), EVERGRAM_OK);
    CHECK_EQ_INT(parsed.type, EVERGRAM_CONTENT_PAYMENT_REQUEST);
    CHECK_EQ_STR(parsed.payment_request.request_id, request.request_id);
    CHECK_EQ_STR(parsed.payment_request.note, "for the group");

    evergram_payment_receipt_t receipt;
    memset(&receipt, 0, sizeof(receipt));
    snprintf(receipt.request_id, sizeof(receipt.request_id), "%s",
             "11111111-2222-4333-8444-555555555555");
    snprintf(receipt.tx_hash, sizeof(receipt.tx_hash), "%s", "DEADBEEF");
    snprintf(receipt.amount, sizeof(receipt.amount), "%s", "10.5");
    snprintf(receipt.currency, sizeof(receipt.currency), "%s", "XAH");
    snprintf(receipt.currency_id, sizeof(receipt.currency_id), "%s", "EVR_XAHAU");
    snprintf(receipt.from, sizeof(receipt.from), "%s", "rPayerAddress");
    snprintf(receipt.from_identity_key, sizeof(receipt.from_identity_key), "%s",
             "1:rPayerAddress");

    CHECK_EQ_INT(evergram_payment_receipt_build(&receipt, built, sizeof(built)), EVERGRAM_OK);
    CHECK_EQ_STR(built, INTEROP_PAYMENT_RECEIPT);

    CHECK_EQ_INT(evergram_message_content_parse(INTEROP_PAYMENT_RECEIPT, &parsed), EVERGRAM_OK);
    CHECK_EQ_INT(parsed.type, EVERGRAM_CONTENT_PAYMENT_RECEIPT);
    CHECK_EQ_STR(parsed.payment_receipt.tx_hash, "DEADBEEF");
    CHECK_EQ_STR(parsed.payment_receipt.from_identity_key, "1:rPayerAddress");
}

static void test_audio_envelope_matches_byte_for_byte(void) {
    char built[2048];
    /* The reference vector encodes this exact 16-byte payload. */
    CHECK_EQ_INT(evergram_audio_message_build("audio/ogg", 1500,
                                              "AAECAwQFBgcICQoLDA0ODw==", built, sizeof(built)),
                 EVERGRAM_OK);
    CHECK_EQ_STR(built, INTEROP_AUDIO);

    evergram_content_t parsed;
    CHECK_EQ_INT(evergram_message_content_parse(INTEROP_AUDIO, &parsed), EVERGRAM_OK);
    CHECK_EQ_INT(parsed.type, EVERGRAM_CONTENT_AUDIO);
    CHECK_EQ_STR(parsed.audio.mime_type, "audio/ogg");
    CHECK_EQ_INT((long long)parsed.audio.duration_ms, 1500LL);
    CHECK_EQ_INT((long long)parsed.audio.size, 16LL);
}

/* A visitor-room frame built by the reference SDK must decode here. */
static void test_relay_frame_from_reference_decodes(void) {
    uint8_t key[E2EE_KEY_BYTES];
    unhex(INTEROP_SYM_KEY_HEX, key, sizeof(key));

    evergram_relay_text_t event;
    CHECK_EQ_INT(evergram_relay_parse_text(key, INTEROP_RELAY_PAYLOAD, &event), EVERGRAM_OK);
    CHECK_EQ_STR(event.text, INTEROP_RELAY_TEXT);
    CHECK_EQ_STR(event.sender, INTEROP_RELAY_SENDER);
    CHECK_EQ_STR(event.msg_id, INTEROP_RELAY_MSG_ID);

    /* The wire kind travels in the clear, so the mapping has to agree too. */
    CHECK_EQ_INT(evergram_relay_kind_from_wire(1), EVERGRAM_RELAY_KIND_TEXT);
    CHECK_EQ_INT(evergram_relay_kind_to_wire(EVERGRAM_RELAY_KIND_TEXT), 1);
    CHECK(evergram_relay_kind_is_content(EVERGRAM_RELAY_KIND_TEXT));

    sodium_memzero(key, sizeof(key));
}

static const test_case_t TESTS[] = {
    {"interop: wallet derivation matches the reference SDK", test_wallet_derivation_matches},
    {"interop: auth signature is byte-identical", test_auth_signature_matches},
    {"interop: sealed chat key opens", test_sealed_chat_key_opens},
    {"interop: reference message decrypts", test_reference_message_decrypts},
    {"interop: payment envelopes match", test_payment_envelopes_match_byte_for_byte},
    {"interop: audio envelope matches", test_audio_envelope_matches_byte_for_byte},
    {"interop: relay frame decodes", test_relay_frame_from_reference_decodes},
};

const test_case_t *interop_tests(size_t *count) {
    *count = sizeof(TESTS) / sizeof(TESTS[0]);
    return TESTS;
}
