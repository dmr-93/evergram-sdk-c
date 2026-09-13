#include "xahau_tx.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>

/*
 * XRPL binary serialization for one Payment.
 *
 * Fields are written in ascending field-code order — that is the format's
 * canonical rule, not a convention — where the code packs the type in the high
 * nibble and the field index in the low nibble (a second byte carries indices
 * above 15). Only the fields a tip needs are implemented; a transaction with
 * anything else must not be built here at all.
 */

/* Type codes, from the protocol's own definitions. */
#define TYPE_UINT16 0x1u
#define TYPE_UINT32 0x2u
#define TYPE_AMOUNT 0x6u
#define TYPE_BLOB 0x7u
#define TYPE_ACCOUNT_ID 0x8u

/* Field indices within those types. */
#define FIELD_TRANSACTION_TYPE 2u  /* UInt16 */
#define FIELD_NETWORK_ID 1u        /* UInt32 */
#define FIELD_SEQUENCE 4u          /* UInt32 */
#define FIELD_LAST_LEDGER_SEQ 27u  /* UInt32 */
#define FIELD_AMOUNT 1u            /* Amount */
#define FIELD_FEE 8u               /* Amount */
#define FIELD_SIGNING_PUB_KEY 3u   /* Blob */
#define FIELD_TXN_SIGNATURE 4u     /* Blob */
#define FIELD_ACCOUNT 1u           /* AccountID */
#define FIELD_DESTINATION 3u       /* AccountID */

#define TRANSACTION_TYPE_PAYMENT 0u

/* "STX\0": the domain separator a single signature commits to. */
static const uint8_t SIGNING_PREFIX[4] = {0x53u, 0x54u, 0x58u, 0x00u};
/* "TXN\0": the domain separator the transaction id hashes. */
static const uint8_t TXN_PREFIX[4] = {0x54u, 0x58u, 0x4eu, 0x00u};

typedef struct {
    uint8_t bytes[XAHAU_BLOB_MAX];
    size_t length;
    bool overflow;
} writer_t;

static void writer_init(writer_t *writer) {
    memset(writer, 0, sizeof(*writer));
}

static void write_bytes(writer_t *writer, const uint8_t *data, size_t length) {
    if (writer->overflow || writer->length + length > sizeof(writer->bytes)) {
        writer->overflow = true;
        return;
    }
    memcpy(writer->bytes + writer->length, data, length);
    writer->length += length;
}

static void write_byte(writer_t *writer, uint8_t value) {
    write_bytes(writer, &value, 1);
}

/* Field code: one byte when the index fits in the low nibble, two otherwise. */
static void write_field_code(writer_t *writer, unsigned type, unsigned field) {
    if (field < 16u) {
        write_byte(writer, (uint8_t)((type << 4) | field));
        return;
    }
    write_byte(writer, (uint8_t)(type << 4));
    write_byte(writer, (uint8_t)field);
}

static void write_uint16(writer_t *writer, unsigned type, unsigned field, uint16_t value) {
    write_field_code(writer, type, field);
    write_byte(writer, (uint8_t)(value >> 8));
    write_byte(writer, (uint8_t)(value & 0xffu));
}

static void write_uint32(writer_t *writer, unsigned type, unsigned field, uint32_t value) {
    write_field_code(writer, type, field);
    write_byte(writer, (uint8_t)(value >> 24));
    write_byte(writer, (uint8_t)((value >> 16) & 0xffu));
    write_byte(writer, (uint8_t)((value >> 8) & 0xffu));
    write_byte(writer, (uint8_t)(value & 0xffu));
}

/* Variable-length: one length byte below 192, then two above it. */
static void write_variable_length(writer_t *writer, size_t length) {
    if (length < 192u) {
        write_byte(writer, (uint8_t)length);
        return;
    }
    write_byte(writer, (uint8_t)(0xc0u | (length >> 8)));
    write_byte(writer, (uint8_t)(length & 0xffu));
}

static void write_vl(writer_t *writer, unsigned type, unsigned field, const uint8_t *data,
                     size_t length) {
    write_field_code(writer, type, field);
    write_variable_length(writer, length);
    write_bytes(writer, data, length);
}

/*
 * A native amount is 8 big-endian bytes holding the drops with bit 62 set
 * (0x4000000000000000), the marker that distinguishes it from an issued
 * currency. Anything that is not a plain decimal string is rejected.
 */
static evergram_status_t write_native_amount(writer_t *writer, unsigned field,
                                             const char *drops_text) {
    if (drops_text == NULL || drops_text[0] == '\0') {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    uint64_t drops = 0;
    for (const char *cursor = drops_text; *cursor != '\0'; cursor++) {
        if (*cursor < '0' || *cursor > '9') {
            return EVERGRAM_ERR_INVALID_ARG;
        }
        uint64_t digit = (uint64_t)(*cursor - '0');
        if (drops > (UINT64_MAX - digit) / 10u) {
            return EVERGRAM_ERR_INVALID_ARG; /* out of range, not silently wrapped */
        }
        drops = drops * 10u + digit;
    }
    if (drops >= 0x4000000000000000ull) {
        return EVERGRAM_ERR_INVALID_ARG; /* more than a native amount can hold */
    }

    uint64_t encoded = drops | 0x4000000000000000ull;
    write_field_code(writer, TYPE_AMOUNT, field);
    for (int shift = 56; shift >= 0; shift -= 8) {
        write_byte(writer, (uint8_t)((encoded >> (unsigned)shift) & 0xffu));
    }
    return EVERGRAM_OK;
}

static evergram_status_t write_account_id(writer_t *writer, unsigned field, const char *address) {
    uint8_t account_id[EVERGRAM_ACCOUNT_ID_BYTES];
    evergram_status_t status = evergram_address_to_account_id(address, account_id);
    if (status != EVERGRAM_OK) {
        return status;
    }
    write_vl(writer, TYPE_ACCOUNT_ID, field, account_id, sizeof(account_id));
    return EVERGRAM_OK;
}

/* Builds everything the signature commits to: prefix, then the fields without
 * TxnSignature (which is not a signing field). */
static evergram_status_t build_signing_data(const xahau_payment_t *payment,
                                            const uint8_t public_key[33], const char *account,
                                            writer_t *writer) {
    writer_init(writer);
    write_bytes(writer, SIGNING_PREFIX, sizeof(SIGNING_PREFIX));

    /* Ascending field code: 0x00010002, 0x00020001, 0x00020002, 0x00020004,
     * 0x0002001B, 0x00060001, 0x00060008, 0x00070003, 0x00080001, 0x00080003. */
    write_uint16(writer, TYPE_UINT16, FIELD_TRANSACTION_TYPE, TRANSACTION_TYPE_PAYMENT);

    if (payment->has_network_id) {
        write_uint32(writer, TYPE_UINT32, FIELD_NETWORK_ID, payment->network_id);
    }
    if (payment->sequence > UINT32_MAX || payment->last_ledger_sequence > UINT32_MAX) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    write_uint32(writer, TYPE_UINT32, FIELD_SEQUENCE, (uint32_t)payment->sequence);
    write_uint32(writer, TYPE_UINT32, FIELD_LAST_LEDGER_SEQ,
                 (uint32_t)payment->last_ledger_sequence);

    evergram_status_t status =
        write_native_amount(writer, FIELD_AMOUNT, payment->amount_drops);
    if (status == EVERGRAM_OK) {
        status = write_native_amount(writer, FIELD_FEE, payment->fee_drops);
    }
    if (status == EVERGRAM_OK) {
        write_vl(writer, TYPE_BLOB, FIELD_SIGNING_PUB_KEY, public_key, 33);
        status = write_account_id(writer, FIELD_ACCOUNT, account);
    }
    if (status == EVERGRAM_OK) {
        status = write_account_id(writer, FIELD_DESTINATION, payment->destination);
    }
    if (status != EVERGRAM_OK) {
        return status;
    }
    return writer->overflow ? EVERGRAM_ERR_BUFFER_TOO_SMALL : EVERGRAM_OK;
}

/* Appends TxnSignature to the signing data: code 0x00070004, which is where it
 * sorts (after SigningPubKey, before Account). */
static evergram_status_t build_signed_blob(const writer_t *signing_data,
                                           const uint8_t signature[64], writer_t *out) {
    writer_init(out);

    /* The prefix is not part of the blob, and TxnSignature goes right after
     * SigningPubKey — so the signature is inserted rather than appended, or the
     * fields would no longer be in canonical order. */
    const uint8_t *bytes = signing_data->bytes + sizeof(SIGNING_PREFIX);
    size_t length = signing_data->length - sizeof(SIGNING_PREFIX);

    size_t split = 0;
    bool found = false;
    while (split + 3u < length) {
        /* Walk the SigningPubKey blob: its code, its length, its 33 bytes. */
        if (bytes[split] == 0x73u) {
            size_t key_length = bytes[split + 1u] < 192u ? bytes[split + 1u] : 0;
            if (key_length == 33u && split + 2u + key_length <= length) {
                split += 2u + key_length;
                found = true;
                break;
            }
        }
        split++;
    }
    if (!found) {
        return EVERGRAM_ERR_PROTOCOL; /* cannot happen for data we built ourselves */
    }

    write_bytes(out, bytes, split);
    write_vl(out, TYPE_BLOB, FIELD_TXN_SIGNATURE, signature, 64);
    write_bytes(out, bytes + split, length - split);
    return out->overflow ? EVERGRAM_ERR_BUFFER_TOO_SMALL : EVERGRAM_OK;
}

static void to_hex(const uint8_t *bytes, size_t length, char *out, size_t out_size, bool *ok) {
    if (out_size < 2u * length + 1u) {
        *ok = false;
        return;
    }
    static const char digits[] = "0123456789ABCDEF";
    for (size_t i = 0; i < length; i++) {
        out[2u * i] = digits[bytes[i] >> 4];
        out[2u * i + 1u] = digits[bytes[i] & 0x0fu];
    }
    out[2u * length] = '\0';
}

evergram_status_t xahau_sign_payment(const char *private_key_hex, const xahau_payment_t *payment,
                                     char *signing_data_hex, size_t signing_data_size,
                                     char *blob_hex, size_t blob_hex_size, char *hash_hex,
                                     size_t hash_hex_size) {
    if (private_key_hex == NULL || payment == NULL || payment->account == NULL ||
        payment->destination == NULL || blob_hex == NULL || hash_hex == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (strlen(private_key_hex) != 66u) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    /* The identity's private key is "ED" + the 32-byte ed25519 seed. */
    uint8_t seed[32];
    if (sodium_hex2bin(seed, sizeof(seed), private_key_hex + 2u, 64, NULL, NULL, NULL) != 0) {
        sodium_memzero(seed, sizeof(seed));
        return EVERGRAM_ERR_INVALID_ARG;
    }
    /* One derivation serves both the SigningPubKey field and the signature. */
    uint8_t public_key[33];
    uint8_t secret[crypto_sign_SECRETKEYBYTES];
    crypto_sign_seed_keypair(public_key + 1, secret, seed);
    public_key[0] = 0xed; /* XRPL marks an ed25519 key with this prefix */

    writer_t signing_data;
    evergram_status_t status =
        build_signing_data(payment, public_key, payment->account, &signing_data);
    if (status != EVERGRAM_OK) {
        sodium_memzero(secret, sizeof(secret));
        sodium_memzero(seed, sizeof(seed));
        return status;
    }

    if (signing_data_hex != NULL) {
        bool ok = true;
        to_hex(signing_data.bytes, signing_data.length, signing_data_hex, signing_data_size, &ok);
        if (!ok) {
            sodium_memzero(secret, sizeof(secret));
            sodium_memzero(seed, sizeof(seed));
            return EVERGRAM_ERR_BUFFER_TOO_SMALL;
        }
    }

    uint8_t signature[64];
    unsigned long long signature_length = 0;
    crypto_sign_detached(signature, &signature_length, signing_data.bytes, signing_data.length,
                         secret);
    sodium_memzero(secret, sizeof(secret));
    sodium_memzero(seed, sizeof(seed));
    if (signature_length != sizeof(signature)) {
        sodium_memzero(signature, sizeof(signature));
        return EVERGRAM_ERR_CRYPTO;
    }

    writer_t blob;
    status = build_signed_blob(&signing_data, signature, &blob);
    sodium_memzero(signature, sizeof(signature));
    if (status != EVERGRAM_OK) {
        return status;
    }

    /* Cleared first, so a failure never leaves a half-written blob behind. */
    if (blob_hex_size > 0) {
        blob_hex[0] = '\0';
    }
    if (hash_hex_size > 0) {
        hash_hex[0] = '\0';
    }

    bool ok = true;
    to_hex(blob.bytes, blob.length, blob_hex, blob_hex_size, &ok);

    uint8_t digest[crypto_hash_sha512_BYTES];
    crypto_hash_sha512_state state;
    crypto_hash_sha512_init(&state);
    crypto_hash_sha512_update(&state, TXN_PREFIX, sizeof(TXN_PREFIX));
    crypto_hash_sha512_update(&state, blob.bytes, blob.length);
    crypto_hash_sha512_final(&state, digest);
    if (ok) {
        to_hex(digest, 32, hash_hex, hash_hex_size, &ok);
    }
    sodium_memzero(digest, sizeof(digest));
    if (!ok) {
        return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }
    return EVERGRAM_OK;
}
