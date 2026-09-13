#include <sodium.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "base64.h"
#include "evergram.h"
#include "internal.h"
#include "json.h"

/*
 * Content classification for decrypted bodies, mirroring the TypeScript SDK's
 * parseMessageContent(): anything that is not a JSON object is plain text, and
 * JSON envelopes are discriminated by their "type" string.
 *
 * Both directions live here: evergram_message_content_type() classifies a body
 * without copying anything, evergram_message_content_parse() decodes the
 * structured fields, and the *_build() functions produce the exact envelopes
 * the TypeScript SDK's message-builders.ts does.
 *
 * Flat JSON is all the protocol needs, so json.c's reader is enough — a nested
 * object is reported as malformed rather than half-read.
 */

#define CONTENT_TYPE_VALUE_MAX 32

/* Finds "field": "<value>" in a flat JSON object. Returns false when absent. */
static bool extract_string_field(const char *json, const char *field, char *out, size_t out_size) {
    size_t field_len = strlen(field);
    const char *cursor = json;

    while ((cursor = strchr(cursor, '"')) != NULL) {
        const char *name = cursor + 1;
        const char *name_end = strchr(name, '"');
        if (name_end == NULL) {
            return false;
        }

        size_t name_len = (size_t)(name_end - name);
        const char *after = name_end + 1;

        if (name_len != field_len || strncmp(name, field, field_len) != 0) {
            cursor = after;
            continue;
        }

        while (*after == ' ' || *after == '\t') {
            after++;
        }
        if (*after != ':') {
            cursor = after;
            continue;
        }
        after++;
        while (*after == ' ' || *after == '\t') {
            after++;
        }
        if (*after != '"') {
            return false; /* the field is not a string */
        }
        after++;

        size_t written = 0;
        while (after[written] != '\0' && after[written] != '"' && written + 1u < out_size) {
            out[written] = after[written];
            written++;
        }
        out[written] = '\0';
        return after[written] == '"';
    }

    return false;
}

evergram_content_type_t evergram_message_content_type(const char *text) {
    if (text == NULL || text[0] != '{') {
        return EVERGRAM_CONTENT_TEXT;
    }

    char value[CONTENT_TYPE_VALUE_MAX];
    value[0] = '\0';
    if (!extract_string_field(text, "type", value, sizeof(value))) {
        return EVERGRAM_CONTENT_UNKNOWN;
    }

    if (strcmp(value, "text") == 0) {
        return EVERGRAM_CONTENT_TEXT;
    }
    if (strcmp(value, "audio") == 0) {
        return EVERGRAM_CONTENT_AUDIO;
    }
    if (strcmp(value, "payment_request") == 0) {
        return EVERGRAM_CONTENT_PAYMENT_REQUEST;
    }
    if (strcmp(value, "payment_receipt") == 0) {
        return EVERGRAM_CONTENT_PAYMENT_RECEIPT;
    }
    if (strcmp(value, "payment_sent") == 0) {
        return EVERGRAM_CONTENT_PAYMENT_SENT;
    }
    return EVERGRAM_CONTENT_UNKNOWN;
}

/* --- structured parsing ---------------------------------------------------- */

/*
 * The audio payload is the one field handed out without a copy: it is base64,
 * which contains nothing that JSON would escape, so a plain pointer into the
 * input is both safe and free. Everything else is copied into the caller's
 * fixed-size struct, so the result cannot dangle.
 */
static const char *borrow_string(const char *text, const char *key) {
    size_t key_len = strlen(key);
    const char *cursor = text;

    while ((cursor = strchr(cursor, '"')) != NULL) {
        const char *name = cursor + 1;
        const char *name_end = strchr(name, '"');
        if (name_end == NULL) {
            return NULL;
        }

        const char *after = name_end + 1;
        if ((size_t)(name_end - name) == key_len && strncmp(name, key, key_len) == 0) {
            while (*after == ' ' || *after == '\t') {
                after++;
            }
            if (*after == ':') {
                after++;
                while (*after == ' ' || *after == '\t') {
                    after++;
                }
                return *after == '"' ? after + 1 : NULL;
            }
        }
        cursor = after;
    }
    return NULL;
}

static void copy_field(const json_object_t *object, const char *key, char *out, size_t out_size) {
    const char *value = json_get_string(object, key);
    out[0] = '\0';
    if (value != NULL) {
        evergram_copy_bounded(out, out_size, value);
    }
}

static void copy_note(const json_object_t *object, bool *has_note, char *out, size_t out_size) {
    const char *value = json_get_string(object, "note");
    out[0] = '\0';
    *has_note = value != NULL && value[0] != '\0';
    if (*has_note) {
        evergram_copy_bounded(out, out_size, value);
    }
}

static void parse_payment_request(const json_object_t *object, evergram_payment_request_t *out) {
    memset(out, 0, sizeof(*out));
    copy_field(object, "requestId", out->request_id, sizeof(out->request_id));
    copy_field(object, "amount", out->amount, sizeof(out->amount));
    copy_field(object, "currency", out->currency, sizeof(out->currency));
    copy_field(object, "currencyId", out->currency_id, sizeof(out->currency_id));
    if (out->currency_id[0] == '\0') {
        /* Legacy messages predate multi-currency support. */
        evergram_copy_bounded(out->currency_id, sizeof(out->currency_id), "XAH");
    }
    copy_note(object, &out->has_note, out->note, sizeof(out->note));
    copy_field(object, "to", out->to, sizeof(out->to));
    copy_field(object, "toIdentityKey", out->to_identity_key, sizeof(out->to_identity_key));
}

static void parse_payment_receipt(const json_object_t *object, evergram_payment_receipt_t *out) {
    memset(out, 0, sizeof(*out));
    copy_field(object, "requestId", out->request_id, sizeof(out->request_id));
    copy_field(object, "txHash", out->tx_hash, sizeof(out->tx_hash));
    copy_field(object, "amount", out->amount, sizeof(out->amount));
    copy_field(object, "currency", out->currency, sizeof(out->currency));
    copy_field(object, "currencyId", out->currency_id, sizeof(out->currency_id));
    if (out->currency_id[0] == '\0') {
        /* Legacy messages predate multi-currency support. */
        evergram_copy_bounded(out->currency_id, sizeof(out->currency_id), "XAH");
    }
    copy_field(object, "from", out->from, sizeof(out->from));
    copy_field(object, "fromIdentityKey", out->from_identity_key, sizeof(out->from_identity_key));
}

static void parse_payment_sent(const json_object_t *object, evergram_payment_sent_t *out) {
    memset(out, 0, sizeof(*out));
    copy_field(object, "id", out->id, sizeof(out->id));
    copy_field(object, "txHash", out->tx_hash, sizeof(out->tx_hash));
    copy_field(object, "amount", out->amount, sizeof(out->amount));
    copy_field(object, "currency", out->currency, sizeof(out->currency));
    copy_field(object, "currencyId", out->currency_id, sizeof(out->currency_id));
    if (out->currency_id[0] == '\0') {
        /* Legacy messages predate multi-currency support. */
        evergram_copy_bounded(out->currency_id, sizeof(out->currency_id), "XAH");
    }
    copy_note(object, &out->has_note, out->note, sizeof(out->note));
    copy_field(object, "from", out->from, sizeof(out->from));
    copy_field(object, "fromIdentityKey", out->from_identity_key, sizeof(out->from_identity_key));
    copy_field(object, "to", out->to, sizeof(out->to));
    copy_field(object, "toIdentityKey", out->to_identity_key, sizeof(out->to_identity_key));
}

evergram_status_t evergram_message_content_parse(const char *text, evergram_content_t *out) {
    if (out == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    memset(out, 0, sizeof(*out));

    if (text == NULL) {
        out->type = EVERGRAM_CONTENT_TEXT;
        out->text = "";
        return EVERGRAM_OK;
    }

    out->raw = text;
    out->text = text; /* usable for display for every non-payment/audio body */
    out->type = evergram_message_content_type(text);

    /*
     * Anything that is not a recognized envelope is text, exactly as the
     * reference SDK's parseMessageContent() decides — including a body that
     * merely starts with '{'. An unrecognized *type* is kept distinct as
     * EVERGRAM_CONTENT_UNKNOWN, which is strictly more information than the
     * reference SDK keeps; `text` is still set for it.
     */
    if (out->type == EVERGRAM_CONTENT_TEXT || out->type == EVERGRAM_CONTENT_UNKNOWN) {
        return EVERGRAM_OK;
    }

    json_object_t object;
    if (json_parse_flat(text, &object) != EVERGRAM_OK) {
        /* Recognized discriminator, unreadable body: fall back to text rather
         * than grant anything on a half-read receipt. */
        out->type = EVERGRAM_CONTENT_TEXT;
        return EVERGRAM_OK;
    }

    switch (out->type) {
    case EVERGRAM_CONTENT_PAYMENT_REQUEST:
        parse_payment_request(&object, &out->payment_request);
        break;
    case EVERGRAM_CONTENT_PAYMENT_RECEIPT:
        parse_payment_receipt(&object, &out->payment_receipt);
        break;
    case EVERGRAM_CONTENT_PAYMENT_SENT:
        parse_payment_sent(&object, &out->payment_sent);
        break;
    case EVERGRAM_CONTENT_AUDIO: {
        const char *payload = json_get_string(&object, "payload");
        copy_field(&object, "mimeType", out->audio.mime_type, sizeof(out->audio.mime_type));
        if (out->audio.mime_type[0] == '\0') {
            /* Some senders use the snake_case spelling. */
            copy_field(&object, "mime_type", out->audio.mime_type, sizeof(out->audio.mime_type));
        }
        double number = 0;
        if (json_get_number(&object, "durationMs", &number) && number > 0) {
            out->audio.duration_ms = (uint64_t)number;
        }
        if (json_get_number(&object, "size", &number) && number > 0) {
            out->audio.size = (size_t)number;
        }
        out->audio.payload_b64 = payload != NULL ? borrow_string(text, "payload") : NULL;
        break;
    }
    default:
        break;
    }

    json_object_dispose(&object);
    return EVERGRAM_OK;
}

/* --- builders -------------------------------------------------------------- */

/* Copies a built envelope out, failing loudly instead of truncating. */
static evergram_status_t finish(json_writer_t *writer, char *out, size_t out_size) {
    if (!json_writer_ok(writer)) {
        if (out_size > 0) {
            out[0] = '\0';
        }
        return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }
    if (writer->length >= out_size) {
        out[0] = '\0';
        return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }
    return EVERGRAM_OK;
}

evergram_status_t evergram_payment_request_build(const evergram_payment_request_t *request, char *out,
                                                size_t out_size) {
    if (request == NULL || out == NULL || out_size == 0) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (request->request_id[0] == '\0' || request->amount[0] == '\0' ||
        request->currency[0] == '\0') {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    json_writer_t writer;
    json_writer_init(&writer, out, out_size);
    json_writer_begin_object(&writer);
    json_writer_field_string(&writer, "type", "payment_request");
    json_writer_field_string(&writer, "requestId", request->request_id);
    json_writer_field_string(&writer, "amount", request->amount);
    json_writer_field_string(&writer, "currency", request->currency);
    json_writer_field_string(&writer, "currencyId",
                             request->currency_id[0] != '\0' ? request->currency_id : "XAH");
    if (request->has_note && request->note[0] != '\0') {
        json_writer_field_string(&writer, "note", request->note);
    }
    json_writer_field_string(&writer, "to", request->to);
    json_writer_field_string(&writer, "toIdentityKey", request->to_identity_key);
    json_writer_end_object(&writer);
    return finish(&writer, out, out_size);
}

evergram_status_t evergram_payment_receipt_build(const evergram_payment_receipt_t *receipt, char *out,
                                                size_t out_size) {
    if (receipt == NULL || out == NULL || out_size == 0) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (receipt->request_id[0] == '\0' || receipt->tx_hash[0] == '\0') {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    json_writer_t writer;
    json_writer_init(&writer, out, out_size);
    json_writer_begin_object(&writer);
    json_writer_field_string(&writer, "type", "payment_receipt");
    json_writer_field_string(&writer, "requestId", receipt->request_id);
    json_writer_field_string(&writer, "txHash", receipt->tx_hash);
    json_writer_field_string(&writer, "amount", receipt->amount);
    json_writer_field_string(&writer, "currency", receipt->currency);
    json_writer_field_string(&writer, "currencyId",
                             receipt->currency_id[0] != '\0' ? receipt->currency_id : "XAH");
    json_writer_field_string(&writer, "from", receipt->from);
    json_writer_field_string(&writer, "fromIdentityKey", receipt->from_identity_key);
    json_writer_end_object(&writer);
    return finish(&writer, out, out_size);
}

evergram_status_t evergram_payment_sent_build(const evergram_payment_sent_t *sent, char *out,
                                             size_t out_size) {
    if (sent == NULL || out == NULL || out_size == 0) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (sent->id[0] == '\0' || sent->tx_hash[0] == '\0') {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    json_writer_t writer;
    json_writer_init(&writer, out, out_size);
    json_writer_begin_object(&writer);
    json_writer_field_string(&writer, "type", "payment_sent");
    json_writer_field_string(&writer, "id", sent->id);
    json_writer_field_string(&writer, "txHash", sent->tx_hash);
    json_writer_field_string(&writer, "amount", sent->amount);
    json_writer_field_string(&writer, "currency", sent->currency);
    json_writer_field_string(&writer, "currencyId",
                             sent->currency_id[0] != '\0' ? sent->currency_id : "XAH");
    if (sent->has_note && sent->note[0] != '\0') {
        json_writer_field_string(&writer, "note", sent->note);
    }
    json_writer_field_string(&writer, "from", sent->from);
    json_writer_field_string(&writer, "fromIdentityKey", sent->from_identity_key);
    json_writer_field_string(&writer, "to", sent->to);
    json_writer_field_string(&writer, "toIdentityKey", sent->to_identity_key);
    json_writer_end_object(&writer);
    return finish(&writer, out, out_size);
}

/* Decoded length of a padded base64 string, without allocating. */
static size_t base64_decoded_size(const char *text) {
    size_t length = strlen(text);
    if (length == 0) {
        return 0;
    }

    size_t padding = 0;
    while (padding < 2u && length > padding && text[length - 1u - padding] == '=') {
        padding++;
    }
    return (length / 4u) * 3u - padding;
}

evergram_status_t evergram_audio_message_build(const char *mime_type, uint64_t duration_ms,
                                              const char *payload_b64, char *out, size_t out_size) {
    if (mime_type == NULL || mime_type[0] == '\0' || payload_b64 == NULL || out == NULL ||
        out_size == 0) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    json_writer_t writer;
    json_writer_init(&writer, out, out_size);
    json_writer_begin_object(&writer);
    json_writer_field_string(&writer, "type", "audio");
    json_writer_field_string(&writer, "mimeType", mime_type);
    json_writer_field_number(&writer, "durationMs", (double)duration_ms);
    /*
     * `size` is the decoded byte count, not the base64 length: the reference SDK
     * stores the byte length it was handed, so the padding has to be discounted
     * or every audio message would claim three bytes too many.
     */
    json_writer_field_number(&writer, "size", (double)base64_decoded_size(payload_b64));
    json_writer_field_string(&writer, "payload", payload_b64);
    json_writer_end_object(&writer);
    return finish(&writer, out, out_size);
}

evergram_status_t evergram_new_request_id(char *out, size_t out_size) {
    if (out == NULL || out_size < EVERGRAM_REQUEST_ID_SIZE) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    uint8_t bytes[16];
    randombytes_buf(bytes, sizeof(bytes));
    bytes[6] = (uint8_t)((bytes[6] & 0x0f) | 0x40); /* version 4 */
    bytes[8] = (uint8_t)((bytes[8] & 0x3f) | 0x80); /* variant 1 */

    snprintf(out, out_size,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", bytes[0],
             bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9],
             bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
    sodium_memzero(bytes, sizeof(bytes));
    return EVERGRAM_OK;
}
