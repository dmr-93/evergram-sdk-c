#include "relay.h"

#include "evergram.pb-c.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "json.h"

/*
 * Frame payload codec. Content frames reuse e2ee_encrypt/e2ee_decrypt (the
 * same secretbox + base64 pair the chat uses) and wrap the result in the
 * {"nonce","ciphertext"} JSON envelope the protocol expects.
 */

#define RELAY_PLAINTEXT_MAX EVERGRAM_TEXT_SIZE
#define RELAY_ENVELOPE_MAX (RELAY_PLAINTEXT_MAX + 256)

evergram_relay_kind_t evergram_relay_kind_from_wire(int wire_kind) {
    if (wire_kind < 0 || wire_kind > (int)EVERGRAM_RELAY_KIND_CHANNEL_MODE) {
        return EVERGRAM_RELAY_KIND_UNKNOWN;
    }
    return (evergram_relay_kind_t)wire_kind;
}

int evergram_relay_kind_to_wire(evergram_relay_kind_t kind) {
    return (kind == EVERGRAM_RELAY_KIND_UNKNOWN) ? -1 : (int)kind;
}

bool evergram_relay_kind_is_content(evergram_relay_kind_t kind) {
    switch (kind) {
    case EVERGRAM_RELAY_KIND_TEXT:
    case EVERGRAM_RELAY_KIND_REACT:
    case EVERGRAM_RELAY_KIND_EDIT:
    case EVERGRAM_RELAY_KIND_REMOVE:
        return true;
    default:
        return false;
    }
}

void evergram_relay_fill_message(Evergram__RelayMessage *relay, const char *room_token,
                                 evergram_relay_kind_t kind, const char *payload) {
    evergram__relay_message__init(relay);
    relay->room_token = (char *)room_token;

    /* An unmapped kind leaves the field unset: sending a made-up enum value
     * would be worse than sending nothing at all. */
    int wire_kind = evergram_relay_kind_to_wire(kind);
    if (wire_kind >= 0) {
        relay->has_kind = 1;
        relay->kind = (Evergram__RelayMessageKind)wire_kind;
    }
    if (payload != NULL && payload[0] != '\0') {
        relay->has_payload = 1;
        relay->payload.data = (uint8_t *)payload;
        relay->payload.len = strlen(payload);
    }
}

static uint64_t now_ms(void) {
    return evergram_now_ms();
}

/* --- encrypted frames ------------------------------------------------------ */

/* Opens the {"nonce","ciphertext"} envelope into the JSON event behind it. */
static evergram_status_t open_content_frame(const uint8_t sym_key[E2EE_KEY_BYTES],
                                            const char *payload, json_object_t *event) {
    if (sym_key == NULL || payload == NULL || event == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    json_object_t envelope;
    evergram_status_t status = json_parse_flat(payload, &envelope);
    if (status != EVERGRAM_OK) {
        return status;
    }

    const char *nonce = json_get_string(&envelope, "nonce");
    const char *ciphertext = json_get_string(&envelope, "ciphertext");
    if (nonce == NULL || ciphertext == NULL) {
        json_object_dispose(&envelope);
        return EVERGRAM_ERR_ENCODING;
    }

    char plaintext[RELAY_PLAINTEXT_MAX];
    size_t plaintext_len = 0;
    status = e2ee_decrypt(sym_key, nonce, ciphertext, plaintext, sizeof(plaintext),
                          &plaintext_len);
    json_object_dispose(&envelope);
    if (status != EVERGRAM_OK) {
        return status;
    }

    status = json_parse_flat(plaintext, event);
    sodium_memzero(plaintext, sizeof(plaintext));
    return status;
}

/* Seals a JSON event into the {"nonce","ciphertext"} envelope. */
static evergram_status_t seal_content_frame(const uint8_t sym_key[E2EE_KEY_BYTES],
                                            const json_writer_t *event, char *payload,
                                            size_t payload_size) {
    char nonce_b64[E2EE_NONCE_B64_SIZE];
    char ciphertext_b64[E2EE_CIPHERTEXT_B64_SIZE(RELAY_PLAINTEXT_MAX)];

    evergram_status_t status = e2ee_encrypt(sym_key, event->buffer, nonce_b64, sizeof(nonce_b64),
                                            ciphertext_b64, sizeof(ciphertext_b64));
    if (status != EVERGRAM_OK) {
        return status;
    }

    json_writer_t writer;
    json_writer_init(&writer, payload, payload_size);
    json_writer_begin_object(&writer);
    json_writer_field_string(&writer, "nonce", nonce_b64);
    json_writer_field_string(&writer, "ciphertext", ciphertext_b64);
    json_writer_end_object(&writer);

    sodium_memzero(ciphertext_b64, sizeof(ciphertext_b64));
    return json_writer_ok(&writer) ? EVERGRAM_OK : EVERGRAM_ERR_BUFFER_TOO_SMALL;
}

static evergram_status_t parse_uint64_field(const json_object_t *event, const char *key,
                                            uint64_t fallback, uint64_t *out) {
    double number = 0;
    if (json_get_number(event, key, &number) && number > 0) {
        *out = (uint64_t)number;
        return EVERGRAM_OK;
    }
    *out = fallback;
    return EVERGRAM_OK;
}

evergram_status_t evergram_relay_build_text(const uint8_t sym_key[E2EE_KEY_BYTES],
                                            const char *sender, const char *text, char *payload,
                                            size_t payload_size,
                                            evergram_relay_text_t *event_out) {
    if (sym_key == NULL || sender == NULL || text == NULL || payload == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    evergram_relay_text_t event;
    memset(&event, 0, sizeof(event));
    {
        uint8_t random[32];
        randombytes_buf(random, sizeof(random));
        sodium_bin2hex(event.msg_id, sizeof(event.msg_id), random, sizeof(random));
        sodium_memzero(random, sizeof(random));
    }
    snprintf(event.sender, sizeof(event.sender), "%s", sender);
    snprintf(event.text, sizeof(event.text), "%s", text);
    event.timestamp_ms = now_ms();

    char json[RELAY_ENVELOPE_MAX];
    json_writer_t writer;
    json_writer_init(&writer, json, sizeof(json));
    json_writer_begin_object(&writer);
    json_writer_field_string(&writer, "msgId", event.msg_id);
    json_writer_field_string(&writer, "sender", event.sender);
    json_writer_field_string(&writer, "text", event.text);
    json_writer_field_number(&writer, "ts", (double)event.timestamp_ms);
    json_writer_end_object(&writer);
    if (!json_writer_ok(&writer)) {
        return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }

    evergram_status_t status = seal_content_frame(sym_key, &writer, payload, payload_size);
    if (status == EVERGRAM_OK && event_out != NULL) {
        *event_out = event;
    }
    return status;
}

evergram_status_t evergram_relay_build_react(const uint8_t sym_key[E2EE_KEY_BYTES],
                                             const char *msg_id, const char *emoji, bool removed,
                                             char *payload, size_t payload_size) {
    if (sym_key == NULL || msg_id == NULL || payload == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    char json[RELAY_ENVELOPE_MAX];
    json_writer_t writer;
    json_writer_init(&writer, json, sizeof(json));
    json_writer_begin_object(&writer);
    json_writer_field_string(&writer, "msgId", msg_id);
    if (removed) {
        json_writer_field_null(&writer, "emoji");
    } else {
        json_writer_field_string(&writer, "emoji", emoji != NULL ? emoji : "");
    }
    json_writer_end_object(&writer);
    if (!json_writer_ok(&writer)) {
        return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }

    return seal_content_frame(sym_key, &writer, payload, payload_size);
}

evergram_status_t evergram_relay_build_edit(const uint8_t sym_key[E2EE_KEY_BYTES],
                                            const char *msg_id, const char *text, char *payload,
                                            size_t payload_size) {
    if (sym_key == NULL || msg_id == NULL || text == NULL || payload == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    char json[RELAY_ENVELOPE_MAX];
    json_writer_t writer;
    json_writer_init(&writer, json, sizeof(json));
    json_writer_begin_object(&writer);
    json_writer_field_string(&writer, "msgId", msg_id);
    json_writer_field_string(&writer, "text", text);
    json_writer_field_number(&writer, "editedAt", (double)now_ms());
    json_writer_end_object(&writer);
    if (!json_writer_ok(&writer)) {
        return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }

    return seal_content_frame(sym_key, &writer, payload, payload_size);
}

evergram_status_t evergram_relay_build_remove(const uint8_t sym_key[E2EE_KEY_BYTES],
                                              const char *msg_id, char *payload,
                                              size_t payload_size) {
    if (sym_key == NULL || msg_id == NULL || payload == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    char json[RELAY_ENVELOPE_MAX];
    json_writer_t writer;
    json_writer_init(&writer, json, sizeof(json));
    json_writer_begin_object(&writer);
    json_writer_field_string(&writer, "msgId", msg_id);
    json_writer_field_number(&writer, "removedAt", (double)now_ms());
    json_writer_end_object(&writer);
    if (!json_writer_ok(&writer)) {
        return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }

    return seal_content_frame(sym_key, &writer, payload, payload_size);
}

evergram_status_t evergram_relay_parse_text(const uint8_t sym_key[E2EE_KEY_BYTES],
                                            const char *payload, evergram_relay_text_t *out) {
    if (out == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    memset(out, 0, sizeof(*out));

    json_object_t event;
    evergram_status_t status = open_content_frame(sym_key, payload, &event);
    if (status != EVERGRAM_OK) {
        return status;
    }

    const char *text = json_get_string(&event, "text");
    if (text == NULL) {
        json_object_dispose(&event);
        return EVERGRAM_ERR_ENCODING;
    }

    evergram_copy_bounded(out->msg_id, sizeof(out->msg_id),
                          json_get_string(&event, "msgId") != NULL
                              ? json_get_string(&event, "msgId")
                              : "");
    evergram_copy_bounded(out->sender, sizeof(out->sender),
                          json_get_string(&event, "sender") != NULL
                              ? json_get_string(&event, "sender")
                              : "");
    evergram_copy_bounded(out->text, sizeof(out->text), text);
    parse_uint64_field(&event, "ts", 0, &out->timestamp_ms);

    json_object_dispose(&event);
    return EVERGRAM_OK;
}

evergram_status_t evergram_relay_parse_react(const uint8_t sym_key[E2EE_KEY_BYTES],
                                             const char *payload, evergram_relay_react_t *out) {
    if (out == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    memset(out, 0, sizeof(*out));

    json_object_t event;
    evergram_status_t status = open_content_frame(sym_key, payload, &event);
    if (status != EVERGRAM_OK) {
        return status;
    }

    const char *msg_id = json_get_string(&event, "msgId");
    if (msg_id == NULL) {
        json_object_dispose(&event);
        return EVERGRAM_ERR_ENCODING;
    }

    evergram_copy_bounded(out->msg_id, sizeof(out->msg_id), msg_id);
    const char *emoji = json_get_string(&event, "emoji");
    if (emoji == NULL) {
        out->removed = true; /* null emoji means the reaction was cleared */
    } else {
        evergram_copy_bounded(out->emoji, sizeof(out->emoji), emoji);
    }

    json_object_dispose(&event);
    return EVERGRAM_OK;
}

evergram_status_t evergram_relay_parse_edit(const uint8_t sym_key[E2EE_KEY_BYTES],
                                            const char *payload, evergram_relay_edit_t *out) {
    if (out == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    memset(out, 0, sizeof(*out));

    json_object_t event;
    evergram_status_t status = open_content_frame(sym_key, payload, &event);
    if (status != EVERGRAM_OK) {
        return status;
    }

    const char *msg_id = json_get_string(&event, "msgId");
    const char *text = json_get_string(&event, "text");
    if (msg_id == NULL || text == NULL) {
        json_object_dispose(&event);
        return EVERGRAM_ERR_ENCODING;
    }

    evergram_copy_bounded(out->msg_id, sizeof(out->msg_id), msg_id);
    evergram_copy_bounded(out->text, sizeof(out->text), text);
    parse_uint64_field(&event, "editedAt", 0, &out->edited_at_ms);

    json_object_dispose(&event);
    return EVERGRAM_OK;
}

evergram_status_t evergram_relay_parse_remove(const uint8_t sym_key[E2EE_KEY_BYTES],
                                              const char *payload, evergram_relay_remove_t *out) {
    if (out == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    memset(out, 0, sizeof(*out));

    json_object_t event;
    evergram_status_t status = open_content_frame(sym_key, payload, &event);
    if (status != EVERGRAM_OK) {
        return status;
    }

    const char *msg_id = json_get_string(&event, "msgId");
    if (msg_id == NULL) {
        json_object_dispose(&event);
        return EVERGRAM_ERR_ENCODING;
    }

    evergram_copy_bounded(out->msg_id, sizeof(out->msg_id), msg_id);
    parse_uint64_field(&event, "removedAt", 0, &out->removed_at_ms);

    json_object_dispose(&event);
    return EVERGRAM_OK;
}

/* --- liveness frames ------------------------------------------------------- */

evergram_status_t evergram_relay_build_typing(bool is_typing, const char *sender, char *payload,
                                              size_t payload_size) {
    if (payload == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    json_writer_t writer;
    json_writer_init(&writer, payload, payload_size);
    json_writer_begin_object(&writer);
    json_writer_field_bool(&writer, "isTyping", is_typing);
    if (sender != NULL && sender[0] != '\0') {
        json_writer_field_string(&writer, "sender", sender);
    }
    json_writer_end_object(&writer);

    return json_writer_ok(&writer) ? EVERGRAM_OK : EVERGRAM_ERR_BUFFER_TOO_SMALL;
}

evergram_status_t evergram_relay_build_presence(const char *sender, const char *previous_sender,
                                                char *payload, size_t payload_size) {
    if (sender == NULL || payload == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    json_writer_t writer;
    json_writer_init(&writer, payload, payload_size);
    json_writer_begin_object(&writer);
    json_writer_field_string(&writer, "sender", sender);
    if (previous_sender != NULL && previous_sender[0] != '\0') {
        json_writer_field_string(&writer, "previousSender", previous_sender);
    }
    json_writer_end_object(&writer);

    return json_writer_ok(&writer) ? EVERGRAM_OK : EVERGRAM_ERR_BUFFER_TOO_SMALL;
}

evergram_status_t evergram_relay_parse_typing(const char *payload, evergram_relay_typing_t *out) {
    if (payload == NULL || out == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    memset(out, 0, sizeof(*out));

    json_object_t event;
    evergram_status_t status = json_parse_flat(payload, &event);
    if (status != EVERGRAM_OK) {
        return status;
    }

    bool is_typing = false;
    if (!json_get_bool(&event, "isTyping", &is_typing)) {
        json_object_dispose(&event);
        return EVERGRAM_ERR_ENCODING;
    }
    out->is_typing = is_typing;

    const char *sender = json_get_string(&event, "sender");
    if (sender != NULL) {
        evergram_copy_bounded(out->sender, sizeof(out->sender), sender);
    }

    json_object_dispose(&event);
    return EVERGRAM_OK;
}

evergram_status_t evergram_relay_parse_presence(const char *payload,
                                                evergram_relay_presence_t *out) {
    if (payload == NULL || out == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    memset(out, 0, sizeof(*out));

    json_object_t event;
    evergram_status_t status = json_parse_flat(payload, &event);
    if (status != EVERGRAM_OK) {
        return status;
    }

    const char *sender = json_get_string(&event, "sender");
    if (sender == NULL || sender[0] == '\0') {
        json_object_dispose(&event);
        return EVERGRAM_ERR_ENCODING;
    }
    evergram_copy_bounded(out->sender, sizeof(out->sender), sender);

    const char *previous = json_get_string(&event, "previousSender");
    if (previous != NULL && previous[0] != '\0') {
        evergram_copy_bounded(out->previous_sender, sizeof(out->previous_sender), previous);
        out->has_previous = true;
    }

    json_object_dispose(&event);
    return EVERGRAM_OK;
}

evergram_status_t evergram_relay_parse_moderation(const char *payload,
                                                  evergram_relay_moderation_t *out) {
    if (payload == NULL || out == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    memset(out, 0, sizeof(*out));

    json_object_t event;
    evergram_status_t status = json_parse_flat(payload, &event);
    if (status != EVERGRAM_OK) {
        return status;
    }

    if (!json_get_bool(&event, "moderated", &out->moderated)) {
        json_object_dispose(&event);
        return EVERGRAM_ERR_ENCODING;
    }

    size_t count = 0;
    const char *const *items = json_get_string_array(&event, "ops", &count);
    if (items != NULL && count > 0) {
        out->ops = calloc(count, sizeof(*out->ops));
        if (out->ops == NULL) {
            json_object_dispose(&event);
            return EVERGRAM_ERR_NO_MEMORY;
        }
        for (size_t i = 0; i < count; i++) {
            out->ops[i] = strdup(items[i] != NULL ? items[i] : "");
            if (out->ops[i] == NULL) {
                /* Publish the partial count so dispose() releases what exists. */
                out->ops_count = i;
                evergram_relay_moderation_dispose(out);
                json_object_dispose(&event);
                return EVERGRAM_ERR_NO_MEMORY;
            }
        }
        out->ops_count = count;
    }

    items = json_get_string_array(&event, "voiced", &count);
    if (items != NULL && count > 0) {
        out->voiced = calloc(count, sizeof(*out->voiced));
        if (out->voiced == NULL) {
            evergram_relay_moderation_dispose(out);
            json_object_dispose(&event);
            return EVERGRAM_ERR_NO_MEMORY;
        }
        for (size_t i = 0; i < count; i++) {
            out->voiced[i] = strdup(items[i] != NULL ? items[i] : "");
            if (out->voiced[i] == NULL) {
                out->voiced_count = i;
                evergram_relay_moderation_dispose(out);
                json_object_dispose(&event);
                return EVERGRAM_ERR_NO_MEMORY;
            }
        }
        out->voiced_count = count;
    }

    json_object_dispose(&event);
    return EVERGRAM_OK;
}

void evergram_relay_moderation_dispose(evergram_relay_moderation_t *state) {
    if (state == NULL) {
        return;
    }
    if (state->ops != NULL) {
        for (size_t i = 0; i < state->ops_count; i++) {
            free(state->ops[i]);
        }
        free(state->ops);
    }
    if (state->voiced != NULL) {
        for (size_t i = 0; i < state->voiced_count; i++) {
            free(state->voiced[i]);
        }
        free(state->voiced);
    }
    memset(state, 0, sizeof(*state));
}

evergram_status_t evergram_relay_parse_left(const char *payload, uint64_t *deadline_ms_out) {
    if (deadline_ms_out != NULL) {
        *deadline_ms_out = 0;
    }
    if (payload == NULL || payload[0] == '\0') {
        return EVERGRAM_OK; /* no payload means "no deadline known" */
    }

    json_object_t event;
    if (json_parse_flat(payload, &event) != EVERGRAM_OK) {
        return EVERGRAM_OK;
    }

    if (deadline_ms_out != NULL) {
        parse_uint64_field(&event, "deadlineAt", 0, deadline_ms_out);
    }
    json_object_dispose(&event);
    return EVERGRAM_OK;
}

evergram_status_t evergram_relay_parse_kicked(const char *payload,
                                              evergram_relay_kicked_t *out) {
    if (out == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    out->banned = false;

    if (payload == NULL || payload[0] == '\0') {
        return EVERGRAM_OK;
    }

    json_object_t event;
    if (json_parse_flat(payload, &event) != EVERGRAM_OK) {
        return EVERGRAM_OK; /* unparseable reason is treated as a plain kick */
    }

    const char *reason = json_get_string(&event, "reason");
    out->banned = reason != NULL && strcmp(reason, "banned") == 0;
    json_object_dispose(&event);
    return EVERGRAM_OK;
}
