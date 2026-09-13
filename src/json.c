#include "json.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Flat-object JSON reader/writer. See json.h for the scope and ownership rules.
 * Numbers are read with strtod and written back without a decimal point when
 * they are integral, which is how the protocol's timestamps travel.
 */

typedef struct {
    const char *cursor;
} reader_t;

static void skip_whitespace(reader_t *reader) {
    while (*reader->cursor == ' ' || *reader->cursor == '\t' || *reader->cursor == '\n' ||
           *reader->cursor == '\r') {
        reader->cursor++;
    }
}

/* Grows the heap buffer so `extra` more bytes plus a terminator fit. */
static bool reserve_bytes(char **buffer, size_t *capacity, size_t *length, size_t extra) {
    if (*length + extra + 1u <= *capacity) {
        return true;
    }

    size_t capacity_next = (*capacity ? *capacity : 32u) * 2u;
    while (capacity_next < *length + extra + 1u) {
        capacity_next *= 2u;
    }

    char *grown = realloc(*buffer, capacity_next);
    if (grown == NULL) {
        return false;
    }
    *buffer = grown;
    *capacity = capacity_next;
    return true;
}

static bool append_bytes(char **buffer, size_t *capacity, size_t *length,
                         const unsigned char *data, size_t size) {
    if (!reserve_bytes(buffer, capacity, length, size)) {
        return false;
    }
    memcpy(*buffer + *length, data, size);
    *length += size;
    (*buffer)[*length] = '\0';
    return true;
}

/* Appends one code point as UTF-8. Only escape sequences need this: raw bytes
 * are copied verbatim so already-UTF-8 text is never re-encoded. */
static bool append_utf8(char **buffer, size_t *capacity, size_t *length, unsigned int code_point) {
    unsigned char encoded[4];
    size_t size;

    if (code_point < 0x80u) {
        encoded[0] = (unsigned char)code_point;
        size = 1;
    } else if (code_point < 0x800u) {
        encoded[0] = (unsigned char)(0xC0u | (code_point >> 6));
        encoded[1] = (unsigned char)(0x80u | (code_point & 0x3Fu));
        size = 2;
    } else if (code_point < 0x10000u) {
        encoded[0] = (unsigned char)(0xE0u | (code_point >> 12));
        encoded[1] = (unsigned char)(0x80u | ((code_point >> 6) & 0x3Fu));
        encoded[2] = (unsigned char)(0x80u | (code_point & 0x3Fu));
        size = 3;
    } else {
        encoded[0] = (unsigned char)(0xF0u | (code_point >> 18));
        encoded[1] = (unsigned char)(0x80u | ((code_point >> 12) & 0x3Fu));
        encoded[2] = (unsigned char)(0x80u | ((code_point >> 6) & 0x3Fu));
        encoded[3] = (unsigned char)(0x80u | (code_point & 0x3Fu));
        size = 4;
    }

    return append_bytes(buffer, capacity, length, encoded, size);
}

static int hex_digit(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static bool read_hex4(reader_t *reader, unsigned int *out) {
    unsigned int value = 0;
    for (int i = 0; i < 4; i++) {
        int digit = hex_digit(reader->cursor[i]);
        if (digit < 0) {
            return false;
        }
        value = (value << 4) | (unsigned int)digit;
    }
    reader->cursor += 4;
    *out = value;
    return true;
}

/* Reads a quoted string, unescaping it into a fresh heap buffer. */
static evergram_status_t read_string(reader_t *reader, char **out) {
    if (*reader->cursor != '"') {
        return EVERGRAM_ERR_ENCODING;
    }
    reader->cursor++;

    char *buffer = NULL;
    size_t capacity = 0;
    size_t length = 0;

    while (*reader->cursor != '\0' && *reader->cursor != '"') {
        /* Raw bytes pass through untouched: the payload is already UTF-8. */
        if (*reader->cursor != '\\') {
            unsigned char raw = (unsigned char)*reader->cursor;
            if (!append_bytes(&buffer, &capacity, &length, &raw, 1)) {
                free(buffer);
                return EVERGRAM_ERR_NO_MEMORY;
            }
            reader->cursor++;
            continue;
        }

        reader->cursor++;
        unsigned int code_point = 0;
        char escape = *reader->cursor;
        bool escape_consumed = false;

        switch (escape) {
        case '"':
        case '\\':
        case '/':
            code_point = (unsigned char)escape;
            break;
        case 'b':
            code_point = '\b';
            break;
        case 'f':
            code_point = '\f';
            break;
        case 'n':
            code_point = '\n';
            break;
        case 'r':
            code_point = '\r';
            break;
        case 't':
            code_point = '\t';
            break;
        case 'u': {
            reader->cursor++;
            unsigned int high = 0;
            if (!read_hex4(reader, &high)) {
                free(buffer);
                return EVERGRAM_ERR_ENCODING;
            }
            /* Surrogate pair: combine with the low half when present. */
            if (high >= 0xD800u && high <= 0xDBFFu && reader->cursor[0] == '\\' &&
                reader->cursor[1] == 'u') {
                reader->cursor += 2;
                unsigned int low = 0;
                if (!read_hex4(reader, &low)) {
                    free(buffer);
                    return EVERGRAM_ERR_ENCODING;
                }
                code_point = 0x10000u + ((high - 0xD800u) << 10) + (low - 0xDC00u);
            } else {
                code_point = high;
            }
            /* \uXXXX already advanced the cursor past the whole escape. */
            escape_consumed = true;
            break;
        }
        default:
            free(buffer);
            return EVERGRAM_ERR_ENCODING;
        }

        if (!append_utf8(&buffer, &capacity, &length, code_point)) {
            free(buffer);
            return EVERGRAM_ERR_NO_MEMORY;
        }
        if (!escape_consumed && *reader->cursor != '\0') {
            reader->cursor++;
        }
    }

    if (*reader->cursor != '"') {
        free(buffer);
        return EVERGRAM_ERR_ENCODING;
    }
    reader->cursor++;

    if (buffer == NULL) {
        buffer = calloc(1, 1);
        if (buffer == NULL) {
            return EVERGRAM_ERR_NO_MEMORY;
        }
    }
    *out = buffer;
    return EVERGRAM_OK;
}

/* Reads ["a","b",...] into a heap array of owned strings. */
static evergram_status_t read_string_array(reader_t *reader, json_field_t *field) {
    reader->cursor++; /* '[' */
    skip_whitespace(reader);

    field->kind = JSON_VALUE_STRING_ARRAY;
    if (*reader->cursor == ']') {
        reader->cursor++;
        return EVERGRAM_OK;
    }

    char **items = NULL;
    size_t count = 0;
    size_t capacity = 0;
    evergram_status_t status = EVERGRAM_OK;

    while (true) {
        skip_whitespace(reader);
        char *item = NULL;
        status = read_string(reader, &item);
        if (status != EVERGRAM_OK) {
            goto fail;
        }

        if (count == capacity) {
            size_t next = capacity ? capacity * 2u : 4u;
            char **grown = realloc(items, next * sizeof(*grown));
            if (grown == NULL) {
                free(item);
                status = EVERGRAM_ERR_NO_MEMORY;
                goto fail;
            }
            items = grown;
            capacity = next;
        }
        items[count++] = item;

        skip_whitespace(reader);
        if (*reader->cursor == ',') {
            reader->cursor++;
            continue;
        }
        if (*reader->cursor == ']') {
            reader->cursor++;
            break;
        }
        status = EVERGRAM_ERR_ENCODING;
        goto fail;
    }

    field->items = items;
    field->item_count = count;
    return EVERGRAM_OK;

fail:
    for (size_t i = 0; i < count; i++) {
        free(items[i]);
    }
    free(items);
    return status;
}

static evergram_status_t read_value(reader_t *reader, json_field_t *field) {
    if (*reader->cursor == '[') {
        return read_string_array(reader, field);
    }
    if (*reader->cursor == '"') {
        field->kind = JSON_VALUE_STRING;
        return read_string(reader, &field->string);
    }

    if (strncmp(reader->cursor, "true", 4) == 0) {
        field->kind = JSON_VALUE_BOOL;
        field->boolean = true;
        reader->cursor += 4;
        return EVERGRAM_OK;
    }
    if (strncmp(reader->cursor, "false", 5) == 0) {
        field->kind = JSON_VALUE_BOOL;
        field->boolean = false;
        reader->cursor += 5;
        return EVERGRAM_OK;
    }
    if (strncmp(reader->cursor, "null", 4) == 0) {
        /* Nulls carry no information for these payloads; treat as absent. */
        field->kind = JSON_VALUE_STRING;
        field->string = NULL;
        reader->cursor += 4;
        return EVERGRAM_OK;
    }

    char *end = NULL;
    double number = strtod(reader->cursor, &end);
    if (end == reader->cursor) {
        return EVERGRAM_ERR_ENCODING; /* nested object/array or garbage */
    }
    field->kind = JSON_VALUE_NUMBER;
    field->number = number;
    reader->cursor = end;
    return EVERGRAM_OK;
}

evergram_status_t json_parse_flat(const char *text, json_object_t *out) {
    if (text == NULL || out == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    memset(out, 0, sizeof(*out));

    reader_t reader = {text};
    skip_whitespace(&reader);
    if (*reader.cursor != '{') {
        return EVERGRAM_ERR_ENCODING;
    }
    reader.cursor++;
    skip_whitespace(&reader);

    if (*reader.cursor == '}') {
        reader.cursor++;
        skip_whitespace(&reader);
        return *reader.cursor == '\0' ? EVERGRAM_OK : EVERGRAM_ERR_ENCODING;
    }

    while (true) {
        skip_whitespace(&reader);
        if (out->count >= JSON_MAX_FIELDS) {
            json_object_dispose(out);
            return EVERGRAM_ERR_ENCODING;
        }

        json_field_t *field = &out->fields[out->count];
        char *key = NULL;
        evergram_status_t status = read_string(&reader, &key);
        if (status != EVERGRAM_OK) {
            json_object_dispose(out);
            return status;
        }
        if (strlen(key) >= sizeof(field->key)) {
            free(key);
            json_object_dispose(out);
            return EVERGRAM_ERR_ENCODING;
        }
        memcpy(field->key, key, strlen(key) + 1u);
        free(key);

        skip_whitespace(&reader);
        if (*reader.cursor != ':') {
            json_object_dispose(out);
            return EVERGRAM_ERR_ENCODING;
        }
        reader.cursor++;
        skip_whitespace(&reader);

        status = read_value(&reader, field);
        if (status != EVERGRAM_OK) {
            json_object_dispose(out);
            return status;
        }
        out->count++;

        skip_whitespace(&reader);
        if (*reader.cursor == ',') {
            reader.cursor++;
            continue;
        }
        if (*reader.cursor == '}') {
            reader.cursor++;
            break;
        }
        json_object_dispose(out);
        return EVERGRAM_ERR_ENCODING;
    }

    skip_whitespace(&reader);
    if (*reader.cursor != '\0') {
        json_object_dispose(out);
        return EVERGRAM_ERR_ENCODING;
    }
    return EVERGRAM_OK;
}

void json_object_dispose(json_object_t *object) {
    if (object == NULL) {
        return;
    }
    for (size_t i = 0; i < object->count; i++) {
        free(object->fields[i].string);
        for (size_t j = 0; j < object->fields[i].item_count; j++) {
            free(object->fields[i].items[j]);
        }
        free(object->fields[i].items);
    }
    memset(object, 0, sizeof(*object));
}

static const json_field_t *find_field(const json_object_t *object, const char *key,
                                      json_value_kind_t kind) {
    if (object == NULL || key == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < object->count; i++) {
        if (object->fields[i].kind == kind && strcmp(object->fields[i].key, key) == 0) {
            return &object->fields[i];
        }
    }
    return NULL;
}

const char *json_get_string(const json_object_t *object, const char *key) {
    const json_field_t *field = find_field(object, key, JSON_VALUE_STRING);
    return field != NULL ? field->string : NULL;
}

bool json_get_number(const json_object_t *object, const char *key, double *out) {
    const json_field_t *field = find_field(object, key, JSON_VALUE_NUMBER);
    if (field == NULL) {
        return false;
    }
    if (out != NULL) {
        *out = field->number;
    }
    return true;
}

bool json_get_bool(const json_object_t *object, const char *key, bool *out) {
    const json_field_t *field = find_field(object, key, JSON_VALUE_BOOL);
    if (field == NULL) {
        return false;
    }
    if (out != NULL) {
        *out = field->boolean;
    }
    return true;
}

const char *const *json_get_string_array(const json_object_t *object, const char *key,
                                         size_t *count) {
    const json_field_t *field = find_field(object, key, JSON_VALUE_STRING_ARRAY);
    if (field == NULL) {
        if (count != NULL) {
            *count = 0;
        }
        return NULL;
    }
    if (count != NULL) {
        *count = field->item_count;
    }
    return (const char *const *)field->items;
}

/* --- writer ---------------------------------------------------------------- */

void json_writer_init(json_writer_t *writer, char *buffer, size_t capacity) {
    writer->buffer = buffer;
    writer->capacity = capacity;
    writer->length = 0;
    writer->failed = capacity == 0;
    if (capacity > 0) {
        buffer[0] = '\0';
    }
}

static void write_bytes(json_writer_t *writer, const char *text, size_t len) {
    if (writer->failed) {
        return;
    }
    if (writer->length + len + 1u > writer->capacity) {
        writer->failed = true;
        return;
    }
    memcpy(writer->buffer + writer->length, text, len);
    writer->length += len;
    writer->buffer[writer->length] = '\0';
}

static void write_raw(json_writer_t *writer, const char *text) {
    write_bytes(writer, text, strlen(text));
}

/* Single character, written from its own address: no temporary buffer. */
static void write_char(json_writer_t *writer, char c) {
    write_bytes(writer, &c, 1);
}

/* Escapes what JSON requires; UTF-8 passes through, like JSON.stringify. */
static void write_escaped(json_writer_t *writer, const char *value) {
    for (size_t i = 0; value[i] != '\0' && !writer->failed; i++) {
        unsigned char c = (unsigned char)value[i];
        switch (c) {
        case '"':
            write_raw(writer, "\\\"");
            break;
        case '\\':
            write_raw(writer, "\\\\");
            break;
        case '\b':
            write_raw(writer, "\\b");
            break;
        case '\f':
            write_raw(writer, "\\f");
            break;
        case '\n':
            write_raw(writer, "\\n");
            break;
        case '\r':
            write_raw(writer, "\\r");
            break;
        case '\t':
            write_raw(writer, "\\t");
            break;
        default:
            if (c < 0x20u) {
                char escape[8];
                snprintf(escape, sizeof(escape), "\\u%04x", c);
                write_raw(writer, escape);
            } else {
                write_char(writer, (char)c);
            }
            break;
        }
    }
}

void json_writer_begin_object(json_writer_t *writer) {
    write_char(writer, '{');
}

void json_writer_end_object(json_writer_t *writer) {
    write_char(writer, '}');
}

static void begin_field(json_writer_t *writer, const char *key) {
    if (writer->length > 1u && writer->buffer[writer->length - 1u] != '{') {
        write_char(writer, ',');
    }
    write_char(writer, '"');
    write_escaped(writer, key);
    write_raw(writer, "\":");
}

void json_writer_field_string(json_writer_t *writer, const char *key, const char *value) {
    if (writer->failed) {
        return;
    }
    begin_field(writer, key);
    write_char(writer, '"');
    write_escaped(writer, value != NULL ? value : "");
    write_char(writer, '"');
}

void json_writer_field_number(json_writer_t *writer, const char *key, double value) {
    if (writer->failed) {
        return;
    }
    begin_field(writer, key);

    char text[32];
    if (value == floor(value) && fabs(value) < 1e15) {
        snprintf(text, sizeof(text), "%.0f", value);
    } else {
        snprintf(text, sizeof(text), "%.17g", value);
    }
    write_raw(writer, text);
}

void json_writer_field_bool(json_writer_t *writer, const char *key, bool value) {
    if (writer->failed) {
        return;
    }
    begin_field(writer, key);
    write_raw(writer, value ? "true" : "false");
}

void json_writer_field_null(json_writer_t *writer, const char *key) {
    if (writer->failed) {
        return;
    }
    begin_field(writer, key);
    write_raw(writer, "null");
}

bool json_writer_ok(const json_writer_t *writer) {
    return writer != NULL && !writer->failed;
}
