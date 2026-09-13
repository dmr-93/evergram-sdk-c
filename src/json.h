#ifndef EVERGRAM_JSON_H
#define EVERGRAM_JSON_H

#include <stdbool.h>
#include <stddef.h>

#include "evergram/status.h"

/*
 * Minimal JSON for protocol payloads.
 *
 * The protocol's JSON payloads are all flat objects with string, number or
 * boolean values (relay events, typing signals, payment content), so nesting is
 * deliberately not supported: a nested object or array is reported as
 * malformed rather than silently ignored.
 *
 * Ownership: json_parse_flat() allocates the parsed strings; release them with
 * json_object_dispose(). The keys point into the parsed object, not the input.
 */

#define JSON_MAX_FIELDS 16
#define JSON_MAX_KEY 64

typedef enum {
    JSON_VALUE_STRING = 0,
    JSON_VALUE_NUMBER,
    JSON_VALUE_BOOL,
    JSON_VALUE_STRING_ARRAY,
} json_value_kind_t;

typedef struct {
    char key[JSON_MAX_KEY];
    json_value_kind_t kind;
    char *string; /* owned; JSON_VALUE_STRING only */
    double number;
    bool boolean;
    char **items; /* owned; JSON_VALUE_STRING_ARRAY only */
    size_t item_count;
} json_field_t;

typedef struct {
    json_field_t fields[JSON_MAX_FIELDS];
    size_t count;
} json_object_t;

/* Parses one flat JSON object. Text must be a complete object, not a fragment. */
evergram_status_t json_parse_flat(const char *text, json_object_t *out);

/* Frees the strings a parsed object owns and resets it. Accepts NULL. */
void json_object_dispose(json_object_t *object);

/* Field accessors; return NULL/false when the field is absent or of another kind. */
const char *json_get_string(const json_object_t *object, const char *key);
bool json_get_number(const json_object_t *object, const char *key, double *out);
bool json_get_bool(const json_object_t *object, const char *key, bool *out);

/* Borrowed view of a string array field; *count is 0 when absent. */
const char *const *json_get_string_array(const json_object_t *object, const char *key,
                                         size_t *count);

/* --- writer ---------------------------------------------------------------- */

/*
 * Appends into a caller-owned buffer. Any overflow marks the writer failed and
 * later calls become no-ops, so callers only have to check json_writer_ok()
 * once at the end. The buffer is always NUL-terminated while it has room.
 */
typedef struct {
    char *buffer;
    size_t capacity;
    size_t length;
    bool failed;
} json_writer_t;

void json_writer_init(json_writer_t *writer, char *buffer, size_t capacity);

void json_writer_begin_object(json_writer_t *writer);
void json_writer_end_object(json_writer_t *writer);

void json_writer_field_string(json_writer_t *writer, const char *key, const char *value);
void json_writer_field_number(json_writer_t *writer, const char *key, double value);
void json_writer_field_bool(json_writer_t *writer, const char *key, bool value);
void json_writer_field_null(json_writer_t *writer, const char *key);

bool json_writer_ok(const json_writer_t *writer);

#endif /* EVERGRAM_JSON_H */
