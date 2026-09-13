#include "base64.h"

#include <sodium.h>
#include <string.h>

evergram_status_t base64_encode(const uint8_t *data, size_t len, char *out, size_t out_size) {
    if (out == NULL || (data == NULL && len > 0)) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (out_size < BASE64_ENCODED_SIZE(len)) {
        return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }

    if (sodium_bin2base64(out, out_size, data, len, sodium_base64_VARIANT_ORIGINAL) == NULL) {
        return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }
    return EVERGRAM_OK;
}

evergram_status_t base64_decode(const char *text, uint8_t *out, size_t out_size, size_t *out_len) {
    if (text == NULL || out == NULL || out_len == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    *out_len = 0;

    size_t len = strlen(text);
    if (sodium_base642bin(out, out_size, text, len, NULL, out_len, NULL,
                          sodium_base64_VARIANT_ORIGINAL) == 0) {
        return EVERGRAM_OK;
    }
    if (sodium_base642bin(out, out_size, text, len, NULL, out_len, NULL,
                          sodium_base64_VARIANT_ORIGINAL_NO_PADDING) == 0) {
        return EVERGRAM_OK;
    }

    *out_len = 0;
    return EVERGRAM_ERR_ENCODING;
}
