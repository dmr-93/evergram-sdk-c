#include "http_post.h"

#include <curl/curl.h>
#include <stdio.h>
#include <string.h>

/*
 * The response body is discarded: what a bridge needs to know is whether the
 * endpoint accepted the delivery, which the status code says. Nothing is
 * retried here — a webhook that must not lose messages belongs behind a queue,
 * not behind a blocking call from a message handler.
 */
static size_t discard_body(char *data, size_t size, size_t count, void *context) {
    (void)data;
    (void)context;
    return size * count;
}

static void set_error(char *error, size_t error_size, const char *message) {
    if (error != NULL && error_size > 0) {
        snprintf(error, error_size, "%s", message);
    }
}

int example_http_post_json(const char *url, const char *json, long timeout_ms, char *error,
                           size_t error_size) {
    if (url == NULL || json == NULL) {
        set_error(error, error_size, "missing url or body");
        return -1;
    }

    /* libcurl's global init is idempotent, so the helper owns it and callers
     * never have to know about it. */
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        set_error(error, error_size, "cannot initialise libcurl");
        return -1;
    }

    CURL *handle = curl_easy_init();
    if (handle == NULL) {
        set_error(error, error_size, "cannot create a curl handle");
        return -1;
    }

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: */*");

    char curl_error[CURL_ERROR_SIZE];
    curl_error[0] = '\0';

    curl_easy_setopt(handle, CURLOPT_URL, url);
    curl_easy_setopt(handle, CURLOPT_POST, 1L);
    curl_easy_setopt(handle, CURLOPT_POSTFIELDS, json);
    curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, (long)strlen(json));
    curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, discard_body);
    curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L); /* safe from a threaded host */
    curl_easy_setopt(handle, CURLOPT_ERRORBUFFER, curl_error);
    if (timeout_ms > 0) {
        curl_easy_setopt(handle, CURLOPT_TIMEOUT_MS, timeout_ms);
        curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT_MS, timeout_ms);
    }
    /* A redirect is not a delivery, so it is reported as the status it is. */
    curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 0L);

    CURLcode result = curl_easy_perform(handle);
    int status = -1;
    if (result == CURLE_OK) {
        long code = 0;
        curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &code);
        status = (int)code;
    } else {
        set_error(error, error_size,
                  curl_error[0] != '\0' ? curl_error : curl_easy_strerror(result));
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(handle);
    return status;
}
