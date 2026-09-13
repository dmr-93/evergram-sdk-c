#ifndef EVERGRAM_EXAMPLE_HTTP_POST_H
#define EVERGRAM_EXAMPLE_HTTP_POST_H

#include <stddef.h>

/*
 * Posts one JSON body to an HTTP(S) endpoint, blocking, and returns the
 * response's status code. Returns -1 when the request never completed (bad URL,
 * connection refused, TLS failure, timeout); `error` then holds a short reason.
 *
 * This belongs to the examples rather than to the library: HTTP is an
 * application concern, so only the example that needs it links libcurl. The
 * TypeScript SDK's equivalent uses the runtime's fetch().
 */
int example_http_post_json(const char *url, const char *json, long timeout_ms, char *error,
                           size_t error_size);

#endif /* EVERGRAM_EXAMPLE_HTTP_POST_H */
