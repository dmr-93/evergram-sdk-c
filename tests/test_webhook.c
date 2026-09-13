#include <arpa/inet.h>
#include <ctype.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../examples/_shared/http_post.h"
#include "test.h"

/*
 * The webhook bridge is the one example that talks HTTP, so its helper is
 * checked against a real socket: a forked child listens on an ephemeral port,
 * records the request it receives and answers. That covers the whole path
 * (request line, headers, body framing, status parsing) without needing a
 * network or a test double for libcurl.
 */

#define REQUEST_MAX 8192

/* strcasestr() is a GNU extension; the project builds against POSIX only. */
static const char *find_header(const char *haystack, const char *needle) {
    size_t needle_len = strlen(needle);
    for (const char *cursor = haystack; *cursor != '\0'; cursor++) {
        size_t i = 0;
        while (i < needle_len && cursor[i] != '\0' &&
               tolower((unsigned char)cursor[i]) == tolower((unsigned char)needle[i])) {
            i++;
        }
        if (i == needle_len) {
            return cursor;
        }
    }
    return NULL;
}

typedef struct {
    pid_t pid;
    int port;
} server_t;

/* Child half: accept one request, write it verbatim to `path`, answer 204. */
static void serve_once(int listener, const char *path) {
    int connection = accept(listener, NULL, NULL);
    if (connection < 0) {
        _exit(1);
    }

    char request[REQUEST_MAX];
    size_t used = 0;
    size_t content_length = 0;
    bool headers_done = false;

    while (used < sizeof(request) - 1u) {
        ssize_t got = read(connection, request + used, sizeof(request) - 1u - used);
        if (got <= 0) {
            break;
        }
        used += (size_t)got;
        request[used] = '\0';

        if (!headers_done) {
            const char *end = strstr(request, "\r\n\r\n");
            if (end != NULL) {
                headers_done = true;
                /* Content-Length decides when the body is complete; libcurl
                 * always sends one for a POST with a known size. */
                const char *header = find_header(request, "Content-Length:");
                if (header != NULL) {
                    content_length = (size_t)strtoul(header + strlen("Content-Length:"), NULL, 10);
                }
            }
        }
        if (headers_done) {
            const char *body = strstr(request, "\r\n\r\n") + 4;
            if ((size_t)(body - request) + content_length <= used) {
                break;
            }
        }
    }

    FILE *capture = fopen(path, "wb");
    if (capture != NULL) {
        fwrite(request, 1, used, capture);
        fclose(capture);
    }

    const char *response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
    ssize_t ignored = write(connection, response, strlen(response));
    (void)ignored;
    close(connection);
    close(listener);
    _exit(0);
}

/* Parent half: a listening socket on an ephemeral port, served by a child. */
static bool start_server(server_t *server, const char *capture_path) {
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        return false;
    }

    int reuse = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0; /* let the kernel pick a free port */

    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(listener, 1) != 0) {
        close(listener);
        return false;
    }

    socklen_t length = sizeof(address);
    if (getsockname(listener, (struct sockaddr *)&address, &length) != 0) {
        close(listener);
        return false;
    }
    server->port = ntohs(address.sin_port);

    server->pid = fork();
    if (server->pid < 0) {
        close(listener);
        return false;
    }
    if (server->pid == 0) {
        serve_once(listener, capture_path);
        _exit(0); /* not reached */
    }

    close(listener); /* the child owns it now */
    return true;
}

static void stop_server(const server_t *server) {
    int status = 0;
    waitpid(server->pid, &status, 0);
}

static bool read_capture(const char *path, char *out, size_t out_size) {
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        return false;
    }
    size_t read_bytes = fread(out, 1, out_size - 1u, file);
    out[read_bytes] = '\0';
    fclose(file);
    return true;
}

static void test_post_reaches_a_real_server(void) {
    const char *capture_path = "build/test_webhook_request.txt";
    remove(capture_path);

    server_t server;
    memset(&server, 0, sizeof(server));
    CHECK(start_server(&server, capture_path));
    if (server.pid <= 0) {
        return;
    }

    char url[64];
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/hook", server.port);

    const char *body = "{\"chatId\":\"c1\",\"text\":\"hello\"}";
    char error[256];
    error[0] = '\0';
    int status = example_http_post_json(url, body, 5000, error, sizeof(error));
    CHECK_EQ_INT(status, 204);
    CHECK_EQ_STR(error, "");

    stop_server(&server);

    char request[REQUEST_MAX];
    CHECK(read_capture(capture_path, request, sizeof(request)));
    CHECK(strstr(request, "POST /hook HTTP/1.1") != NULL);
    CHECK(find_header(request, "Content-Type: application/json") != NULL);
    /* The body must arrive byte for byte, and be framed by its real length. */
    CHECK(strstr(request, body) != NULL);
    char length_header[64];
    snprintf(length_header, sizeof(length_header), "Content-Length: %zu", strlen(body));
    CHECK(strstr(request, length_header) != NULL);

    remove(capture_path);
}

/* A refused connection is reported as a failure, with a reason, not as status
 * zero — a bridge must be able to tell "never delivered" from "delivered". */
static void test_unreachable_endpoint_reports_failure(void) {
    char error[256];
    error[0] = '\0';

    /* Port 1 on loopback: nothing listens there, and connecting fails at once. */
    int status = example_http_post_json("http://127.0.0.1:1/hook", "{}", 2000, error,
                                        sizeof(error));
    CHECK_EQ_INT(status, -1);
    CHECK(error[0] != '\0');

    /* Malformed and missing arguments are refused before any socket work. */
    CHECK_EQ_INT(example_http_post_json(NULL, "{}", 1000, error, sizeof(error)), -1);
    CHECK_EQ_INT(example_http_post_json("http://127.0.0.1:1/", NULL, 1000, error, sizeof(error)),
                 -1);

    /* An error buffer is optional. */
    CHECK_EQ_INT(example_http_post_json("http://127.0.0.1:1/", "{}", 2000, NULL, 0), -1);
}

static const test_case_t TESTS[] = {
    {"webhook: a post reaches a real server", test_post_reaches_a_real_server},
    {"webhook: an unreachable endpoint is reported", test_unreachable_endpoint_reports_failure},
};

const test_case_t *webhook_tests(size_t *count) {
    *count = sizeof(TESTS) / sizeof(TESTS[0]);
    return TESTS;
}
