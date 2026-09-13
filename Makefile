# evergram-sdk-c - C17 build
#
# Common targets:
#   all       build static + shared libraries and the echo bot example
#   test      build and run the unit tests
#   asan      clean rebuild with ASan+UBSan, then run the tests
#   ubsan     clean rebuild with UBSan only, then run the tests
#   analyze   run the compiler's static analyzer over our sources
#   cppcheck  run cppcheck when installed
#   tidy      run clang-tidy when installed
#   valgrind  run the test binary under valgrind when installed
#   format    apply .clang-format to our sources
#   proto     regenerate src/proto/evergram.pb-c.[ch] from proto/evergram.proto

CC ?= cc
AR ?= ar

STD = -std=c17
WARN = -Wall -Wextra -Wpedantic
OPT ?= -O2 -g
SANITIZE ?=
# POSIX.1-2008 is used for file permissions (open/fdopen) and strnlen.
DEFS = -D_POSIX_C_SOURCE=200809L
INCLUDES = -Iinclude -Isrc -Isrc/proto

# -MMD -MP writes a .d file per object, so a header change rebuilds exactly the
# objects that include it. Without this a struct change in a public header left
# stale objects behind, and the tests then compared two different layouts.
CFLAGS = $(STD) $(WARN) -Werror $(OPT) $(DEFS) $(INCLUDES) -fPIC -fvisibility=hidden $(SANITIZE)
DEPFLAGS = -MMD -MP
LDFLAGS = $(SANITIZE)

LIBS = -lsodium -lwebsockets -lprotobuf-c -lssl -lcrypto

# libcurl is needed only by the webhook-bridge example, which is where HTTP
# belongs: the library itself never opens an HTTP connection. Without it
# everything else still builds, and the example is skipped with a note.
HAVE_CURL = $(shell pkg-config --exists libcurl && echo 1)
ifeq ($(HAVE_CURL),1)
CURL_LIBS = $(shell pkg-config --libs libcurl)
CURL_CFLAGS = $(shell pkg-config --cflags libcurl)
WEBHOOK_BRIDGE = $(BIN_DIR)/webhook-bridge
else
WEBHOOK_BRIDGE =
endif

BUILD_DIR = build
# Sanitized builds get their own object tree so switching modes never reuses
# incompatible objects.
SANITIZE_SUFFIX = $(if $(SANITIZE),-sanitized,)
OBJ_DIR = $(BUILD_DIR)/obj$(SANITIZE_SUFFIX)
BIN_DIR = $(BUILD_DIR)/bin$(SANITIZE_SUFFIX)
LIB_DIR = $(BUILD_DIR)/lib$(SANITIZE_SUFFIX)

LIB_STATIC = $(LIB_DIR)/libevergram.a
LIB_SHARED = $(LIB_DIR)/libevergram.so
MINIMAL = $(BIN_DIR)/minimal
ECHO_BOT = $(BIN_DIR)/echo-bot
MODERATION_BOT = $(BIN_DIR)/moderation-bot
PAYWALL_BOT = $(BIN_DIR)/paywall-bot
TRIVIA_BOT = $(BIN_DIR)/trivia-bot
REGULAR_KEY_CHECK = $(BIN_DIR)/regular-key-auth-check
WIDGET_VISITOR_BOT = $(BIN_DIR)/widget-visitor-bot
WIDGET_CHANNEL_BOT = $(BIN_DIR)/widget-channel-bot
XAHAU_TIP_BOT = $(BIN_DIR)/xahau-tip-bot
TEST_BIN = $(BIN_DIR)/run_tests

# The HTTP helper test needs libcurl, so it is part of the suite only where the
# library is present; everywhere else the rest of the tests still run.
# The Xahau transaction module is plain C with libsodium, so its test always
# runs; the HTTP helper test needs libcurl and joins only where it exists.
TEST_EXTRA_SOURCES = tests/test_xahau_tx.c examples/xahau-tip-bot/xahau_tx.c examples/xahau-tip-bot/xahau_rpc.c examples/xahau-tip-bot/commands.c

ifeq ($(HAVE_CURL),1)
TEST_EXTRA_SOURCES += tests/test_webhook.c examples/_shared/http_post.c
TEST_EXTRA_LIBS = $(CURL_LIBS)
TEST_EXTRA_CFLAGS = $(CURL_CFLAGS) -DEVERGRAM_HAVE_CURL=1
else
TEST_EXTRA_LIBS =
TEST_EXTRA_CFLAGS =
endif

SOURCES = \
	src/backoff.c \
	src/base58.c \
	src/bot.c \
	src/base64.c \
	src/chatkeys.c \
	src/chats.c \
	src/client.c \
	src/content.c \
	src/e2ee.c \
	src/handshake.c \
	src/identity.c \
	src/json.c \
	src/identity_file.c \
	src/log.c \
	src/parser.c \
	src/relay.c \
	src/rxqueue.c \
	src/transport.c \
	src/xrpl.c

GENERATED = src/proto/evergram.pb-c.c

TEST_SOURCES = \
	tests/main.c \
	tests/test_backoff.c \
	tests/test_bot.c \
	tests/test_base58.c \
	tests/test_chatkeys.c \
	tests/test_chats.c \
	tests/test_content.c \
	tests/test_json.c \
	tests/test_relay.c \
	tests/test_visitor.c \
	tests/test_requests.c \
	tests/test_interop.c \
	tests/test_widgets.c \
	tests/test_purchase.c \
	tests/test_e2ee.c \
	tests/test_identity.c \
	tests/test_parser.c \
	tests/test_rxqueue.c \
	tests/test_xrpl.c

OBJECTS = $(patsubst %.c,$(OBJ_DIR)/%.o,$(SOURCES) $(GENERATED))
DEPS = $(OBJECTS:.o=.d)

# The test and example binaries are compiled in one command, so make cannot see
# their includes: they depend on every header instead.
HEADERS = $(wildcard include/*.h include/evergram/*.h src/*.h tests/*.h examples/_shared/*.h)

# Explicit, because the included dependency files below are rules too and would
# otherwise become the default goal.
.DEFAULT_GOAL := all

.PHONY: all test asan ubsan analyze cppcheck tidy valgrind format proto clean help interop-vectors xahau-vectors

all: $(LIB_STATIC) $(LIB_SHARED) $(MINIMAL) $(ECHO_BOT) $(MODERATION_BOT) \
	$(WIDGET_VISITOR_BOT) $(WIDGET_CHANNEL_BOT) $(PAYWALL_BOT) \
	$(TRIVIA_BOT) $(REGULAR_KEY_CHECK) $(WEBHOOK_BRIDGE) $(XAHAU_TIP_BOT)

$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

# Generated protobuf-c code is third-party output; keep it quiet without
# relaxing the warnings we enforce on our own sources.
$(OBJ_DIR)/src/proto/%.o: src/proto/%.c
	@mkdir -p $(dir $@)
	$(CC) $(STD) $(OPT) $(DEFS) $(INCLUDES) -fPIC -fvisibility=hidden -w -c $< -o $@

# One set of PIC objects feeds both libraries.
$(LIB_STATIC): $(OBJECTS)
	@mkdir -p $(dir $@)
	$(AR) rcs $@ $^

$(LIB_SHARED): $(OBJECTS)
	@mkdir -p $(dir $@)
	$(CC) -shared $(LDFLAGS) -o $@ $^ $(LIBS)

# Links against the shared library and records an rpath so the binary runs
# from the build tree without LD_LIBRARY_PATH.
$(ECHO_BOT): examples/echo-bot/index.c $(HEADERS) $(LIB_SHARED)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $< -L$(LIB_DIR) -levergram $(LIBS) \
		-Wl,-rpath,'$$ORIGIN/../lib' -o $@

$(MODERATION_BOT): examples/moderation-bot/index.c $(HEADERS) $(LIB_SHARED)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $< -L$(LIB_DIR) -levergram $(LIBS) \
		-Wl,-rpath,'$$ORIGIN/../lib' -o $@

$(TRIVIA_BOT): examples/trivia-bot/index.c examples/trivia-bot/questions.h $(HEADERS) $(LIB_SHARED)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $< -L$(LIB_DIR) -levergram $(LIBS) \
		-Wl,-rpath,'$$ORIGIN/../lib' -o $@

$(REGULAR_KEY_CHECK): examples/regular-key-auth-check/index.c $(HEADERS) $(LIB_SHARED)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $< -L$(LIB_DIR) -levergram $(LIBS) \
		-Wl,-rpath,'$$ORIGIN/../lib' -o $@

$(WIDGET_VISITOR_BOT): examples/widget-visitor-bot/index.c $(HEADERS) $(LIB_SHARED)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $< -L$(LIB_DIR) -levergram $(LIBS) \
		-Wl,-rpath,'$$ORIGIN/../lib' -o $@

$(PAYWALL_BOT): examples/paywall-bot/index.c $(HEADERS) $(LIB_SHARED)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $< -L$(LIB_DIR) -levergram $(LIBS) \
		-Wl,-rpath,'$$ORIGIN/../lib' -o $@

$(WIDGET_CHANNEL_BOT): examples/widget-channel-bot/index.c $(HEADERS) $(LIB_SHARED)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $< -L$(LIB_DIR) -levergram $(LIBS) \
		-Wl,-rpath,'$$ORIGIN/../lib' -o $@

# Links libcurl on top of the library: the example, not the SDK, talks HTTP.
$(WEBHOOK_BRIDGE): examples/webhook-bridge/index.c examples/_shared/http_post.c $(HEADERS) $(LIB_SHARED)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CURL_CFLAGS) examples/webhook-bridge/index.c examples/_shared/http_post.c \
		-L$(LIB_DIR) -levergram $(LIBS) $(CURL_LIBS) \
		-Wl,-rpath,'$$ORIGIN/../lib' -o $@

$(XAHAU_TIP_BOT): examples/xahau-tip-bot/index.c examples/xahau-tip-bot/commands.c \
		examples/xahau-tip-bot/xahau_tx.c examples/xahau-tip-bot/xahau_rpc.c $(HEADERS) $(LIB_SHARED)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) examples/xahau-tip-bot/index.c examples/xahau-tip-bot/commands.c \
		examples/xahau-tip-bot/xahau_tx.c examples/xahau-tip-bot/xahau_rpc.c \
		-L$(LIB_DIR) -levergram $(LIBS) \
		-Wl,-rpath,'$$ORIGIN/../lib' -o $@

$(MINIMAL): examples/minimal.c $(HEADERS) $(LIB_SHARED)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $< -L$(LIB_DIR) -levergram $(LIBS) \
		-Wl,-rpath,'$$ORIGIN/../lib' -o $@

# Tests link the static library: hermetic and sanitizer friendly.
$(TEST_BIN): $(TEST_SOURCES) $(TEST_EXTRA_SOURCES) $(HEADERS) $(LIB_STATIC)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(TEST_EXTRA_CFLAGS) $(TEST_SOURCES) $(TEST_EXTRA_SOURCES) \
		$(LIB_STATIC) $(LIBS) $(TEST_EXTRA_LIBS) -o $@

test: $(TEST_BIN)
	@mkdir -p $(BUILD_DIR)
	./$(TEST_BIN)

asan:
	@$(MAKE) --no-print-directory \
		SANITIZE="-fsanitize=address,undefined -fno-omit-frame-pointer" OPT="-O1 -g" test

ubsan:
	@$(MAKE) --no-print-directory \
		SANITIZE="-fsanitize=undefined -fno-omit-frame-pointer" OPT="-O1 -g" test

analyze:
	@mkdir -p $(OBJ_DIR)
	@echo "== gcc -fanalyzer =="
	@for source in $(SOURCES); do \
		echo "-- $$source"; \
		$(CC) $(STD) $(WARN) $(DEFS) $(INCLUDES) -fanalyzer -c $$source -o $(OBJ_DIR)/analyzer.o || exit 1; \
	done

cppcheck:
	@if command -v cppcheck >/dev/null 2>&1; then \
		cppcheck --enable=warning,performance,portability --error-exitcode=1 \
			--std=c17 --quiet -Iinclude -Isrc $(SOURCES); \
		echo "cppcheck: clean"; \
	else \
		echo "cppcheck not installed, skipping"; \
	fi

tidy:
	@if command -v clang-tidy >/dev/null 2>&1; then \
		clang-tidy $(SOURCES) -- $(CFLAGS); \
	else \
		echo "clang-tidy not installed, skipping"; \
	fi

valgrind: $(TEST_BIN)
	@if command -v valgrind >/dev/null 2>&1; then \
		valgrind --leak-check=full --error-exitcode=1 ./$(TEST_BIN); \
	else \
		echo "valgrind not installed, skipping"; \
	fi

format:
	@if command -v clang-format >/dev/null 2>&1; then \
		clang-format -i $(SOURCES) $(wildcard src/*.h) $(wildcard include/*.h) \
			$(wildcard include/evergram/*.h) examples/*.c tests/*.c tests/*.h; \
		echo "formatted"; \
	else \
		echo "clang-format not installed, skipping"; \
	fi

# Regenerates tests/interop_vectors.h from a TypeScript SDK checkout. Requires
# that checkout to have its dependencies installed; TS_SDK defaults to a sibling
# directory, which is how the two repositories are usually laid out.
TS_SDK ?= ../evergram-sdk

interop-vectors:
	@test -d "$(TS_SDK)" || { \
		echo "TS_SDK=$(TS_SDK) is not a checkout; set TS_SDK=/path/to/evergram-sdk"; \
		exit 1; }
	@test -x "$(TS_SDK)/node_modules/.bin/tsx" || { \
		echo "run npm install in $(TS_SDK) first"; \
		exit 1; }
	TS_SDK="$(TS_SDK)" "$(TS_SDK)/node_modules/.bin/tsx" tools/gen_interop_vectors.mjs \
		tests/interop_vectors.h

xahau-vectors:
	@test -x "$(TS_SDK)/node_modules/.bin/tsx" || { \
		echo "run npm install in $(TS_SDK) first (or set TS_SDK=...)"; \
		exit 1; }
	TS_SDK="$(TS_SDK)" node tools/gen_xahau_vectors.mjs tests/xahau_vectors.h

proto:
	protoc-c --c_out=src/proto -Iproto proto/evergram.proto
	@echo "regenerated src/proto/evergram.pb-c.[ch]"

clean:
	rm -rf $(BUILD_DIR)
	@echo "clean"

help:
	@echo "evergram-sdk-c targets:"
	@echo "  all       build the libraries and the bundled examples"
	@echo "  test      build and run unit tests (one command)"
	@echo "  asan      clean rebuild with AddressSanitizer + UBSan, run tests"
	@echo "  ubsan     clean rebuild with UndefinedBehaviorSanitizer, run tests"
	@echo "  analyze   gcc -fanalyzer over our sources"
	@echo "  cppcheck  static analysis (skipped when not installed)"
	@echo "  tidy      clang-tidy (skipped when not installed)"
	@echo "  valgrind  run tests under valgrind (skipped when not installed)"
	@echo "  format    clang-format -i (skipped when not installed)"
	@echo "  proto     regenerate protobuf-c sources"
	@echo "  interop-vectors  regenerate the TS interop vectors (needs TS_SDK)"
	@echo "  xahau-vectors    regenerate the ledger vectors (needs TS_SDK)"
	@echo "  clean     remove build/"
	@echo ""
	@echo "libcurl is optional: without it the webhook-bridge example and its"
	@echo "test are skipped, everything else builds unchanged."

# Included last on purpose: see .DEFAULT_GOAL above.
-include $(DEPS)
