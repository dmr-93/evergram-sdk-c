# Evergram SDK C

**C client library for the Evergram gateway.** It authenticates an XRPL account via challenge signing, registers devices, maintains a WebSocket session, and dispatches encrypted envelopes to callbacks. The SDK also ships a bot layer with reconnection, mailbox delivery, and identity persistence.

---

## What It Covers

| Area | Status |
|---|---|
| XRPL auth & device registration | ✅ |
| End‑to‑end encryption (nacl.box / secretbox) | ✅ |
| Chat sync (delta, paginated, removals) | ✅ |
| Chat create / leave / local metadata | ✅ |
| Membership, roles, invites, join requests | ✅ |
| Blocking, profile, presence, key rotation | ✅ |
| Send / reply / react / edit / delete / typing | ✅ |
| Visitor rooms & `public_group` widget channels | ✅ |
| Widget creation & configuration | ✅ |
| Account access & reputation | ✅ |
| Bot layer (reconnection, mailbox) | ✅ |
| Purchases (Pro) | ⚠️ Wrapped, not live‑tested |
| Message history | ❌ (protocol has no query) |
| Automatic reconnect in core client | ❌ (bot layer only) |
| ABI versioning | ❌ |

---

## Dependencies

- **Required:** `libsodium`, `libwebsockets`, `protobuf‑c`, `OpenSSL`, C17 compiler
- **Optional:** `libcurl` (only for the `webhook-bridge` example)

**Debian/Ubuntu:**
```bash
sudo apt-get install -y libsodium-dev libwebsockets-dev \
  protobuf-c-compiler libprotobuf-c-dev libssl-dev libcurl4-openssl-dev
```

---

## Building

```bash
make            # builds libevergram.a, libevergram.so, and all examples
make test       # unit tests
make asan       # ASan + UBSan
make ubsan      # UBSan only
make analyze    # gcc -fanalyzer
make cppcheck   # skipped if not installed
make valgrind   # skipped if not installed
make format     # clang-format -i
make proto      # regenerate protobuf-c sources
```

Artifacts:
- `build/lib/libevergram.a` — static
- `build/lib/libevergram.so` — shared
- `build/bin/` — example binaries

---

## Using the SDK in Your Own Project

### Against the shared library

```bash
cc -std=c17 -I include my_app.c \
   -L build/lib -levergram \
   -Wl,-rpath,"$PWD/build/lib" \
   -o my_app
```

`-levergram` pulls in all required transitive libraries. `-rpath` is optional; otherwise use `LD_LIBRARY_PATH=build/lib`.

### Against the static library

```bash
cc -std=c17 -I include my_app.c \
   build/lib/libevergram.a \
   -lsodium -lwebsockets -lprotobuf-c -lssl -lcrypto \
   -o my_app
```

### Makefile integration

```makefile
EVERGRAM_DIR ?= ../evergram-sdk-c
CFLAGS  += -std=c17 -I$(EVERGRAM_DIR)/include
LDFLAGS += -L$(EVERGRAM_DIR)/build/lib -levergram \
           -Wl,-rpath,$(EVERGRAM_DIR)/build/lib
```

---

## Basic Usage

```c
evergram_t *client = evergram_create(&(evergram_options_t){
    .url      = "wss://staging.evergram.app/api/ws",
    .wallet   = &wallet,
    .device   = &device,
    .platform = "Terminal",
    .user_data = &my_context,
});

evergram_on_message(client, on_message);
evergram_on_connected(client, on_connected);
evergram_start(client);          /* opens socket; auth is async */

while (running) {
    evergram_status_t status = evergram_poll(client, 100);
    if (status != EVERGRAM_OK && status != EVERGRAM_ERR_TIMEOUT) break;
}

evergram_destroy(client);
```

Callbacks receive the pointer passed as `options.user_data` via `evergram_user_data(eg)`.

---

## Bot Layer (Ergonomic Wrapper)

```c
evergram_bot_t *bot = evergram_bot_create(&(evergram_bot_options_t){
    .url            = "wss://staging.evergram.app/api/ws",
    .identity_path  = "identity.json",
    .name           = "MyBot",
    .user_data      = &my_context,
});

evergram_bot_on_message(bot, on_message);
evergram_bot_run(bot);           /* connects, reconnects, pumps */
```

`evergram_bot_t` handles:
- Identity persistence (loads or generates `identity.json`, mode 0600)
- Reconnection (exponential backoff with jitter)
- Re‑authentication and chat rediscovery
- Mailbox for delayed decryption (queues capped at 500/chat, 200 chats, 4000 frames)
- Nickname application per connection
- Deferred request decisions (accept/decline via `evergram_bot_poll()`)

Use `evergram_bot_poll()` for embeddable loops. Blocking calls must be made between polls, never inside a handler.

---

## Encryption Model

- Each chat has a random 32‑byte symmetric key, sealed per device with `nacl.box` (X25519 + XSalsa20‑Poly1305).
- Message bodies, reactions, edits use `nacl.secretbox` with a fresh 24‑byte nonce, base64‑encoded.
- Keys are learned from `ChatInfo` payloads (`registerDeviceResponse`, `createChatResponse`, `queryChatsResponse`, etc.).
- Chats auto‑sync after authentication, so `evergram_send` works on existing chats without extra calls.
- `evergram_message_t.text` is `NULL` when the key is unknown or decryption fails (fails closed, never raw ciphertext).

---

## Examples

| Example | Demonstrates |
|---|---|
| `minimal` | Smallest consumer: connect, log events, optional send |
| `echo-bot` | Identity bootstrap, listen, reply with typing indicator |
| `moderation-bot` | Auto‑approve join requests, promote, deny, report |
| `trivia-bot` | Chat game with in‑memory scoreboard, deadlines |
| `widget-visitor-bot` | Owner side of embeddable widget, visitor rooms |
| `widget-channel-bot` | `public_group` widget channel, presence, moderation |
| `paywall-bot` | Gated group via `payment_request`/`payment_receipt` |
| `webhook-bridge` | Forwards decrypted messages to HTTP endpoint (needs libcurl) |
| `xahau-tip-bot` | Tipping XAH on Xahau ledger (own XRPL client) |
| `regular-key-auth-check` | RegularKey auth against a real gateway |

Run any example with:
```bash
EVERGRAM_GATEWAY_URL=wss://staging.evergram.app/api/ws \
EVERGRAM_IDENTITY_FILE=identity.json \
./build/bin/echo-bot
```

---

## Ownership & Error Handling

- `evergram_create` copies wallet, device, platform — caller frees originals immediately.
- `evergram_destroy` zeroes secrets, tears down transport, frees client (accepts `NULL`).
- Callback arguments (`message->text`, `reply_to_message_id`) are borrowed — valid only during the callback.
- Every fallible function returns `evergram_status_t`; `EVERGRAM_OK` is `0`, so `if (status)` reads naturally.
- `evergram_poll` returns `EVERGRAM_ERR_TIMEOUT` — not a failure, just no event this round.
- `assert` is never used for runtime validation; the library never calls `abort`/`exit`.

---

## Known Limitations

1. Some protocol areas not ported: message history (no protocol query), anonymous magic‑link joiner, live Xahau ledger transport.
2. Core client does **not** reconnect on its own — reconnection is handled by the bot layer.
3. Single‑threaded: `evergram_poll` must be called from one thread.
4. No ABI versioning: `libevergram.so` has no soname suffix yet.

