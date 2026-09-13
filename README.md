# evergram-sdk-c

C17 client library for the Evergram gateway: a clean rewrite of `evergram-c`
with the same observable behaviour, a smaller public surface, and explicit
ownership and error rules.

It authenticates an XRPL account by signing the gateway's challenge, registers
the device on first use, keeps a websocket session alive, and dispatches
incoming envelopes to callbacks.

## Layout

```
include/evergram.h            public API (umbrella)
include/evergram/export.h     ABI macros (EVERGRAM_API, EVERGRAM_PRINTF)
include/evergram/status.h     status codes
include/evergram/types.h      POD types, callbacks, options
src/internal.h                private state, shared by all modules
src/base58.[ch]               base58 / base58check with XRPL alphabet
src/xrpl.[ch]                 ed25519 keys, addresses, challenge signatures
src/identity.[ch]             wallet and device generation
src/identity_file.c           "key=value" identity file, mode 0600
src/json.[ch]                 flat JSON reader/writer for protocol payloads
src/relay.[ch]                ephemeral relay frame codec (visitor rooms, channels)
src/rxqueue.[ch]              byte queue that preserves message boundaries
src/transport.[ch]            libwebsockets client
src/handshake.c               auth request and device registration
src/parser.c                  ServerMessage dispatch
src/client.c                  lifecycle, callbacks, send/reply
src/log.[ch]                  leveled logging
src/proto/evergram.pb-c.[ch]  protobuf-c output (generated, checked in)
proto/evergram.proto          wire contract
examples/echo_bot.c           full-featured bot
examples/minimal.c            smallest useful consumer
tests/                        unit tests
```

## Build

Requires a C17 compiler and the development packages for libsodium,
libwebsockets, protobuf-c and OpenSSL. `libcurl` is optional: only the
`webhook-bridge` example (and its test) uses it, and it is skipped when absent.

```sh
# Debian/Ubuntu
sudo apt-get install -y libsodium-dev libwebsockets-dev protobuf-c-compiler \
    libprotobuf-c-dev libssl-dev libcurl4-openssl-dev
```

Requires `libsodium`, `libwebsockets`, `protobuf-c`, `openssl`, and a C17
compiler.

```sh
sudo apt-get install libsodium-dev libwebsockets-dev protobuf-c-compiler \
     libprotobuf-c-dev libssl-dev
make            # build/lib/libevergram.{a,so} + build/bin/echo_bot
make test       # unit tests, one command
make asan       # ASan + UBSan (separate object tree)
make ubsan      # UBSan only
make analyze    # gcc -fanalyzer over our sources
make cppcheck   # skipped when not installed
make valgrind   # skipped when not installed
make format     # clang-format -i
make proto      # regenerate protobuf-c sources
```

Our sources build with `-std=c17 -Wall -Wextra -Wpedantic -Werror`.
The generated `src/proto/evergram.pb-c.c` is compiled with warnings disabled;
it is third-party output and is never edited by hand.

Object files carry their own header dependencies (`-MMD -MP`), so changing a
public struct rebuilds exactly what includes it — without that, a stale object
compiled against the previous layout could make the tests compare two different
structures and pass.

### Artifacts and ABI

`make` produces both libraries from a single set of `-fPIC` objects:

| file | used by |
| --- | --- |
| `build/lib/libevergram.a` | tests, static embedding |
| `build/lib/libevergram.so` | `echo_bot` and dynamic consumers |

Objects are compiled with `-fvisibility=hidden`, and only declarations marked
`EVERGRAM_API` are exported. `nm -D --defined-only build/lib/libevergram.so`
therefore lists exactly the public API and nothing else.

The example links the shared library and records an rpath of
`$ORIGIN/../lib`, so it runs from the build tree without `LD_LIBRARY_PATH`.
Setting `LD_LIBRARY_PATH=./build/lib` still works and takes precedence.

There is no soname/ABI versioning yet: `libevergram.so` carries no version
suffix, so replacing it in place is a breaking change for existing binaries.
Add versioning before publishing the library for third-party consumption.

## Usage

### Bundled examples

`make` builds these next to the libraries. The ported examples mirror the
TypeScript SDK's `examples/` layout and share `examples/_shared/example.h`.

| example | shows |
| --- | --- |
| `minimal` | smallest useful consumer: connect, log events, optionally send one message |
| `echo-bot` | the basics: identity bootstrap, listen, reply with a typing indicator |
| `moderation-bot` | group management: auto-approving join requests by allowlist, promoting to moderator, denying and reporting |
| `trivia-bot` | a chat game: one round per chat, `!trivia`/`!skip`/`!score`/`!help`, in-memory scoreboard, deadline-driven round expiry |
| `widget-visitor-bot` | the owner side of the embeddable widget: visitor rooms, echoing the visitor, persisting rooms across restarts |
| `widget-channel-bot` | a `public_group` widget channel: presence, a slash-command moderation surface, re-subscribing after a reconnect |
| `paywall-bot` | gating a group behind a `payment_request`/`payment_receipt` handshake, then granting access |
| `webhook-bridge` | forwarding every decrypted message to an external HTTP endpoint, from a queue |
| `xahau-tip-bot` | tipping XAH on the Xahau ledger: `!tip`/`!balance`/`!help`, transaction signing and JSON-RPC submission |
| `regular-key-auth-check` | RegularKey authentication against a real gateway, using the core API directly with an ephemeral device |

```sh
# point them at a gateway; defaults to ws://localhost:9000/api/ws
export EVERGRAM_GATEWAY_URL=wss://staging.evergram.app/api/ws
export EVERGRAM_IDENTITY_FILE=identity.json   # created on first run, mode 0600

./build/bin/echo-bot
./build/bin/moderation-bot                     # MODERATION_ALLOWLIST / MODERATION_PROMOTE
./build/bin/trivia-bot
./build/bin/paywall-bot                         # PAYWALL_CHAT_ID=...
WEBHOOK_URL=https://example.test/hook ./build/bin/webhook-bridge
XAHAU_RPC_URL=ws://localhost:16003 ./build/bin/xahau-tip-bot   # TIPBOT_MAX_TIP=...
./build/bin/widget-visitor-bot                   # WIDGET_ID=... EVERGRAM_SESSIONS_FILE=...
EVERGRAM_WIDGET_ID=... EVERGRAM_CHANNEL_KEY=<64 hex> ./build/bin/widget-channel-bot
# both values come from the widget itself: evergram_widget_list() +
# evergram_widget_get_info() report them, as the channel example explains
ACCOUNT_ADDRESS=r... REGULAR_KEY_SEED=sEd... ./build/bin/regular-key-auth-check
./build/bin/minimal "$EVERGRAM_GATEWAY_URL" "$EVERGRAM_IDENTITY_FILE"
./build/bin/minimal "$EVERGRAM_GATEWAY_URL" "$EVERGRAM_IDENTITY_FILE" <chat_id> "hello"
```

`webhook-bridge` is the only example that needs a library the SDK itself does
not use: it links **libcurl** for its HTTP POST. `make` detects it with
`pkg-config` and builds the example (and its test) only when it is present;
everything else builds without it.

All nine examples are ported. `xahau-tip-bot` is the one that reaches a ledger,
so it carries its own small XRPL client (`examples/xahau-tip-bot/`): transaction
serialization, ed25519 signing and JSON-RPC over websocket. The reference example
gets all of that from the `xrpl` npm package; here it is hand-written, and pinned
against that package **byte for byte** — see "Xahau/XRPL interoperability". The
SDK itself never talks to a ledger.

### Library skeleton

```c
evergram_t *client = evergram_create(&(evergram_options_t){
    .url = "wss://staging.evergram.app/api/ws",
    .wallet = &wallet,
    .device = &device,
    .platform = "Terminal",
    .user_data = &my_context,
});

evergram_on_message(client, on_message);
evergram_on_connected(client, on_connected);

evergram_start(client);                 /* opens the socket; auth is async */
while (running) {
    evergram_status_t status = evergram_poll(client, 100);
    if (status != EVERGRAM_OK && status != EVERGRAM_ERR_TIMEOUT) break;
}
evergram_destroy(client);
```

Callbacks receive the pointer passed as `options.user_data` through
`evergram_user_data(eg)`, which is how a context reaches them without globals.

### Building your own project

Everything needed is under `include/` and `build/lib/`; nothing has to be
installed. Full programs to copy from: `examples/minimal.c` and the bots under
`examples/` (identity handling, replies, typing, reactions).

**Against the shared library**

```sh
cc -std=c17 -I include my_app.c \
   -L build/lib -levergram \
   -Wl,-rpath,"$PWD/build/lib" \
   -o my_app
```

`-levergram` is enough: libsodium, libwebsockets, protobuf-c and OpenSSL are
recorded as dependencies of `libevergram.so`. The `-rpath` is optional; drop it
and run the program with `LD_LIBRARY_PATH=build/lib` instead. To
ship the binary somewhere else, copy `libevergram.so` next to it and link with
`-Wl,-rpath,'$ORIGIN'`.

**Against the static library**

```sh
cc -std=c17 -I include my_app.c \
   build/lib/libevergram.a \
   -lsodium -lwebsockets -lprotobuf-c -lssl -lcrypto \
   -o my_app
```

The static archive carries no dependency information, so the transitive
libraries have to be listed explicitly.

**Makefile**

```make
EVERGRAM_DIR ?= ../evergram-sdk-c

CFLAGS  += -std=c17 -I$(EVERGRAM_DIR)/include
LDFLAGS += -L$(EVERGRAM_DIR)/build/lib -levergram -Wl,-rpath,$(EVERGRAM_DIR)/build/lib
```

## Encryption

Messages are end-to-end encrypted with the same primitives as the TypeScript
SDK (`tweetnacl` → libsodium here), so the gateway only ever relays ciphertext:

* each chat has a random 32-byte symmetric key, sealed once per device with
  `nacl.box` (X25519 + XSalsa20-Poly1305); only the device's own secret key can
  open it;
* message bodies, reactions and edits use `nacl.secretbox` with a fresh 24-byte
  nonce, both travelling base64 encoded.

Keys are learned from every message that can carry a `ChatInfo`:
`registerDeviceResponse.rotated_sym_keys`, `createChatResponse.chat`,
`queryChatsResponse.results[].chat`, `rotateChatVersionResponse.chat` and
`acceptChatRequestResponse.chat`. The client also **syncs chats automatically
right after authentication**, which is how it learns the keys of conversations
that already existed — that is why `evergram_send` works on a chat the bot was
already part of without any extra call.

Consequences worth knowing:

* `evergram_message_t.text` is **NULL** when the chat key is not known (yet) or
  the payload cannot be decrypted. Nothing is ever delivered as raw ciphertext,
  and decryption fails closed: a tampered tag or a wrong key yields NULL rather
  than a partial body.
* Outgoing calls return `EVERGRAM_ERR_NO_CHAT_KEY` and send nothing when the key
  is unknown; check with `evergram_has_chat_key()`. Use `evergram_sync_chats()`
  to re-sync later.

## Chats

The gateway has **no "get chat" command**: metadata is accumulated locally from
every `ChatInfo` it sends. So `evergram_chat_get()` / `evergram_chat_list()` /
`evergram_chat_count()` are local lookups that never block, and the returned
pointers are borrowed from the store (invalidated when that chat is updated or
the client is destroyed).

Operations that do go to the gateway are **synchronous**: `evergram_chat_create()`
and `evergram_chat_leave()` send the request and pump the transport until the
response arrives or the timeout expires (`timeout_ms < 0` = 30s default). One
call may be in flight at a time; calling them from inside a callback returns
`EVERGRAM_ERR_STATE`. When the gateway rejects a request the call returns
`EVERGRAM_ERR_GATEWAY` and the code/message are available from
`evergram_last_error_code()` / `evergram_last_error()`.

`evergram_chat_create()` needs no manual key exchange: the gateway seals the new
chat key for every participant device, so `evergram_has_chat_key()` is true for
the new chat as soon as the call returns.

## Groups, invites and blocking

All of these are synchronous gateway calls, like the chat operations above.
Approving a join request is `evergram_chat_add_participant()` (there is no
separate "approve" command on the wire); denying is `evergram_join_request_deny()`.
Requests arrive through `evergram_on_join_request()`, which is fed by the
gateway's `joinRequested` push.

| operation | function |
| --- | --- |
| add / remove member | `evergram_chat_add_participant()`, `evergram_chat_remove_participant()` |
| moderated join gate | `evergram_chat_set_mode()` |
| admin / moderator lists | `evergram_chat_update_roles()` |
| deny a join request | `evergram_join_request_deny()` |
| invite codes | `evergram_invite_generate()`, `evergram_invite_revoke()`, `evergram_invite_resolve()` |
| join by code | `evergram_chat_request_join()` |
| block / unblock | `evergram_identity_block()`, `evergram_identity_unblock()` |

Like chat creation, membership changes need no manual key wrapping: the gateway
reseals the chat key for the affected devices.

## Structured content, payments and tiers

A message body is plain text until it is a JSON envelope, and
`evergram_message_content_parse()` decodes those into structs:
`payment_request`, `payment_receipt`, `payment_sent` and `audio`. The
discriminator alone is available without copying anything through
`evergram_message_content_type()`.

```c
evergram_content_t content;
if (evergram_message_content_parse(message->text, &content) == EVERGRAM_OK &&
    content.type == EVERGRAM_CONTENT_PAYMENT_RECEIPT) {
    printf("paid %s %s (tx %s)\n", content.payment_receipt.amount,
           content.payment_receipt.currency, content.payment_receipt.tx_hash);
}
```

The matching builders (`evergram_payment_request_build()`,
`_payment_receipt_build()`, `_payment_sent_build()`, `_audio_message_build()`)
produce the same envelopes the TypeScript SDK's `message-builders.ts` does, and
`evergram_new_request_id()` mints the UUID v4 a request is correlated by.

**A receipt is not proof of payment.** Nothing in the gateway or the contract
verifies `tx_hash`: it is exactly as trustworthy as any other field a peer chose
to send. A paywall must check the hash against the XRPL or Xahau ledger — right
amount, right currency, right destination — before granting anything. The
`paywall-bot` example demonstrates the message plumbing only; it says so at the
top of the file.

Two deliberate differences from the reference SDK, both narrowing what can go
wrong: a body whose discriminator says "payment" but whose JSON cannot be read
is reported as **text**, not as a half-filled receipt, and an envelope with an
unrecognized `type` is kept distinct as `EVERGRAM_CONTENT_UNKNOWN` (the
reference SDK collapses both cases into text). `content.text` is always set for
anything that is not a parsed payment or audio envelope.

Account access is reported with every successful authentication:
`evergram_access()` returns the tier, capabilities, admin flag, subscription
count, the device limit when one is enforced (absent, not zero, otherwise) and
whether the account is **restricted**
(`evergram_is_restricted()`). A later reputation push can change that flag;
`evergram_on_restricted()` fires on the transition into restricted, which is the
one a bot has to react to.

## Chat requests, group invites and chat sync

A one-on-one chat only exists once the recipient approves it, so the requester
waits while the recipient decides.

* `evergram_on_chat_request()` reports a request, with the requester's identity,
  nickname and timestamp. `evergram_chat_request_accept()` creates the chat (the
  chat record and its key are in the store by the time the call returns, so
  `evergram_chat_get()` and sending work immediately);
  `evergram_chat_request_decline()` refuses that one request and deliberately
  does *not* block the sender — block separately if that is the intent.
* `evergram_on_group_invite()` / `evergram_group_invite_accept()` /
  `..._decline()` are the group equivalent.

Both are replayed by the boot sync, because a process that starts (or
reconnects) after the request arrived would otherwise never hear about it. The
client remembers what is still pending, so each request is reported exactly
once: `evergram_chat_request_is_pending()`,
`evergram_group_invite_is_pending()` and the two `*_count()` accessors expose
that state. Deciding either way clears it.

`evergram_on_chat_removed()` fires when a chat this client knew about is gone
server-side — left, deleted, or this identity was removed from it. The chat
metadata *and its key* are dropped together, so nothing lingers decryptable.

`evergram_sync_chats()` sends the versions it already holds
(`known_versions` / `known_meta_versions`) so the gateway answers with what
changed instead of the whole history, and follows `next_cursor` for pages
(capped at 50, so a misbehaving gateway cannot loop forever). The two version
maps are kept separate on purpose: a moderation change bumps the metadata
version only, and must never look like a key rotation on devices that already
hold the current key. A chat reported as `MISSING` is dropped, and metadata
changes land in `evergram_chat_info_t.meta_version`.

## Profile, presence and key rotation

`evergram_profile_get()` fetches another identity's profile from its identity
key (`"<chainFamily>:<address>"`, validated the same way the TypeScript SDK does:
unknown chains and empty addresses are rejected). `evergram_profile_set()`
updates this identity's own profile; fields left NULL are unchanged, and the
gateway echoes the merged profile back.

Presence is push-based: `evergram_identities_watch()` / `_unwatch()` are
fire-and-forget (the protocol has no response for them) and the gateway then
delivers `evergram_on_presence()` for those identities.
`evergram_on_profile_updated()` reports profile pushes.

`evergram_chat_rotate_key()` asks the gateway to generate a fresh chat key and
reseal it for every participant device; the parser swaps in the new key while
handling the response, so the client is on the new key when the call returns.

## Purchases (Pro)

This is the one surface with **no counterpart in the reference TypeScript SDK**,
which ships no method for these messages; it follows the protocol directly.

Buying Pro is two steps because the payment happens on-chain:

```c
evergram_purchase_t purchase;
evergram_purchase_initiate(eg, NULL, NULL, NULL, 35000, &purchase);
if (purchase.already_subscribed) {
    /* nothing to buy */
} else if (purchase.has_payment) {
    /* sign and submit purchase.payment with your own XRPL/Xahau client, then */
    evergram_subscription_t subscription;
    evergram_purchase_verify(eg, purchase.intent_id, tx_hash, NULL, 35000, &subscription);
}
```

`evergram_purchase_claim_pro()` activates a subscription that was granted out of
band. `evergram_subscription_is_active()` takes "now" as an argument, so the
caller decides what that means.

The answer to `initiate` is deliberately rich, and one detail matters: when the
gateway returns both a fresh transaction and an **open intent** — another device
of the same account started a purchase — the intent's transaction is the one that
should be paid, and that is the one `purchase.payment` carries. Nothing in this
API touches a ledger: the SDK never signs a payment transaction.

## Widgets

The embeddable widget is created once by its owner and configured with colors,
copy and a mode: `private_chat` gives every visitor their own 1:1 room, while
`public_group` puts them all in one shared channel whose `channel_key` *is* the
room key (`evergram_visitor_subscribe_channel()` takes it).

```c
evergram_widget_t widget;
evergram_widget_create(eg, "Support", 35000, &widget);

/* Read the current config, change one field, send it back: the call replaces
   the stored config, and only flagged fields are transmitted. */
evergram_widget_t all[16];
size_t count = 0;
evergram_widget_list(eg, 35000, all, 16, &count);

evergram_widget_config_t config = all[0].config;
config.has_welcome_message = true;
snprintf(config.welcome_message, sizeof(config.welcome_message), "Hi! How can we help?");
config.has_mode = true;
snprintf(config.mode, sizeof(config.mode), "%s", EVERGRAM_WIDGET_MODE_PUBLIC_GROUP);
evergram_widget_set_config(eg, widget.widget_id, &config, 35000);
```

`evergram_widget_set_enabled()` pauses and resumes a widget without deleting it,
and `evergram_widget_delete()` retires it for good.
`evergram_widget_get_info()` is the one call the gateway answers **without**
authorization, which is what lets an embedding page describe its own widget; it
reports the owner, the registered devices, the enabled flag and the config.

Widget calls are slower than the rest of the protocol: the reference SDK allows
them 35 seconds, so pass `35000` unless you have a reason not to.

## Visitor rooms (widget relay)

The embeddable widget is built on *ephemeral rooms*: the visitor's page opens a
room against a widget id, each of the owner's devices is offered it, and the two
sides then exchange frames the gateway relays without being able to read them
(the content kinds are sealed with the room's own key, which never leaves the
participants). A room is bound to two live sockets: there is no stored history
and no offline delivery, by design.

Two roles, and the SDK takes care of the asymmetry between them:

* the **creator** (the visitor) calls `evergram_visitor_room_create()`, which
  generates the room key, optionally seals a first message with it, and stores
  the key for the session;
* the **joiner** (the widget owner) receives `evergram_on_visitor_room()`. The
  key arrives already opened with the device key, and the client immediately
  sends the `RELAY_JOINED` frame that claims the room — that frame is what flips
  the visitor's UI to "connected". A slot belongs to a socket, so every
  re-authentication re-claims the rooms this client is the joiner of.

```c
/* Owner: echo whatever the visitor sends. */
static void on_room(evergram_t *eg, const evergram_visitor_room_t *room) {
    if (room->has_first_message) {
        evergram_visitor_send_text(eg, room->room_token, NULL, "hello!");
    }
}

static void on_text(evergram_t *eg, const char *token, const evergram_relay_text_t *event) {
    evergram_visitor_send_text(eg, token, NULL, event->text);
}

evergram_on_visitor_room(eg, on_room);
evergram_on_visitor_text(eg, on_text);
```

Sending mirrors the chat API — `evergram_visitor_send_text()`, `_react()`
(a NULL emoji clears the reaction), `_edit()`, `_remove()`, `_typing()` and
`_end_room()` — and every one of them is fire-and-forget, so they are safe to
call from a callback. `evergram_visitor_has_room()` /
`evergram_visitor_room_key()` expose the session state, and
`EVERGRAM_ERR_NO_ROOM_KEY` is returned when a frame is attempted for a room this
client does not know.

Session and channel events:

| Callback | Fires for |
| --- | --- |
| `evergram_on_visitor_room` | a room opened against one of our widgets |
| `evergram_on_visitor_text` / `_react` / `_edit` / `_remove` | decrypted content frames |
| `evergram_on_visitor_typing` | plaintext typing liveness |
| `evergram_on_visitor_state` | `CONNECTED`, `PEER_LEFT` (with the reclaim deadline), `ENDED`, `CLAIMED_ELSEWHERE`, `KICKED` (with the reason) |
| `evergram_on_visitor_presence` | `public_group` participant join/part |
| `evergram_on_visitor_moderation` | `public_group` moderation snapshot |
| `evergram_on_visitor_timed_out` | a visitor's room was never claimed |

The final states drop the room key, so nothing lingering stays usable. A
`CLAIMED_ELSEWHERE` frame means another device of the same identity won the
race — a normal outcome when the owner is logged in on more than one device, not
an error.

A `public_group` widget is a *channel* instead of a 1:1 room. The operator's
channel key (64 hex characters) **is** the room key, so
`evergram_visitor_subscribe_channel()` is the only channel-specific join step:
everything above then applies unchanged, including the send calls. Only the
application can rejoin a channel after a reconnect (see "Known limitations"),
which also means `evergram_visitor_announce_presence()` — plaintext, like
typing — is what puts this client's nickname on the roster, and
`evergram_visitor_moderate_channel()` performs kick/ban/unban/op/voice/+m,
reporting the resulting snapshot through `evergram_on_visitor_moderation()`.
Authorization is enforced by the gateway: a non-op caller gets
`EVERGRAM_ERR_GATEWAY` with the code in `evergram_last_error_code()`.

Content frames are indistinguishable from chat messages at the crypto layer:
`nacl.secretbox` with a fresh nonce, base64 `{"nonce","ciphertext"}` as the
payload, and the plaintext a small JSON envelope carrying `msgId`, `sender`,
`text` and `ts`. Typing, presence, moderation and lifecycle frames are
deliberately plaintext — they describe liveness, not content — which is what
lets the gateway keep its channel rosters consistent.

`evergram_visitor_room_create()` mints the key itself: a caller cannot supply
one, because the first message has to be sealed with the same key the owner will
receive. For a `public_group` widget the response also carries the initial
participant and moderation snapshot, reported through the presence and
moderation callbacks *before* the call returns; those callbacks run inside a
synchronous call, so they must not start another request.

Because a room only exists while both sockets do, a bot that restarts loses its
rooms unless it saves `{room_token, key, widget, label, origin}` itself and
re-registers them; this port keeps the same contract (see
`evergram_visitor_room_key()`), and the `widget-visitor-bot` example shows the
persistence pattern.

## Bot layer

`evergram_bot_t` (in `evergram/bot.h`) is the ergonomic layer over the client,
mirroring the TypeScript SDK's `EvergramBot`. It owns:

* **identity persistence** — loads `identity_path`, or generates and saves one
  (mode 0600) when it is missing or unusable;
* **reconnection** — exponential backoff with jitter
  (`min(base * 2^(attempt-1), 30s)`, 500 ms of jitter), driven from
  `evergram_bot_poll()`, so no signals or timers are needed;
* **re-authentication and chat rediscovery** — both happen on every reconnect
  because the client re-authenticates and re-syncs chats after auth;
* **a mailbox** — a `SEND`/`REACT`/`EDIT` whose chat key has not arrived yet is
  held and delivered once the key lands, instead of being handed to the app as
  an empty message. Queues are capped (500 per chat, 200 chats, 4000 frames)
  and identical frames are not queued twice;
* **the configured nickname** — applied through `setProfile` once per
  connection, right after authentication;
* **deferred request decisions** — `evergram_bot_accept_chat_request()`,
  `_decline_chat_request()`, `_accept_group_invite()` and
  `_decline_group_invite()` queue the call for `evergram_bot_poll()`, since a
  handler may not start a synchronous request. `evergram_bot_on_chat_request()`,
  `evergram_bot_on_group_invite()` and `evergram_bot_on_chat_removed()` forward
  the pushes.

```c
evergram_bot_t *bot = evergram_bot_create(&(evergram_bot_options_t){
    .url = "wss://staging.evergram.app/api/ws",
    .identity_path = "identity.json",
    .name = "MyBot",
    .user_data = &my_context,
});

evergram_bot_on_message(bot, on_message);
evergram_bot_run(bot);            /* connects, reconnects, pumps */
```

Inside a handler, recover the bot and then your own context:

```c
static void on_message(evergram_t *eg, const evergram_message_t *message) {
    app_t *app = evergram_bot_user_data(evergram_bot_from_client(eg));
    ...
}
```

`evergram_bot_poll()` is the embeddable form of `evergram_bot_run()`: it pumps
the client, fires a reconnect when the backoff timer is due, applies the
nickname and drains the mailbox. Calls that block (like `evergram_chat_create`)
must be made between polls, never from inside a handler.

Using the mailbox changes one behaviour: without it, an undecryptable payload is
still delivered with `text == NULL`; with it, delivery is simply postponed.

## Ownership rules

* `evergram_create` copies wallet, device, and platform. The caller keeps
  ownership of everything it passed in and may free it immediately.
* `evergram_destroy` zeroes the copied secrets, tears down the transport, and
  frees the client. It accepts `NULL`.
* Callback arguments are borrowed: `evergram_message_t.text` and
  `reply_to_message_id` point into the decoded frame and are only valid for the
  duration of that callback. Copy what you need to keep.
* `evergram_identity_save` creates the file with mode 0600 and replaces it
  atomically (temp file + `rename`). Secrets never reach a world-readable file.
* Strings returned by `evergram_status_str`, `transport_last_error`, and
  `evergram_log_level_from_name` are static or borrowed; never free them.

## Error handling

Every fallible function returns `evergram_status_t`; `EVERGRAM_OK` is zero, so
`if (status)` reads naturally. `evergram_status_str` maps any code to a stable
name. Errors also reach the registered error callback with the gateway's own
message when one is available.

`evergram_poll` returns `EVERGRAM_ERR_TIMEOUT`, which is not a failure: it
means the round produced no event.

`assert` is not used for runtime validation in the library; it never calls
`abort`/`exit`.

## Invariants

* **Oneofs are dispatched by `*_case`, never by the union members.** protobuf-c
  stores every oneof variant at the same address, so `envelope->send` is also
  `envelope->typing`. Reading a variant pointer instead of the case selector
  reinterprets another variant's payload.
* **ed25519 keys carry the `0xED` prefix.** `xrpl_address_from_public_key`
  rejects keys without it, so an address can never be derived from a
  differently hashed representation of the same key.
* **The address is derived from the prefixed key**:
  `base58check(0x00 || RIPEMD160(SHA256(0xED || public_key)))`, matching
  `ripple-keypairs`.
* **Message boundaries survive the transport.** `rxqueue` keeps frame
  boundaries, so two messages delivered in one read event cannot be parsed as
  one.
* **One allocation has one owner.** Each module frees what it allocates; the
  transport owns the socket and the receive queue; the parser frees the decoded
  message before returning.
* **No mutable globals**, except the process-wide log level in `src/log.c`,
  which is documented at its definition and is set once at startup.
* `struct evergram` is defined exactly once, in `src/internal.h`, so the layout
  cannot drift between translation units.

## Platform assumptions

POSIX.1-2008 is requested (`_POSIX_C_SOURCE=200809L`) for `open`/`fdopen` file
permissions, `rename`, `unlink`, and `strnlen`. Everything else is C17 plus the
three C libraries above. No endianness assumptions: all wire fields are encoded
by protobuf-c.

## Known limitations

* A `public_group` channel is joined with `evergram_visitor_subscribe_channel()`
  and is *not* re-established automatically after a reconnect: unlike a 1:1
  room, it is not a slot that a `RELAY_JOINED` frame can re-claim, so the
  application subscribes again (the `widget-channel-bot` example does it from
  its loop, never from a callback, because subscribing is a synchronous call).
  The reference SDK performs this resubscribe internally.

1. **Some protocol areas are not ported yet.** Working today: XRPL auth, device
   registration, E2EE, chat sync (delta, paginated, with removals), chat
   create/leave, local chat metadata, membership and roles, invites, join
   requests and chat requests/group invites with approve/deny, blocking, profile
   and presence, explicit chat key rotation, send/reply/react/edit/delete/typing,
   1:1 visitor rooms and `public_group` channels, widget creation and
   configuration, account access and reputation, and a bot layer with
   reconnection and mailbox delivery. Still missing: message history (the
   protocol has no query for past messages), the on-chain purchase RPCs the
   reference SDK leaves unwrapped (`InitiatePurchase`/`VerifyPurchase`/
   `ClaimPro` — the SDK here does wrap those four, but no live network has
   verified them — the anonymous magic-link joiner, and the ledger transport of
   `xahau-tip-bot` (its encoding is verified against the reference library, its
   socket is not: nothing here has been pointed at a live Xahau node).
2. **The core client does not reconnect on its own.** A dropped websocket leaves
   it idle until `evergram_start()` is called again; reconnection with
   exponential backoff belongs to the bot layer.
3. **Single-threaded.** `evergram_poll` must be called from one thread.
4. **No ABI versioning.** `libevergram.so` has no soname suffix yet; see
   "Artifacts and ABI".

### Xahau/XRPL interoperability

`tests/xahau_vectors.h` is generated by `tools/gen_xahau_vectors.mjs` from the
`xrpl` package — the library the TypeScript example submits with — for fixed
accounts and transactions. `tests/test_xahau_tx.c` then asserts that the C
implementation produces the **same signing payload, the same signed blob and the
same transaction hash**, byte for byte. Ed25519 is deterministic, so this is
equality rather than mere verification, and it is the only honest way to check a
hand-written binary format: a decoder of my own could agree with itself and still
be wrong on the wire.

It also pins the details that are easy to get subtly wrong: the
`0x4000000000…` native-amount marker, field-code ordering (including
`NetworkID`, which Xahau requires and XRPL mainnet omits), and the `TXN\0`
prefix the transaction id hashes.

```sh
make xahau-vectors TS_SDK=/path/to/evergram-sdk
```

The ledger *transport* is a thin JSON-RPC client over websocket, carrying only
the calls a tip needs: `account_info`, `server_state`, `ledger_current_index`,
`server_info`, `fee`, `submit` and `tx`.

### TypeScript interoperability

`tests/interop_vectors.h` is generated by `tools/gen_interop_vectors.mjs`, which
loads the TypeScript SDK's own modules and asks them to produce the artifacts —
nothing in it is a reimplementation. `tests/test_interop.c` then proves:

* the same seed derives the same XRPL keypair and address in both SDKs;
* the authentication signature over the gateway's challenge is byte-identical
  (ed25519 is deterministic, so this is equality, not just verification);
* the chat key the gateway seals for a device opens here (`nacl.box`);
* a message the reference SDK encrypted decrypts here (`nacl.secretbox`);
* the payment and audio envelopes are byte-identical in both directions;
* a visitor-room relay frame from the reference SDK decodes here.

Regenerate against a checkout with its dependencies installed:

```sh
make interop-vectors TS_SDK=/path/to/evergram-sdk
```

The output is deterministic, so a rebuild with the same SDK version must leave
the file (and therefore the test) unchanged.

## Operational notes

* **One connection per identity+device.** Running two clients with the same
  wallet and device id at once makes the gateway reject the second
  authentication (it surfaces as `invalid_signed_message_signature`), because
  the challenge nonce and session belong to one socket. Stop the previous
  process before starting another.
* The gateway rate-limits `is_typing=true` to roughly one per two seconds per
  identity+device and silently drops the excess.

## Differences from the original evergram-c port

This library replaces `evergram-c`, which it was written from; that original is
no longer in the tree. Same behaviour, plus:

| Area | evergram-c (original) | this library |
| --- | --- | --- |
| Public key sent to the gateway | 64 hex chars, rejected as `invalid_signed_message_signature` | 66 chars with the `0xED` prefix |
| Account address | hashed 32 bytes, rejected as `invalid_signed_message_address` | hashed `0xED || key`, matching `ripple-keypairs` |
| `RegisterDevice` | oneof case never set, serialized to 0 bytes and never sent | case set, 0-byte payload rejected |
| Auth retry | resent immediately in a tight loop | sent after `RegisterDeviceResponse` |
| Envelope dispatch | `envelope->send` used as a type test, segfault on TYPING | `content_case` switch; TYPING and REACT reach their callbacks |
| `sEd...` seed import | rejected (wrong version prefix) | accepted (`0x01 0xE1 0x4B`) |
| Receive path | two buffers, no frame boundaries | one rx queue with frame boundaries (unit tested) |
| Private state | `struct evergram` duplicated in three files | defined once in `src/internal.h` |
| Request ids | constant `1` | per-client counter starting at 1 |
| Logging | unconditional `printf` traces | leveled (`EVERGRAM_LOG`), lws noise silenced |
| Identity secrets | plain `fopen`, secrets left in memory | mode 0600, atomic replace, wiped buffers |
| `hs_state` | marked authenticated on send | set only when the gateway confirms |
| Message bodies | base64 ciphertext delivered as `text`; outgoing sent in the clear | decrypted with `secretbox`; outgoing encrypted, `text` is NULL when undecryptable |
| Chat keys | never stored | learned from every ChatInfo carrier, auto chat sync after auth |
| Envelopes | no `device`, `ts` or identity-key sender | `device`, `ts` and `"1:<address>"` sender, like the TypeScript SDK |
| Message lifecycle | send only | send, reply, react, unreact, edit, delete, typing, edited/deleted callbacks |
| Chats | nothing | local store (+ create/leave calls), synced automatically |
| Groups | nothing | members, roles, moderated mode, invites, join requests, blocking |
| Reconnection | none (`auto_reconnect` declared but never read) | exponential backoff with jitter, re-auth and chat resync |
| Undecryptable messages | delivered as raw base64 in `text` | held in a mailbox and delivered once the key arrives |
| Examples | 9 bots | `echo-bot`, `moderation-bot`, `trivia-bot`, `regular-key-auth-check` and `minimal` ported so far |
| Request correlation | constant `request_id = 1`, never serialized | per-client counter, proto2 presence flag set, responses matched |
| Artifacts | `.a` and `.so`, every internal symbol exported | `.a` and `.so`, only `EVERGRAM_API` exported |
| Example linkage | needs `LD_LIBRARY_PATH` | rpath, runs from the build tree |
| Tests | none | 39 cases / 5k checks, ASan+UBSan clean |

## Tests

`make test` runs deterministic unit tests:

* `test_base58.c` — roundtrips, checksum rejection, alphabet limits, zero bytes
* `test_rxqueue.c` — frame assembly, fragmentation, ordering, compaction
* `test_xrpl.c` — seed forms, key derivation, address rules, and a signature
  vector captured from a live session
* `test_identity.c` — generation, file roundtrip, file mode, legacy files
* `test_parser.c` — envelope dispatch per content type, malformed input, and two
  integration paths driven by tweetnacl-generated vectors: opening a sealed chat
  key and then decrypting a `SEND`/`REACT`/`EDIT` body
* `test_e2ee.c` — base64, sealed-key opening, secretbox roundtrip, fail-closed
  tamper handling, all against golden vectors from `tweetnacl`
* `test_chatkeys.c` — key store behaviour, growth and NULL safety
* `test_chats.c` — chat store upsert, participant replacement, iteration, NULL
* `test_backoff.c` — the reconnect delay curve, asserted exactly
* `test_content.c` — text vs audio vs payment envelope classification, the
  structured decode of every envelope, and the builders both directions
* `test_json.c` — decoding and encoding protocol payloads, including escapes,
  surrogate pairs, raw UTF-8 pass-through and malformed input
* `test_relay.c` — relay frames: encrypted text/react/edit/remove parsed from
  tweetnacl vectors, plaintext typing/presence/moderation/lifecycle frames,
  kind mapping and fail-closed handling of a wrong room key
* inside `test_identity.c` and `test_bot.c`, the RegularKey wallet rules and the
  typing-delay curve
* `test_bot.c` — identity persistence plus the mailbox end to end: a `SEND`
  with no key is held, and delivered once a sealed key arrives
* `test_visitor.c` — visitor rooms: a sealed room key offered to the owner, every
  encrypted frame kind decrypted, session states, channel presence/moderation
  and the fail-closed paths (a key sealed for another device, a tampered seal, an
  oversized payload)
* `test_requests.c` — chat requests and group invites reported exactly once
  whether they arrive live or in the boot sync, `MISSING` chats dropped with
  their keys, the delta-sync version maps, and account access/reputation
* `test_interop.c` — interoperability with the reference TypeScript SDK, using
  vectors generated by the SDK's own sources (see below)
* `test_widgets.c` — the widget wire contract: only flagged config fields are
  sent, widget and info records map across intact, and listing refuses to
  silently truncate a caller's array
* `test_xahau_tx.c` — the ledger half of the tip bot: account-id decoding,
  payments byte-identical to the `xrpl` package (with and without a network id),
  the transaction-hash rule, the JSON-RPC request shape, tip-command parsing and
  amount-to-drops conversion
* `test_purchase.c` — the purchase mapping: subscriptions and their expiry, the
  transaction fields, an open intent from another device winning over a fresh
  one, and the already-subscribed answer
* `test_webhook.c` — the example HTTP helper against a real forked server: the
  request line, content type, framing and body byte for byte, plus the
  connection-refused path (only built where libcurl is available)
* and inside `test_parser.c`, regression tests for proto2 presence flags and for
  matching responses to the pending call
