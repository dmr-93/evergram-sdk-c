#include <sodium.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "chatkeys.h"
#include "e2ee.h"
#include "evergram.pb-c.h"
#include "base58.h"
#include "identity.h"
#include "internal.h"
#include "xrpl.h"
#include "relay.h"

#define DEFAULT_PLATFORM "Terminal"
#define MESSAGE_ID_BYTES 32
#define MESSAGE_ID_HEX_CHARS (2 * MESSAGE_ID_BYTES)
#define CHAIN_FAMILY_XRPL 1

/* --- transport callbacks -------------------------------------------------- */

static void on_transport_open(void *context) {
    evergram_t *eg = context;
    eg->state = EG_STATE_AWAITING_CHALLENGE;
    EG_DEBUG("websocket open, waiting for auth challenge");
}

static void on_transport_closed(void *context) {
    evergram_t *eg = context;

    eg->state = EG_STATE_IDLE;
    eg->challenge_len = 0;
    sodium_memzero(eg->challenge, sizeof(eg->challenge));
    EG_INFO("connection closed");

    if (eg->on_disconnected != NULL) {
        eg->on_disconnected(eg);
    }
}

static void on_transport_error(void *context, evergram_status_t status, const char *detail) {
    evergram_emit_error((evergram_t *)context, status, detail);
}

static void on_transport_message(void *context, const uint8_t *data, size_t len) {
    parser_dispatch((evergram_t *)context, data, len);
}

/* --- internal helpers ----------------------------------------------------- */

uint32_t evergram_take_request_id(evergram_t *eg) {
    eg->next_request_id++;
    if (eg->next_request_id == 0) {
        eg->next_request_id = 1; /* 0 means "unset" on the wire */
    }
    return eg->next_request_id;
}

void evergram_emit_error(evergram_t *eg, evergram_status_t status, const char *detail) {
    const char *text = detail != NULL ? detail : evergram_status_str(status);
    EG_ERROR("%s: %s", evergram_status_str(status), text);

    if (eg != NULL && eg->on_error != NULL) {
        eg->on_error(eg, status, text);
    }
}

evergram_status_t evergram_send_client_message(evergram_t *eg,
                                               const struct Evergram__ClientMessage *message,
                                               const char *label) {
    size_t size = evergram__client_message__get_packed_size(message);
    if (size == 0) {
        EG_ERROR("%s serialized to 0 bytes", label);
        return EVERGRAM_ERR_PROTOCOL;
    }

    uint8_t *packed = malloc(size);
    if (packed == NULL) {
        return EVERGRAM_ERR_NO_MEMORY;
    }

    evergram__client_message__pack(message, packed);
    evergram_status_t status = transport_send(eg->transport, packed, size);
    sodium_memzero(packed, size);
    free(packed);

    if (status != EVERGRAM_OK) {
        EG_ERROR("cannot send %s: %s", label, evergram_status_str(status));
    } else {
        EG_DEBUG("sent %s (%zu bytes, request %u)", label, size, message->request_id);
    }
    return status;
}

static void random_id_hex(char *out, size_t out_size) {
    uint8_t random[MESSAGE_ID_BYTES];
    randombytes_buf(random, sizeof(random));
    sodium_bin2hex(out, out_size, random, sizeof(random));
    sodium_memzero(random, sizeof(random));
}

/*
 * Outgoing envelopes. Every content variant lives in the same struct so one
 * shape covers SEND, REACT, EDIT and TYPING; only the matching field is
 * attached to the envelope.
 */
typedef struct {
    Evergram__Device device;
    Evergram__SendContent send;
    Evergram__ReactContent react;
    Evergram__EditContent edit;
    Evergram__TypingContent typing;
    Evergram__Envelope envelope;
} outgoing_envelope_t;

static void envelope_begin(outgoing_envelope_t *out, const evergram_t *eg, const char *type,
                           const char *chat_id) {
    evergram__device__init(&out->device);
    out->device.device_id = (char *)eg->device.device_id;
    out->device.device_pub_hex = (char *)eg->device.public_key_hex;

    evergram__envelope__init(&out->envelope);
    out->envelope.type = (char *)type;
    out->envelope.device = &out->device;
    out->envelope.chat_id = (char *)chat_id;
    out->envelope.sender = (char *)eg->identity_key;
    out->envelope.has_ts = 1;
    out->envelope.ts = (int64_t)evergram_now_ms();
}

static evergram_status_t envelope_send(evergram_t *eg, outgoing_envelope_t *out,
                                       const char *label) {
    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    evergram_set_request_id(&message, evergram_take_request_id(eg));
    message.envelope = &out->envelope;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_ENVELOPE;

    return evergram_send_client_message(eg, &message, label);
}

/* Encrypts into the client-owned ciphertext buffer; no allocation per message. */
static evergram_status_t encrypt_for_chat(evergram_t *eg, const char *chat_id,
                                          const char *plaintext, char *nonce_b64,
                                          size_t nonce_b64_size) {
    const uint8_t *key = chatkeys_get(eg->chat_keys, chat_id);
    if (key == NULL) {
        EG_WARN("no symmetric key known for chat %s", chat_id);
        return EVERGRAM_ERR_NO_CHAT_KEY;
    }

    return e2ee_encrypt(key, plaintext, nonce_b64, nonce_b64_size, eg->ciphertext_buffer,
                        sizeof(eg->ciphertext_buffer));
}

static evergram_status_t require_connected(const evergram_t *eg) {
    if (eg == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (eg->state != EG_STATE_AUTHENTICATED) {
        return EVERGRAM_ERR_NOT_CONNECTED;
    }
    return EVERGRAM_OK;
}

static evergram_status_t require_authenticated(const evergram_t *eg, const char *chat_id) {
    evergram_status_t status = require_connected(eg);
    if (status != EVERGRAM_OK) {
        return status;
    }
    if (chat_id == NULL || chat_id[0] == '\0' || strlen(chat_id) >= EVERGRAM_CHAT_ID_SIZE) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    return EVERGRAM_OK;
}

/* --- request/response ----------------------------------------------------- */

static void call_release(evergram_t *eg) {
    if (eg->call.response != NULL) {
        evergram__server_message__free_unpacked(eg->call.response, NULL);
        eg->call.response = NULL;
    }
    eg->call.pending = false;
    eg->call.resolved = false;
}

void evergram_set_request_id(struct Evergram__ClientMessage *message, uint32_t request_id) {
    message->request_id = request_id;
    message->has_request_id = 1;
}

evergram_status_t evergram_check_status(evergram_t *eg,
                                        const struct Evergram__ResponseStatus *status) {
    if (status != NULL && status->ok) {
        eg->last_error_code[0] = '\0';
        eg->last_error_message[0] = '\0';
        return EVERGRAM_OK;
    }

    snprintf(eg->last_error_code, sizeof(eg->last_error_code), "%s",
             status != NULL && status->code != NULL ? status->code : "");
    snprintf(eg->last_error_message, sizeof(eg->last_error_message), "%s",
             status != NULL && status->message != NULL ? status->message
                                                       : "gateway rejected the request");
    return EVERGRAM_ERR_GATEWAY;
}

evergram_status_t evergram_call(evergram_t *eg, struct Evergram__ClientMessage *message,
                                uint32_t expected_case, int timeout_ms,
                                struct Evergram__ServerMessage **response) {
    if (eg == NULL || message == NULL || response == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (eg->state != EG_STATE_AUTHENTICATED) {
        return EVERGRAM_ERR_NOT_CONNECTED;
    }
    if (eg->call.pending) {
        return EVERGRAM_ERR_STATE; /* one call at a time */
    }

    *response = NULL;

    evergram_set_request_id(message, evergram_take_request_id(eg));
    eg->call.pending = true;
    eg->call.resolved = false;
    eg->call.response = NULL;
    eg->call.request_id = message->request_id;
    eg->call.expected_case = expected_case;

    evergram_status_t status = evergram_send_client_message(eg, message, "request");
    if (status != EVERGRAM_OK) {
        call_release(eg);
        return status;
    }

    int budget = timeout_ms >= 0 ? timeout_ms : EVERGRAM_DEFAULT_TIMEOUT_MS;
    uint64_t deadline = evergram_now_ms() + (uint64_t)budget;

    while (!eg->call.resolved) {
        uint64_t now = evergram_now_ms();
        if (now >= deadline) {
            call_release(eg);
            return EVERGRAM_ERR_TIMEOUT;
        }

        uint64_t left = deadline - now;
        int slice = left > 100u ? 100 : (int)left;
        evergram_status_t polled = transport_service(eg->transport, slice);
        if (polled != EVERGRAM_OK && polled != EVERGRAM_ERR_TIMEOUT) {
            call_release(eg);
            return polled;
        }
    }

    *response = eg->call.response;
    return EVERGRAM_OK;
}

void evergram_call_finish(evergram_t *eg) {
    if (eg != NULL) {
        call_release(eg);
    }
}

const char *evergram_last_error(const evergram_t *eg) {
    if (eg == NULL || eg->last_error_message[0] == '\0') {
        return NULL;
    }
    return eg->last_error_message;
}

const char *evergram_last_error_code(const evergram_t *eg) {
    if (eg == NULL || eg->last_error_code[0] == '\0') {
        return NULL;
    }
    return eg->last_error_code;
}

evergram_status_t evergram_apply_chat_record(evergram_t *eg,
                                             const evergram_chat_info_t *record) {
    if (eg == NULL || record == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    return chats_upsert(eg->chats, record);
}

/* --- public API ----------------------------------------------------------- */

evergram_t *evergram_create(const evergram_options_t *options) {
    if (options == NULL || options->url == NULL || options->wallet == NULL ||
        options->device == NULL) {
        return NULL;
    }
    if (options->url[0] == '\0' || strlen(options->url) >= EVERGRAM_URL_SIZE) {
        return NULL;
    }
    if (options->wallet->address[0] == '\0') {
        return NULL;
    }
    if (sodium_init() < 0) {
        return NULL;
    }

    evergram_t *eg = calloc(1, sizeof(*eg));
    if (eg == NULL) {
        return NULL;
    }

    const char *platform = options->platform != NULL ? options->platform : DEFAULT_PLATFORM;
    if (strlen(platform) >= sizeof(eg->platform)) {
        free(eg);
        return NULL;
    }

    int written = snprintf(eg->identity_key, sizeof(eg->identity_key), "%d:%s",
                           CHAIN_FAMILY_XRPL, options->wallet->address);
    if (written < 0 || (size_t)written >= sizeof(eg->identity_key)) {
        free(eg);
        return NULL;
    }

    snprintf(eg->url, sizeof(eg->url), "%s", options->url);
    snprintf(eg->platform, sizeof(eg->platform), "%s", platform);
    eg->wallet = *options->wallet;
    eg->device = *options->device;
    eg->user_data = options->user_data;
    eg->state = EG_STATE_IDLE;

    eg->chat_keys = chatkeys_create();
    eg->room_keys = chatkeys_create();
    eg->chats = chats_create();
    if (eg->chat_keys == NULL || eg->room_keys == NULL || eg->chats == NULL) {
        chatkeys_destroy(eg->chat_keys);
        chatkeys_destroy(eg->room_keys);
        chats_destroy(eg->chats);
        sodium_memzero(eg, sizeof(*eg));
        free(eg);
        return NULL;
    }

    const transport_events_t events = {
        .on_open = on_transport_open,
        .on_closed = on_transport_closed,
        .on_error = on_transport_error,
        .on_message = on_transport_message,
        .context = eg,
    };

    eg->transport = transport_create(eg->url, &events);
    if (eg->transport == NULL) {
        chatkeys_destroy(eg->chat_keys);
        chatkeys_destroy(eg->room_keys);
        chats_destroy(eg->chats);
        sodium_memzero(eg, sizeof(*eg));
        free(eg);
        return NULL;
    }

    EG_DEBUG("client created for %s as %s", eg->url, eg->identity_key);
    return eg;
}

void evergram_destroy(evergram_t *eg) {
    if (eg == NULL) {
        return;
    }

    transport_destroy(eg->transport);
    chatkeys_destroy(eg->chat_keys);
    chatkeys_destroy(eg->room_keys);
    chats_destroy(eg->chats);
    free(eg->pending_requests);
    free(eg->pending_invites);
    call_release(eg);
    evergram_wallet_wipe(&eg->wallet);
    evergram_device_wipe(&eg->device);
    sodium_memzero(eg, sizeof(*eg));
    free(eg);
}

evergram_status_t evergram_start(evergram_t *eg) {
    if (eg == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (eg->state != EG_STATE_IDLE) {
        return EVERGRAM_ERR_STATE;
    }

    eg->state = EG_STATE_CONNECTING;
    evergram_status_t status = transport_connect(eg->transport);
    if (status != EVERGRAM_OK) {
        eg->state = EG_STATE_IDLE;
    }
    return status;
}

evergram_status_t evergram_poll(evergram_t *eg, int timeout_ms) {
    if (eg == NULL || timeout_ms < 0) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    return transport_service(eg->transport, timeout_ms);
}

bool evergram_is_connected(const evergram_t *eg) {
    return eg != NULL && eg->state == EG_STATE_AUTHENTICATED;
}

bool evergram_has_chat_key(const evergram_t *eg, const char *chat_id) {
    return eg != NULL && chatkeys_has(eg->chat_keys, chat_id);
}

void evergram_on_message(evergram_t *eg, evergram_message_fn fn) {
    if (eg != NULL) {
        eg->on_message = fn;
    }
}

void evergram_on_message_edited(evergram_t *eg, evergram_message_edited_fn fn) {
    if (eg != NULL) {
        eg->on_message_edited = fn;
    }
}

void evergram_on_message_deleted(evergram_t *eg, evergram_message_deleted_fn fn) {
    if (eg != NULL) {
        eg->on_message_deleted = fn;
    }
}

void evergram_on_reaction(evergram_t *eg, evergram_reaction_fn fn) {
    if (eg != NULL) {
        eg->on_reaction = fn;
    }
}

void evergram_on_typing(evergram_t *eg, evergram_typing_fn fn) {
    if (eg != NULL) {
        eg->on_typing = fn;
    }
}

void evergram_on_error(evergram_t *eg, evergram_error_fn fn) {
    if (eg != NULL) {
        eg->on_error = fn;
    }
}

void evergram_on_connected(evergram_t *eg, evergram_connected_fn fn) {
    if (eg != NULL) {
        eg->on_connected = fn;
    }
}

void evergram_on_disconnected(evergram_t *eg, evergram_disconnected_fn fn) {
    if (eg != NULL) {
        eg->on_disconnected = fn;
    }
}

void *evergram_user_data(const evergram_t *eg) {
    return eg != NULL ? eg->user_data : NULL;
}

evergram_status_t evergram_address_to_account_id(const char *address,
                                                     uint8_t out[EVERGRAM_ACCOUNT_ID_BYTES]) {
    if (address == NULL || out == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    uint8_t decoded[BASE58_DECODED_MAX];
    size_t decoded_len = 0;
    evergram_status_t status =
        base58check_decode(address, decoded, sizeof(decoded), &decoded_len);
    if (status != EVERGRAM_OK) {
        return status;
    }
    /* 1 version byte + the 20-byte id; the checksum was verified on the way in. */
    if (decoded_len != 1u + EVERGRAM_ACCOUNT_ID_BYTES || decoded[0] != XRPL_ACCOUNT_VERSION) {
        sodium_memzero(decoded, sizeof(decoded));
        return EVERGRAM_ERR_ENCODING;
    }

    memcpy(out, decoded + 1, EVERGRAM_ACCOUNT_ID_BYTES);
    sodium_memzero(decoded, sizeof(decoded));
    return EVERGRAM_OK;
}

/* --- misc ------------------------------------------------------------------ */

/*
 * Fills the buffer with cryptographically secure random bytes from the same
 * source the SDK uses for keys and request ids. Exposed because callers need
 * random material the protocol does not generate for them (a widget's channel
 * key is 32 random bytes as hex).
 */
evergram_status_t evergram_random_bytes(uint8_t *out, size_t length) {
    if (out == NULL || length == 0) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    randombytes_buf(out, length);
    return EVERGRAM_OK;
}

/* --- identity -------------------------------------------------------------- */

/*
 * The seed may be written either way this SDK accepts elsewhere: the raw
 * 32-byte ed25519 seed as hex (what evergram_identity_save writes), or the
 * base58 family seed an XRPL wallet exports ("sEd..."). Both describe the same
 * keypair, so the derived address matches either way.
 */
evergram_status_t evergram_wallet_from_seed(const char *seed, evergram_wallet_t *out) {
    if (seed == NULL || out == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    uint8_t bytes[XRPL_SEED_BYTES];
    evergram_status_t status = xrpl_seed_from_text(seed, bytes);
    if (status != EVERGRAM_OK) {
        sodium_memzero(bytes, sizeof(bytes));
        return status;
    }

    status = identity_wallet_from_seed(bytes, out);
    sodium_memzero(bytes, sizeof(bytes));
    if (status != EVERGRAM_OK) {
        evergram_wallet_wipe(out);
    }
    return status;
}

/* --- purchases ------------------------------------------------------------- */

/*
 * The purchase flow is the one protocol area the reference SDK leaves
 * unwrapped, so these four calls follow the proto rather than another SDK. None
 * of them touches a ledger: initiate returns a transaction for the caller to
 * sign and submit, and verify takes the resulting hash.
 */

void evergram_subscription_from_proto(const Evergram__Subscription *subscription,
                                      evergram_subscription_t *out) {
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    if (subscription == NULL) {
        return;
    }

    evergram_copy_bounded(out->type, sizeof(out->type),
                          subscription->type != NULL ? subscription->type : "");
    out->issued_at_ms =
        subscription->has_issued_at && subscription->issued_at > 0
            ? (uint64_t)subscription->issued_at
            : 0;
    out->expires_at_ms =
        subscription->has_expires_at && subscription->expires_at > 0
            ? (uint64_t)subscription->expires_at
            : 0;
    out->days_remaining = subscription->has_days_remaining ? subscription->days_remaining : 0;
    evergram_copy_bounded(out->token_id, sizeof(out->token_id),
                          subscription->token_id != NULL ? subscription->token_id : "");
}

static void payment_from_proto(const Evergram__PaymentTxn *payment, evergram_payment_txn_t *out) {
    memset(out, 0, sizeof(*out));
    if (payment == NULL) {
        return;
    }

    evergram_copy_bounded(out->transaction_type, sizeof(out->transaction_type),
                          payment->transactiontype != NULL ? payment->transactiontype : "");
    evergram_copy_bounded(out->destination, sizeof(out->destination),
                          payment->destination != NULL ? payment->destination : "");
    evergram_copy_bounded(out->amount, sizeof(out->amount),
                          payment->amount != NULL ? payment->amount : "");

    for (size_t i = 0; i < payment->n_hookparameters && i < EVERGRAM_MAX_HOOK_PARAMS; i++) {
        const Evergram__PaymentTxn__HookParameterWrapper *wrapper = payment->hookparameters[i];
        if (wrapper == NULL || wrapper->hookparameter == NULL) {
            continue;
        }
        evergram_copy_bounded(out->hook_params[out->hook_param_count].name,
                              EVERGRAM_HOOK_PARAM_NAME_SIZE,
                              wrapper->hookparameter->hookparametername != NULL
                                  ? wrapper->hookparameter->hookparametername
                                  : "");
        evergram_copy_bounded(out->hook_params[out->hook_param_count].value,
                              EVERGRAM_HOOK_PARAM_VALUE_SIZE,
                              wrapper->hookparameter->hookparametervalue != NULL
                                  ? wrapper->hookparameter->hookparametervalue
                                  : "");
        out->hook_param_count++;
    }

    for (size_t i = 0; i < payment->n_memos && i < EVERGRAM_MAX_MEMOS; i++) {
        const Evergram__PaymentTxn__MemoWrapper *wrapper = payment->memos[i];
        if (wrapper == NULL || wrapper->memo == NULL) {
            continue;
        }
        evergram_copy_bounded(out->memos[out->memo_count].data, EVERGRAM_MEMO_DATA_SIZE,
                              wrapper->memo->memodata != NULL ? wrapper->memo->memodata : "");
        evergram_copy_bounded(out->memos[out->memo_count].type, EVERGRAM_MEMO_TYPE_SIZE,
                              wrapper->memo->memotype != NULL ? wrapper->memo->memotype : "");
        evergram_copy_bounded(out->memos[out->memo_count].format, EVERGRAM_MEMO_TYPE_SIZE,
                              wrapper->memo->memoformat != NULL ? wrapper->memo->memoformat : "");
        out->memo_count++;
    }
}

void evergram_purchase_from_initiate(const Evergram__InitiatePurchaseResponse *response,
                                     evergram_purchase_t *out) {
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    if (response == NULL) {
        return;
    }

    evergram_copy_bounded(out->intent_id, sizeof(out->intent_id),
                          response->intent_id != NULL ? response->intent_id : "");

    out->has_payment = response->payment != NULL;
    payment_from_proto(response->payment, &out->payment);

    out->has_subscription = response->subscription != NULL;
    evergram_subscription_from_proto(response->subscription, &out->subscription);

    if (response->already_subscribed != NULL) {
        out->already_subscribed = true;
        const Evergram__AlreadySubscribedInfo *info = response->already_subscribed;
        out->existing_subscription.issued_at_ms =
            info->has_issued_at && info->issued_at > 0 ? (uint64_t)info->issued_at : 0;
        out->existing_subscription.expires_at_ms =
            info->has_expires_at && info->expires_at > 0 ? (uint64_t)info->expires_at : 0;
        out->existing_subscription.days_remaining =
            info->has_days_remaining ? info->days_remaining : 0;
        evergram_copy_bounded(out->existing_subscription.token_id,
                              sizeof(out->existing_subscription.token_id),
                              info->token_id != NULL ? info->token_id : "");
        evergram_copy_bounded(out->existing_source, sizeof(out->existing_source),
                              info->source != NULL ? info->source : "");
    }

    if (response->existing_intent != NULL) {
        out->has_existing_intent = true;
        const Evergram__ExistingIntent *intent = response->existing_intent;
        evergram_copy_bounded(out->existing_intent.plan, sizeof(out->existing_intent.plan),
                              intent->plan != NULL ? intent->plan : "");
        evergram_copy_bounded(out->existing_intent.intent_id,
                              sizeof(out->existing_intent.intent_id),
                              intent->intent_id != NULL ? intent->intent_id : "");
        out->existing_intent.created_at_ms =
            intent->has_created_at && intent->created_at > 0 ? (uint64_t)intent->created_at : 0;
        out->existing_intent.expires_at_ms =
            intent->has_expires_at && intent->expires_at > 0 ? (uint64_t)intent->expires_at : 0;
        /* The old intent's transaction is what should be paid, so it wins. */
        if (intent->payment != NULL) {
            out->has_payment = true;
            payment_from_proto(intent->payment, &out->payment);
        }
    }
}

/* True while the subscription has not expired. `now_ms` is injectable so this
 * stays a pure function of its inputs. */
bool evergram_subscription_is_active(const evergram_subscription_t *subscription, uint64_t now_ms) {
    if (subscription == NULL || subscription->expires_at_ms == 0) {
        return false;
    }
    return now_ms < subscription->expires_at_ms;
}

/*
 * Starts a purchase: the gateway answers with the transaction to submit (or with
 * the subscription/intent that already exists). `account` defaults to this
 * identity's address, and `pro_observation_jwt` may be NULL.
 */
evergram_status_t evergram_purchase_initiate(evergram_t *eg, const char *account, const char *plan,
                                            const char *pro_observation_jwt, int timeout_ms,
                                            evergram_purchase_t *out) {
    if (eg == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
    }

    Evergram__InitiatePurchase request;
    evergram__initiate_purchase__init(&request);
    request.account = (char *)(account != NULL ? account : eg->wallet.address);
    request.plan = (char *)(plan != NULL && plan[0] != '\0' ? plan : "pro");
    request.pro_observation_jwt = (char *)(pro_observation_jwt != NULL ? pro_observation_jwt : "");

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.initiate_purchase = &request;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_INITIATE_PURCHASE;

    Evergram__ServerMessage *response = NULL;
    evergram_status_t status = evergram_call(
        eg, &message, EVERGRAM__SERVER_MESSAGE__PAYLOAD_INITIATE_PURCHASE_RESPONSE, timeout_ms,
        &response);
    if (status == EVERGRAM_OK) {
        const Evergram__InitiatePurchaseResponse *result = response->initiate_purchase_response;
        status = evergram_check_status(eg, result != NULL ? result->status : NULL);
        if (status == EVERGRAM_OK) {
            evergram_purchase_from_initiate(result, out);
        }
    }

    evergram_call_finish(eg);
    return status;
}

/* Reports the hash of the submitted payment; the gateway verifies it on-chain. */
evergram_status_t evergram_purchase_verify(evergram_t *eg, const char *intent_id,
                                          const char *tx_hash, const char *pro_observation_jwt,
                                          int timeout_ms, evergram_subscription_t *out) {
    if (eg == NULL || intent_id == NULL || intent_id[0] == '\0' || tx_hash == NULL ||
        tx_hash[0] == '\0') {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
    }

    Evergram__VerifyPurchase request;
    evergram__verify_purchase__init(&request);
    request.intent_id = (char *)intent_id;
    request.tx_hash = (char *)tx_hash;
    request.pro_observation_jwt = (char *)(pro_observation_jwt != NULL ? pro_observation_jwt : "");

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.verify_purchase = &request;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_VERIFY_PURCHASE;

    Evergram__ServerMessage *response = NULL;
    evergram_status_t status = evergram_call(
        eg, &message, EVERGRAM__SERVER_MESSAGE__PAYLOAD_VERIFY_PURCHASE_RESPONSE, timeout_ms,
        &response);
    if (status == EVERGRAM_OK) {
        const Evergram__VerifyPurchaseResponse *result = response->verify_purchase_response;
        status = evergram_check_status(eg, result != NULL ? result->status : NULL);
        if (status == EVERGRAM_OK) {
            evergram_subscription_from_proto(result != NULL ? result->subscription : NULL, out);
        }
    }

    evergram_call_finish(eg);
    return status;
}

/* Activates a subscription that was granted without an on-chain purchase. */
evergram_status_t evergram_purchase_claim_pro(evergram_t *eg, const char *account, int timeout_ms,
                                             evergram_subscription_t *out) {
    if (eg == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
    }

    Evergram__ClaimPro request;
    evergram__claim_pro__init(&request);
    request.account = (char *)(account != NULL ? account : eg->wallet.address);

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.claim_pro = &request;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_CLAIM_PRO;

    Evergram__ServerMessage *response = NULL;
    evergram_status_t status = evergram_call(eg, &message,
                                             EVERGRAM__SERVER_MESSAGE__PAYLOAD_CLAIM_PRO_RESPONSE,
                                             timeout_ms, &response);
    if (status == EVERGRAM_OK) {
        const Evergram__ClaimProResponse *result = response->claim_pro_response;
        status = evergram_check_status(eg, result != NULL ? result->status : NULL);
        if (status == EVERGRAM_OK) {
            evergram_subscription_from_proto(result != NULL ? result->subscription : NULL, out);
        }
    }

    evergram_call_finish(eg);
    return status;
}

/* --- widgets --------------------------------------------------------------- */

/*
 * These two mappings are the whole widget wire contract, so they live apart
 * from the calls and are exercised directly by the tests.
 */

void evergram_fill_widget_config(const evergram_widget_config_t *config,
                                 Evergram__WidgetConfig *out) {
    evergram__widget_config__init(out);
    if (config == NULL) {
        return;
    }

    /* Only the flagged fields travel: the gateway replaces the stored config
     * with what arrives, so sending an unset field would clear it. */
    if (config->has_primary_color) {
        out->primary_color = (char *)config->primary_color;
    }
    if (config->has_logo_url) {
        out->logo_url = (char *)config->logo_url;
    }
    if (config->has_welcome_message) {
        out->welcome_message = (char *)config->welcome_message;
    }
    if (config->has_input_placeholder) {
        out->input_placeholder = (char *)config->input_placeholder;
    }
    if (config->has_agent_name) {
        out->agent_name = (char *)config->agent_name;
    }
    if (config->has_position) {
        out->position = (char *)config->position;
    }
    if (config->has_mode) {
        out->mode = (char *)config->mode;
    }
    if (config->has_channel_key) {
        out->channel_key = (char *)config->channel_key;
    }
}

static void widget_config_from_proto(const Evergram__WidgetConfig *config,
                                     evergram_widget_config_t *out) {
    memset(out, 0, sizeof(*out));
    if (config == NULL) {
        return;
    }

    struct {
        const char *value;
        bool *flag;
        char *target;
        size_t size;
    } fields[] = {
        {config->primary_color, &out->has_primary_color, out->primary_color,
         sizeof(out->primary_color)},
        {config->logo_url, &out->has_logo_url, out->logo_url, sizeof(out->logo_url)},
        {config->welcome_message, &out->has_welcome_message, out->welcome_message,
         sizeof(out->welcome_message)},
        {config->input_placeholder, &out->has_input_placeholder, out->input_placeholder,
         sizeof(out->input_placeholder)},
        {config->agent_name, &out->has_agent_name, out->agent_name, sizeof(out->agent_name)},
        {config->position, &out->has_position, out->position, sizeof(out->position)},
        {config->mode, &out->has_mode, out->mode, sizeof(out->mode)},
        {config->channel_key, &out->has_channel_key, out->channel_key,
         sizeof(out->channel_key)},
    };

    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        if (fields[i].value == NULL) {
            continue;
        }
        evergram_copy_bounded(fields[i].target, fields[i].size, fields[i].value);
        *fields[i].flag = true;
    }
}

void evergram_widget_from_proto(const Evergram__Widget *widget, evergram_widget_t *out) {
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    if (widget == NULL) {
        return;
    }

    evergram_copy_bounded(out->widget_id, sizeof(out->widget_id),
                          widget->widget_id != NULL ? widget->widget_id : "");
    evergram_copy_bounded(out->name, sizeof(out->name), widget->name != NULL ? widget->name : "");
    out->enabled = widget->enabled;
    out->deleted = widget->deleted;
    out->widget_version =
        widget->has_widget_version && widget->widget_version > 0 ? (uint64_t)widget->widget_version
                                                                 : 0;
    out->created_at_ms =
        widget->has_created_at && widget->created_at > 0 ? (uint64_t)widget->created_at : 0;
    out->has_config = widget->config != NULL;
    widget_config_from_proto(widget->config, &out->config);
}

void evergram_widget_info_from_proto(const Evergram__GetWidgetInfoResponse *response,
                                     evergram_widget_info_t *out) {
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    if (response == NULL) {
        return;
    }

    evergram_copy_bounded(out->widget_id, sizeof(out->widget_id),
                          response->widget_id != NULL ? response->widget_id : "");
    evergram_copy_bounded(out->owner_identity_key, sizeof(out->owner_identity_key),
                          response->owner_identity_key != NULL ? response->owner_identity_key : "");
    out->enabled = response->enabled;
    out->device_count = response->n_devices;
    out->has_config = response->config != NULL;
    widget_config_from_proto(response->config, &out->config);
}

/* Creates a widget owned by this identity. `name` may be NULL for a default. */
evergram_status_t evergram_widget_create(evergram_t *eg, const char *name, int timeout_ms,
                                        evergram_widget_t *out) {
    if (eg == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
    }

    Evergram__CreateWidget request;
    evergram__create_widget__init(&request);
    request.name = (char *)(name != NULL ? name : "");

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.create_widget = &request;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_CREATE_WIDGET;

    Evergram__ServerMessage *response = NULL;
    evergram_status_t status = evergram_call(
        eg, &message, EVERGRAM__SERVER_MESSAGE__PAYLOAD_CREATE_WIDGET_RESPONSE, timeout_ms,
        &response);
    if (status == EVERGRAM_OK) {
        const Evergram__CreateWidgetResponse *result = response->create_widget_response;
        status = evergram_check_status(eg, result != NULL ? result->status : NULL);
        if (status == EVERGRAM_OK) {
            evergram_widget_from_proto(result != NULL ? result->widget : NULL, out);
            if (out != NULL && out->widget_id[0] == '\0') {
                status = EVERGRAM_ERR_PROTOCOL; /* the id is the point of creating one */
            }
        }
    }

    evergram_call_finish(eg);
    return status;
}

/* Every widget this identity owns, deleted ones included (the callers that
 * care filter on `deleted`). */
evergram_status_t evergram_widget_list(evergram_t *eg, int timeout_ms, evergram_widget_t *out,
                                      size_t capacity, size_t *count) {
    /* Cleared first: a stale count must never look like a result. */
    if (count != NULL) {
        *count = 0;
    }
    if (eg == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (out == NULL && capacity > 0) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    Evergram__ListWidgets request;
    evergram__list_widgets__init(&request);

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.list_widgets = &request;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_LIST_WIDGETS;

    Evergram__ServerMessage *response = NULL;
    evergram_status_t status = evergram_call(
        eg, &message, EVERGRAM__SERVER_MESSAGE__PAYLOAD_LIST_WIDGETS_RESPONSE, timeout_ms,
        &response);
    if (status == EVERGRAM_OK) {
        const Evergram__ListWidgetsResponse *result = response->list_widgets_response;
        status = evergram_check_status(eg, result != NULL ? result->status : NULL);
        if (status == EVERGRAM_OK && result != NULL) {
            if (result->n_widgets > capacity) {
                /* Reported rather than silently truncated: the caller sized the
                 * array and needs to know it was too small. */
                status = EVERGRAM_ERR_BUFFER_TOO_SMALL;
            } else {
                for (size_t i = 0; i < result->n_widgets; i++) {
                    evergram_widget_from_proto(result->widgets[i], &out[i]);
                }
                if (count != NULL) {
                    *count = result->n_widgets;
                }
            }
        }
    }

    evergram_call_finish(eg);
    return status;
}

evergram_status_t evergram_widget_set_enabled(evergram_t *eg, const char *widget_id, bool enabled,
                                             int timeout_ms, evergram_widget_t *out) {
    if (eg == NULL || widget_id == NULL || widget_id[0] == '\0') {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
    }

    Evergram__UpdateWidget request;
    evergram__update_widget__init(&request);
    request.widget_id = (char *)widget_id;
    request.has_enabled = 1;
    request.enabled = enabled;

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.update_widget = &request;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_UPDATE_WIDGET;

    Evergram__ServerMessage *response = NULL;
    evergram_status_t status = evergram_call(
        eg, &message, EVERGRAM__SERVER_MESSAGE__PAYLOAD_UPDATE_WIDGET_RESPONSE, timeout_ms,
        &response);
    if (status == EVERGRAM_OK) {
        const Evergram__UpdateWidgetResponse *result = response->update_widget_response;
        status = evergram_check_status(eg, result != NULL ? result->status : NULL);
        if (status == EVERGRAM_OK) {
            evergram_widget_from_proto(result != NULL ? result->widget : NULL, out);
        }
    }

    evergram_call_finish(eg);
    return status;
}

/* Replaces this widget's stored configuration. Only the flagged fields travel,
 * so read the current config back from evergram_widget_list() first when the
 * intent is to change one field. */
evergram_status_t evergram_widget_set_config(evergram_t *eg, const char *widget_id,
                                            const evergram_widget_config_t *config,
                                            int timeout_ms) {
    if (eg == NULL || widget_id == NULL || widget_id[0] == '\0' || config == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    Evergram__WidgetConfig wire;
    Evergram__UpdateWidgetConfig request;
    evergram__update_widget_config__init(&request);
    request.widget_id = (char *)widget_id;
    evergram_fill_widget_config(config, &wire);
    request.config = &wire;

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.update_widget_config = &request;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_UPDATE_WIDGET_CONFIG;

    Evergram__ServerMessage *response = NULL;
    evergram_status_t status = evergram_call(
        eg, &message, EVERGRAM__SERVER_MESSAGE__PAYLOAD_UPDATE_WIDGET_CONFIG_RESPONSE, timeout_ms,
        &response);
    if (status == EVERGRAM_OK) {
        const Evergram__UpdateWidgetConfigResponse *result = response->update_widget_config_response;
        status = evergram_check_status(eg, result != NULL ? result->status : NULL);
    }

    evergram_call_finish(eg);
    return status;
}

evergram_status_t evergram_widget_delete(evergram_t *eg, const char *widget_id, int timeout_ms) {
    if (eg == NULL || widget_id == NULL || widget_id[0] == '\0') {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    Evergram__DeleteWidget request;
    evergram__delete_widget__init(&request);
    request.widget_id = (char *)widget_id;

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.delete_widget = &request;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_DELETE_WIDGET;

    Evergram__ServerMessage *response = NULL;
    evergram_status_t status = evergram_call(
        eg, &message, EVERGRAM__SERVER_MESSAGE__PAYLOAD_DELETE_WIDGET_RESPONSE, timeout_ms,
        &response);
    if (status == EVERGRAM_OK) {
        const Evergram__DeleteWidgetResponse *result = response->delete_widget_response;
        status = evergram_check_status(eg, result != NULL ? result->status : NULL);
    }

    evergram_call_finish(eg);
    return status;
}

/* Public widget description; the gateway deliberately answers this without any
 * authorization check, which is what lets an embed ask about its own widget. */
evergram_status_t evergram_widget_get_info(evergram_t *eg, const char *widget_id, int timeout_ms,
                                          evergram_widget_info_t *out) {
    if (eg == NULL || widget_id == NULL || widget_id[0] == '\0') {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
    }

    Evergram__GetWidgetInfo request;
    evergram__get_widget_info__init(&request);
    request.widget_id = (char *)widget_id;

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.get_widget_info = &request;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_GET_WIDGET_INFO;

    Evergram__ServerMessage *response = NULL;
    evergram_status_t status = evergram_call(
        eg, &message, EVERGRAM__SERVER_MESSAGE__PAYLOAD_GET_WIDGET_INFO_RESPONSE, timeout_ms,
        &response);
    if (status == EVERGRAM_OK) {
        const Evergram__GetWidgetInfoResponse *result = response->get_widget_info_response;
        status = evergram_check_status(eg, result != NULL ? result->status : NULL);
        if (status == EVERGRAM_OK) {
            evergram_widget_info_from_proto(result, out);
        }
    }

    evergram_call_finish(eg);
    return status;
}

/* --- account access -------------------------------------------------------- */

const evergram_access_t *evergram_access(const evergram_t *eg) {
    if (eg == NULL || !eg->has_access) {
        return NULL;
    }
    return &eg->access;
}

bool evergram_is_restricted(const evergram_t *eg) {
    return eg != NULL && eg->has_access && eg->access.is_restricted;
}

void evergram_on_restricted(evergram_t *eg, evergram_restricted_fn fn) {
    if (eg != NULL) {
        eg->on_restricted = fn;
    }
}

/* True when the account carries this capability (exact match). */
bool evergram_access_has_capability(const evergram_t *eg, const char *capability) {
    if (eg == NULL || capability == NULL || !eg->has_access) {
        return false;
    }
    for (size_t i = 0; i < eg->access.capability_count; i++) {
        if (strcmp(eg->access.capabilities[i], capability) == 0) {
            return true;
        }
    }
    return false;
}

/* The ledger address on its own, for payment payloads that carry one. */
const char *evergram_address(const evergram_t *eg) {
    return eg != NULL ? eg->wallet.address : NULL;
}

const char *evergram_identity_key(const evergram_t *eg) {
    return eg != NULL ? eg->identity_key : NULL;
}

static evergram_status_t send_message(evergram_t *eg, const char *chat_id, const char *text,
                                      const char *reply_to_message_id) {
    evergram_status_t status = require_authenticated(eg, chat_id);
    if (status != EVERGRAM_OK) {
        return status;
    }
    if (text == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    char nonce_b64[E2EE_NONCE_B64_SIZE];
    status = encrypt_for_chat(eg, chat_id, text, nonce_b64, sizeof(nonce_b64));
    if (status != EVERGRAM_OK) {
        return status;
    }

    char message_id[MESSAGE_ID_HEX_CHARS + 1u];
    random_id_hex(message_id, sizeof(message_id));

    outgoing_envelope_t out;
    envelope_begin(&out, eg, "SEND", chat_id);
    evergram__send_content__init(&out.send);
    out.send.msg_id = message_id;
    out.send.ciphertext = eg->ciphertext_buffer;
    out.send.nonce = nonce_b64;
    out.send.reply_to_msg_id = (char *)(reply_to_message_id != NULL ? reply_to_message_id : "");
    out.envelope.send = &out.send;
    out.envelope.content_case = EVERGRAM__ENVELOPE__CONTENT_SEND;

    status = envelope_send(eg, &out, "envelope(SEND)");

    sodium_memzero(nonce_b64, sizeof(nonce_b64));
    sodium_memzero(message_id, sizeof(message_id));
    return status;
}

evergram_status_t evergram_send(evergram_t *eg, const char *chat_id, const char *text) {
    return send_message(eg, chat_id, text, NULL);
}

evergram_status_t evergram_reply(evergram_t *eg, const evergram_message_t *to, const char *format,
                                 ...) {
    if (to == NULL || format == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    char text[EVERGRAM_TEXT_SIZE];
    va_list args;
    va_start(args, format);
    int length = vsnprintf(text, sizeof(text), format, args);
    va_end(args);

    if (length < 0) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if ((size_t)length >= sizeof(text)) {
        sodium_memzero(text, sizeof(text));
        return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }

    evergram_status_t status =
        send_message(eg, to->chat_id, text, to->message_id[0] != '\0' ? to->message_id : NULL);
    sodium_memzero(text, sizeof(text));
    return status;
}

evergram_status_t evergram_react(evergram_t *eg, const char *chat_id, const char *message_id,
                                 const char *emoji, bool removed) {
    evergram_status_t status = require_authenticated(eg, chat_id);
    if (status != EVERGRAM_OK) {
        return status;
    }
    if (message_id == NULL || message_id[0] == '\0') {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    char nonce_b64[E2EE_NONCE_B64_SIZE];
    const char *ciphertext = "";

    if (!removed) {
        if (emoji == NULL) {
            return EVERGRAM_ERR_INVALID_ARG;
        }
        status = encrypt_for_chat(eg, chat_id, emoji, nonce_b64, sizeof(nonce_b64));
        if (status != EVERGRAM_OK) {
            return status;
        }
        ciphertext = eg->ciphertext_buffer;
    } else {
        nonce_b64[0] = '\0';
    }

    outgoing_envelope_t out;
    envelope_begin(&out, eg, "REACT", chat_id);
    evergram__react_content__init(&out.react);
    out.react.msg_id = (char *)message_id;
    out.react.ciphertext = (char *)ciphertext;
    out.react.nonce = nonce_b64;
    out.react.has_removed = 1;
    out.react.removed = removed ? 1 : 0;
    out.envelope.react = &out.react;
    out.envelope.content_case = EVERGRAM__ENVELOPE__CONTENT_REACT;

    status = envelope_send(eg, &out, removed ? "envelope(REACT-remove)" : "envelope(REACT)");
    sodium_memzero(nonce_b64, sizeof(nonce_b64));
    return status;
}

evergram_status_t evergram_edit_message(evergram_t *eg, const char *chat_id,
                                        const char *message_id, const char *text) {
    evergram_status_t status = require_authenticated(eg, chat_id);
    if (status != EVERGRAM_OK) {
        return status;
    }
    if (message_id == NULL || message_id[0] == '\0' || text == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    char nonce_b64[E2EE_NONCE_B64_SIZE];
    status = encrypt_for_chat(eg, chat_id, text, nonce_b64, sizeof(nonce_b64));
    if (status != EVERGRAM_OK) {
        return status;
    }

    outgoing_envelope_t out;
    envelope_begin(&out, eg, "EDIT", chat_id);
    evergram__edit_content__init(&out.edit);
    out.edit.msg_id = (char *)message_id;
    out.edit.ciphertext = eg->ciphertext_buffer;
    out.edit.nonce = nonce_b64;
    out.edit.has_edited_at = 1;
    out.edit.edited_at = (int64_t)evergram_now_ms();
    out.edit.has_removed = 1;
    out.edit.removed = 0;
    out.envelope.edit = &out.edit;
    out.envelope.content_case = EVERGRAM__ENVELOPE__CONTENT_EDIT;

    status = envelope_send(eg, &out, "envelope(EDIT)");
    sodium_memzero(nonce_b64, sizeof(nonce_b64));
    return status;
}

evergram_status_t evergram_delete_message(evergram_t *eg, const char *chat_id,
                                          const char *message_id) {
    evergram_status_t status = require_authenticated(eg, chat_id);
    if (status != EVERGRAM_OK) {
        return status;
    }
    if (message_id == NULL || message_id[0] == '\0') {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    /* "Delete for everyone" is an edit tombstone with no body. */
    outgoing_envelope_t out;
    envelope_begin(&out, eg, "EDIT", chat_id);
    evergram__edit_content__init(&out.edit);
    out.edit.msg_id = (char *)message_id;
    out.edit.ciphertext = "";
    out.edit.nonce = "";
    out.edit.has_edited_at = 1;
    out.edit.edited_at = (int64_t)evergram_now_ms();
    out.edit.has_removed = 1;
    out.edit.removed = 1;
    out.envelope.edit = &out.edit;
    out.envelope.content_case = EVERGRAM__ENVELOPE__CONTENT_EDIT;

    return envelope_send(eg, &out, "envelope(DELETE)");
}

evergram_status_t evergram_send_typing(evergram_t *eg, const char *chat_id, bool is_typing) {
    evergram_status_t status = require_authenticated(eg, chat_id);
    if (status != EVERGRAM_OK) {
        return status;
    }

    outgoing_envelope_t out;
    envelope_begin(&out, eg, "TYPING", chat_id);
    evergram__typing_content__init(&out.typing);
    out.typing.has_is_typing = 1;
    out.typing.is_typing = is_typing ? 1 : 0;
    out.envelope.typing = &out.typing;
    out.envelope.content_case = EVERGRAM__ENVELOPE__CONTENT_TYPING;

    return envelope_send(eg, &out, "envelope(TYPING)");
}

/*
 * A chat is only reported back when the gateway's version is ahead of the one
 * we hold, so an up-to-date client transfers a map instead of every chat it
 * knows. Metadata versions travel separately, because a moderation change must
 * not look like a key rotation to any device.
 */
evergram_status_t evergram_fill_known_versions(const evergram_t *eg,
                                               struct Evergram__QueryChats *query,
                                               evergram_known_versions_t *scratch) {
    if (eg == NULL || query == NULL || scratch == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    memset(scratch, 0, sizeof(*scratch));

    size_t count = chats_count(eg->chats);
    size_t capacity = count > 0 ? count : 1u;
    scratch->versions = calloc(capacity, sizeof(*scratch->versions));
    scratch->meta = calloc(capacity, sizeof(*scratch->meta));
    scratch->version_entries = calloc(capacity, sizeof(*scratch->version_entries));
    scratch->meta_entries = calloc(capacity, sizeof(*scratch->meta_entries));
    if (scratch->versions == NULL || scratch->meta == NULL || scratch->version_entries == NULL ||
        scratch->meta_entries == NULL) {
        evergram_known_versions_dispose(scratch);
        return EVERGRAM_ERR_NO_MEMORY;
    }

    size_t known = 0;
    for (size_t i = 0; i < count; i++) {
        const evergram_chat_info_t *chat = chats_at(eg->chats, i);
        if (chat == NULL || chat->chat_id[0] == '\0') {
            continue;
        }

        /* proto2 optionals: without has_value the entry serializes as zero,
         * which would ask the gateway for the whole history again. */
        evergram__query_chats__known_versions_entry__init(&scratch->versions[known]);
        scratch->versions[known].key = (char *)chat->chat_id;
        scratch->versions[known].has_value = 1;
        scratch->versions[known].value = (uint32_t)chat->chat_version;
        scratch->version_entries[known] = &scratch->versions[known];

        evergram__query_chats__known_meta_versions_entry__init(&scratch->meta[known]);
        scratch->meta[known].key = (char *)chat->chat_id;
        scratch->meta[known].has_value = 1;
        scratch->meta[known].value = (uint32_t)chat->meta_version;
        scratch->meta_entries[known] = &scratch->meta[known];
        known++;
    }

    query->n_known_versions = known;
    query->known_versions = known > 0 ? scratch->version_entries : NULL;
    query->n_known_meta_versions = known;
    query->known_meta_versions = known > 0 ? scratch->meta_entries : NULL;
    return EVERGRAM_OK;
}

void evergram_known_versions_dispose(evergram_known_versions_t *scratch) {
    if (scratch == NULL) {
        return;
    }
    free(scratch->versions);
    free(scratch->meta);
    free(scratch->version_entries);
    free(scratch->meta_entries);
    memset(scratch, 0, sizeof(*scratch));
}

evergram_status_t evergram_sync_chats_page(evergram_t *eg, const char *cursor) {
    if (eg == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (eg->state != EG_STATE_AUTHENTICATED) {
        return EVERGRAM_ERR_NOT_CONNECTED;
    }

    Evergram__QueryChats query;
    evergram__query_chats__init(&query);
    query.cursor = (char *)(cursor != NULL ? cursor : "");

    evergram_known_versions_t scratch;
    evergram_status_t status = evergram_fill_known_versions(eg, &query, &scratch);
    if (status != EVERGRAM_OK) {
        return status;
    }

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    evergram_set_request_id(&message, evergram_take_request_id(eg));
    message.query_chats = &query;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_QUERY_CHATS;

    status = evergram_send_client_message(eg, &message, "queryChats");
    evergram_known_versions_dispose(&scratch);
    return status;
}

evergram_status_t evergram_sync_chats(evergram_t *eg) {
    if (eg == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (eg->state != EG_STATE_AUTHENTICATED) {
        return EVERGRAM_ERR_NOT_CONNECTED;
    }

    eg->sync_pages = 1;
    return evergram_sync_chats_page(eg, "");
}

/* --- chats ---------------------------------------------------------------- */

const evergram_chat_info_t *evergram_chat_get(const evergram_t *eg, const char *chat_id) {
    if (eg == NULL || chat_id == NULL) {
        return NULL;
    }
    return chats_find(eg->chats, chat_id);
}

size_t evergram_chat_count(const evergram_t *eg) {
    return eg != NULL ? chats_count(eg->chats) : 0;
}

void evergram_chat_list(const evergram_t *eg,
                        bool (*visit)(const evergram_chat_info_t *chat, void *context),
                        void *context) {
    if (eg == NULL || visit == NULL) {
        return;
    }

    size_t count = chats_count(eg->chats);
    for (size_t i = 0; i < count; i++) {
        if (!visit(chats_at(eg->chats, i), context)) {
            break;
        }
    }
}

/* Copies the caller's participant list into an array protobuf-c can point at. */
static evergram_status_t copy_participants(const char *const *participants, size_t count,
                                           char ***out_names) {
    *out_names = NULL;
    if (count == 0) {
        return EVERGRAM_OK;
    }

    char **names = calloc(count, sizeof(*names));
    if (names == NULL) {
        return EVERGRAM_ERR_NO_MEMORY;
    }

    for (size_t i = 0; i < count; i++) {
        if (participants[i] == NULL || participants[i][0] == '\0') {
            for (size_t j = 0; j < i; j++) {
                free(names[j]);
            }
            free(names);
            return EVERGRAM_ERR_INVALID_ARG;
        }

        size_t len = strlen(participants[i]);
        names[i] = malloc(len + 1u);
        if (names[i] == NULL) {
            for (size_t j = 0; j < i; j++) {
                free(names[j]);
            }
            free(names);
            return EVERGRAM_ERR_NO_MEMORY;
        }
        memcpy(names[i], participants[i], len + 1u);
    }

    *out_names = names;
    return EVERGRAM_OK;
}

static void free_participant_copies(char **names, size_t count) {
    if (names == NULL) {
        return;
    }
    for (size_t i = 0; i < count; i++) {
        free(names[i]);
    }
    free(names);
}

evergram_status_t evergram_chat_create(evergram_t *eg, const char *type,
                                       const char *const *participants,
                                       size_t participant_count, int timeout_ms,
                                       const evergram_chat_info_t **out) {
    if (eg == NULL || type == NULL || participants == NULL || participant_count == 0) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (eg->state != EG_STATE_AUTHENTICATED) {
        return EVERGRAM_ERR_NOT_CONNECTED;
    }
    if (out != NULL) {
        *out = NULL;
    }

    char **names = NULL;
    evergram_status_t status = copy_participants(participants, participant_count, &names);
    if (status != EVERGRAM_OK) {
        return status;
    }

    Evergram__Device device;
    evergram__device__init(&device);
    device.device_id = (char *)eg->device.device_id;
    device.device_pub_hex = (char *)eg->device.public_key_hex;

    Evergram__CreateChat create;
    evergram__create_chat__init(&create);
    create.type = (char *)type;
    create.device = &device;
    create.participants = names;
    create.n_participants = participant_count;

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.create_chat = &create;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_CREATE_CHAT;

    Evergram__ServerMessage *response = NULL;
    status = evergram_call(eg, &message, EVERGRAM__SERVER_MESSAGE__PAYLOAD_CREATE_CHAT_RESPONSE,
                           timeout_ms, &response);
    if (status == EVERGRAM_OK) {
        const Evergram__CreateChatResponse *result = response->create_chat_response;
        status = evergram_check_status(eg, result != NULL ? result->status : NULL);

        if (status == EVERGRAM_OK && out != NULL && result->chat != NULL &&
            result->chat->chat_id != NULL) {
            /* The parser already stored the chat while handling this response. */
            *out = chats_find(eg->chats, result->chat->chat_id);
        }
        evergram_call_finish(eg);
    }

    free_participant_copies(names, participant_count);
    return status;
}

evergram_status_t evergram_chat_leave(evergram_t *eg, const char *chat_id, int timeout_ms) {
    evergram_status_t status = require_authenticated(eg, chat_id);
    if (status != EVERGRAM_OK) {
        return status;
    }

    Evergram__LeaveChat leave;
    evergram__leave_chat__init(&leave);
    leave.chat_id = (char *)chat_id;

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.leave_chat = &leave;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_LEAVE_CHAT;

    Evergram__ServerMessage *response = NULL;
    status = evergram_call(eg, &message, EVERGRAM__SERVER_MESSAGE__PAYLOAD_LEAVE_CHAT_RESPONSE,
                           timeout_ms, &response);
    if (status == EVERGRAM_OK) {
        const Evergram__LeaveChatResponse *result = response->leave_chat_response;
        status = evergram_check_status(eg, result != NULL ? result->status : NULL);
        evergram_call_finish(eg);

        if (status == EVERGRAM_OK) {
            chats_remove(eg->chats, chat_id);
            chatkeys_remove(eg->chat_keys, chat_id);
        }
    }

    return status;
}

/* --- groups, invites and blocking ----------------------------------------- */

void evergram_on_join_request(evergram_t *eg, evergram_join_request_fn fn) {
    if (eg != NULL) {
        eg->on_join_request = fn;
    }
}

/* Shared prologue: validate state and run one request/response round trip. */
static evergram_status_t chat_request(evergram_t *eg, const char *chat_id,
                                      Evergram__ClientMessage *message, uint32_t expected_case,
                                      int timeout_ms, Evergram__ServerMessage **response) {
    evergram_status_t status = require_authenticated(eg, chat_id);
    if (status != EVERGRAM_OK) {
        return status;
    }
    return evergram_call(eg, message, expected_case, timeout_ms, response);
}

static evergram_status_t plain_request(evergram_t *eg, Evergram__ClientMessage *message,
                                       uint32_t expected_case, int timeout_ms,
                                       Evergram__ServerMessage **response) {
    evergram_status_t status = require_connected(eg);
    if (status != EVERGRAM_OK) {
        return status;
    }
    return evergram_call(eg, message, expected_case, timeout_ms, response);
}

evergram_status_t evergram_chat_add_participant(evergram_t *eg, const char *chat_id,
                                                const char *identity, int timeout_ms) {
    if (identity == NULL || identity[0] == '\0') {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    Evergram__AddParticipantRequest request;
    evergram__add_participant_request__init(&request);
    request.chat_id = (char *)chat_id;
    request.remote_identity = (char *)identity;

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.add_participant = &request;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_ADD_PARTICIPANT;

    Evergram__ServerMessage *response = NULL;
    evergram_status_t status =
        chat_request(eg, chat_id, &message,
                     EVERGRAM__SERVER_MESSAGE__PAYLOAD_ADD_PARTICIPANT_RESPONSE, timeout_ms,
                     &response);
    if (status != EVERGRAM_OK) {
        return status;
    }

    const Evergram__AddParticipantResponse *result = response->add_participant_response;
    status = evergram_check_status(eg, result != NULL ? result->status : NULL);
    evergram_call_finish(eg);
    return status;
}

evergram_status_t evergram_chat_remove_participant(evergram_t *eg, const char *chat_id,
                                                   const char *identity, int timeout_ms) {
    if (identity == NULL || identity[0] == '\0') {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    Evergram__RemoveParticipantRequest request;
    evergram__remove_participant_request__init(&request);
    request.chat_id = (char *)chat_id;
    request.remote_identity = (char *)identity;

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.remove_participant = &request;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_REMOVE_PARTICIPANT;

    Evergram__ServerMessage *response = NULL;
    evergram_status_t status =
        chat_request(eg, chat_id, &message,
                     EVERGRAM__SERVER_MESSAGE__PAYLOAD_REMOVE_PARTICIPANT_RESPONSE, timeout_ms,
                     &response);
    if (status != EVERGRAM_OK) {
        return status;
    }

    const Evergram__RemoveParticipantResponse *result = response->remove_participant_response;
    status = evergram_check_status(eg, result != NULL ? result->status : NULL);
    evergram_call_finish(eg);
    return status;
}

evergram_status_t evergram_chat_set_mode(evergram_t *eg, const char *chat_id, bool moderated,
                                         int timeout_ms) {
    Evergram__SetChatMode request;
    evergram__set_chat_mode__init(&request);
    request.chat_id = (char *)chat_id;
    request.has_moderated = 1;
    request.moderated = moderated ? 1 : 0;

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.set_chat_mode = &request;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_SET_CHAT_MODE;

    Evergram__ServerMessage *response = NULL;
    evergram_status_t status = chat_request(eg, chat_id, &message,
                                            EVERGRAM__SERVER_MESSAGE__PAYLOAD_SET_CHAT_MODE_RESPONSE,
                                            timeout_ms, &response);
    if (status != EVERGRAM_OK) {
        return status;
    }

    const Evergram__SetChatModeResponse *result = response->set_chat_mode_response;
    status = evergram_check_status(eg, result != NULL ? result->status : NULL);
    evergram_call_finish(eg);
    return status;
}

evergram_status_t evergram_chat_update_roles(evergram_t *eg, const char *chat_id,
                                             const char *const *admins, size_t admin_count,
                                             const char *const *moderators,
                                             size_t moderator_count, int timeout_ms) {
    if ((admin_count > 0 && admins == NULL) || (moderator_count > 0 && moderators == NULL)) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    char **admin_names = NULL;
    char **moderator_names = NULL;
    evergram_status_t status = copy_participants(admins, admin_count, &admin_names);
    if (status != EVERGRAM_OK) {
        return status;
    }
    status = copy_participants(moderators, moderator_count, &moderator_names);
    if (status != EVERGRAM_OK) {
        free_participant_copies(admin_names, admin_count);
        return status;
    }

    Evergram__UpdateChatRoles request;
    evergram__update_chat_roles__init(&request);
    request.chat_id = (char *)chat_id;
    request.admins = admin_names;
    request.n_admins = admin_count;
    request.moderators = moderator_names;
    request.n_moderators = moderator_count;

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.update_chat_roles = &request;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_UPDATE_CHAT_ROLES;

    Evergram__ServerMessage *response = NULL;
    status = chat_request(eg, chat_id, &message,
                          EVERGRAM__SERVER_MESSAGE__PAYLOAD_UPDATE_CHAT_ROLES_RESPONSE, timeout_ms,
                          &response);
    if (status == EVERGRAM_OK) {
        const Evergram__UpdateChatRolesResponse *result = response->update_chat_roles_response;
        status = evergram_check_status(eg, result != NULL ? result->status : NULL);
        evergram_call_finish(eg);
    }

    free_participant_copies(admin_names, admin_count);
    free_participant_copies(moderator_names, moderator_count);
    return status;
}

evergram_status_t evergram_join_request_deny(evergram_t *eg, const char *chat_id,
                                             const char *identity, int timeout_ms) {
    if (identity == NULL || identity[0] == '\0') {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    Evergram__DenyJoinRequest request;
    evergram__deny_join_request__init(&request);
    request.chat_id = (char *)chat_id;
    request.remote_identity = (char *)identity;

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.deny_join_request = &request;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_DENY_JOIN_REQUEST;

    Evergram__ServerMessage *response = NULL;
    evergram_status_t status =
        chat_request(eg, chat_id, &message, EVERGRAM__SERVER_MESSAGE__PAYLOAD_DENY_JOIN_RESPONSE,
                     timeout_ms, &response);
    if (status != EVERGRAM_OK) {
        return status;
    }

    const Evergram__DenyJoinResponse *result = response->deny_join_response;
    status = evergram_check_status(eg, result != NULL ? result->status : NULL);
    evergram_call_finish(eg);
    return status;
}

evergram_status_t evergram_invite_generate(evergram_t *eg, const char *chat_id,
                                           int64_t expires_at_ms, int32_t max_uses, int timeout_ms,
                                           char *invite_code, size_t invite_code_size) {
    if (invite_code == NULL || invite_code_size == 0) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    invite_code[0] = '\0';

    Evergram__GenerateInviteLink request;
    evergram__generate_invite_link__init(&request);
    request.chat_id = (char *)chat_id;
    if (expires_at_ms > 0) {
        request.has_expires_at = 1;
        request.expires_at = expires_at_ms;
    }
    if (max_uses > 0) {
        request.has_max_uses = 1;
        request.max_uses = max_uses;
    }

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.generate_invite_link = &request;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_GENERATE_INVITE_LINK;

    Evergram__ServerMessage *response = NULL;
    evergram_status_t status =
        chat_request(eg, chat_id, &message,
                     EVERGRAM__SERVER_MESSAGE__PAYLOAD_GENERATE_INVITE_LINK_RESPONSE, timeout_ms,
                     &response);
    if (status != EVERGRAM_OK) {
        return status;
    }

    const Evergram__GenerateInviteLinkResponse *result = response->generate_invite_link_response;
    status = evergram_check_status(eg, result != NULL ? result->status : NULL);
    if (status == EVERGRAM_OK) {
        if (result->invite_code == NULL) {
            status = EVERGRAM_ERR_PROTOCOL;
        } else if (strlen(result->invite_code) >= invite_code_size) {
            status = EVERGRAM_ERR_BUFFER_TOO_SMALL;
        } else {
            snprintf(invite_code, invite_code_size, "%s", result->invite_code);
        }
    }
    evergram_call_finish(eg);
    return status;
}

evergram_status_t evergram_invite_revoke(evergram_t *eg, const char *chat_id, int timeout_ms) {
    Evergram__RevokeInviteLink request;
    evergram__revoke_invite_link__init(&request);
    request.chat_id = (char *)chat_id;

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.revoke_invite_link = &request;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_REVOKE_INVITE_LINK;

    Evergram__ServerMessage *response = NULL;
    evergram_status_t status =
        chat_request(eg, chat_id, &message,
                     EVERGRAM__SERVER_MESSAGE__PAYLOAD_REVOKE_INVITE_LINK_RESPONSE, timeout_ms,
                     &response);
    if (status != EVERGRAM_OK) {
        return status;
    }

    const Evergram__RevokeInviteLinkResponse *result = response->revoke_invite_link_response;
    status = evergram_check_status(eg, result != NULL ? result->status : NULL);
    evergram_call_finish(eg);
    return status;
}

evergram_status_t evergram_invite_resolve(evergram_t *eg, const char *invite_code, int timeout_ms,
                                          evergram_invite_info_t *out) {
    if (invite_code == NULL || invite_code[0] == '\0') {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
    }

    Evergram__ResolveInvite request;
    evergram__resolve_invite__init(&request);
    request.invite_code = (char *)invite_code;

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.resolve_invite = &request;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_RESOLVE_INVITE;

    Evergram__ServerMessage *response = NULL;
    evergram_status_t status =
        plain_request(eg, &message, EVERGRAM__SERVER_MESSAGE__PAYLOAD_RESOLVE_INVITE_RESPONSE,
                      timeout_ms, &response);
    if (status != EVERGRAM_OK) {
        return status;
    }

    const Evergram__ResolveInviteResponse *result = response->resolve_invite_response;
    status = evergram_check_status(eg, result != NULL ? result->status : NULL);
    if (status == EVERGRAM_OK && out != NULL && result != NULL) {
        evergram_copy_bounded(out->chat_id, sizeof(out->chat_id),
                     result->chat_id != NULL ? result->chat_id : "");
        evergram_copy_bounded(out->name, sizeof(out->name), result->name != NULL ? result->name : "");
        out->member_count = result->member_count;
        out->already_member = result->already_member != 0;
        out->already_requested = result->already_requested != 0;
    }
    evergram_call_finish(eg);
    return status;
}

evergram_status_t evergram_chat_request_join(evergram_t *eg, const char *invite_code,
                                             int timeout_ms) {
    if (invite_code == NULL || invite_code[0] == '\0') {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    Evergram__RequestJoin request;
    evergram__request_join__init(&request);
    request.invite_code = (char *)invite_code;

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.request_join = &request;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_REQUEST_JOIN;

    Evergram__ServerMessage *response = NULL;
    evergram_status_t status =
        plain_request(eg, &message, EVERGRAM__SERVER_MESSAGE__PAYLOAD_REQUEST_JOIN_RESPONSE,
                      timeout_ms, &response);
    if (status != EVERGRAM_OK) {
        return status;
    }

    const Evergram__RequestJoinResponse *result = response->request_join_response;
    status = evergram_check_status(eg, result != NULL ? result->status : NULL);
    evergram_call_finish(eg);
    return status;
}

evergram_status_t evergram_identity_block(evergram_t *eg, const char *identity, int timeout_ms) {
    if (identity == NULL || identity[0] == '\0') {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    Evergram__BlockIdentity request;
    evergram__block_identity__init(&request);
    request.target_identity = (char *)identity;

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.block_identity = &request;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_BLOCK_IDENTITY;

    Evergram__ServerMessage *response = NULL;
    evergram_status_t status =
        plain_request(eg, &message, EVERGRAM__SERVER_MESSAGE__PAYLOAD_BLOCK_IDENTITY_RESPONSE,
                      timeout_ms, &response);
    if (status != EVERGRAM_OK) {
        return status;
    }

    const Evergram__BlockIdentityResponse *result = response->block_identity_response;
    status = evergram_check_status(eg, result != NULL ? result->status : NULL);
    evergram_call_finish(eg);
    return status;
}

evergram_status_t evergram_identity_unblock(evergram_t *eg, const char *identity, int timeout_ms) {
    if (identity == NULL || identity[0] == '\0') {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    Evergram__UnblockIdentity request;
    evergram__unblock_identity__init(&request);
    request.target_identity = (char *)identity;

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.unblock_identity = &request;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_UNBLOCK_IDENTITY;

    Evergram__ServerMessage *response = NULL;
    evergram_status_t status =
        plain_request(eg, &message, EVERGRAM__SERVER_MESSAGE__PAYLOAD_UNBLOCK_IDENTITY_RESPONSE,
                      timeout_ms, &response);
    if (status != EVERGRAM_OK) {
        return status;
    }

    const Evergram__UnblockIdentityResponse *result = response->unblock_identity_response;
    status = evergram_check_status(eg, result != NULL ? result->status : NULL);
    evergram_call_finish(eg);
    return status;
}

/* --- profile and presence -------------------------------------------------- */

void evergram_profile_from_message(evergram_profile_t *out,
                                   const struct Evergram__Profile *profile) {
    memset(out, 0, sizeof(*out));
    if (profile == NULL) {
        return;
    }

    if (profile->identity != NULL) {
        snprintf(out->identity_key, sizeof(out->identity_key), "%d:%s",
                 (int)profile->identity->chain_family,
                 profile->identity->address != NULL ? profile->identity->address : "");
    }
    evergram_copy_bounded(out->nickname, sizeof(out->nickname),
                          profile->nickname != NULL ? profile->nickname : "");
    evergram_copy_bounded(out->avatar_url, sizeof(out->avatar_url),
                          profile->avatar_url != NULL ? profile->avatar_url : "");
    evergram_copy_bounded(out->bio, sizeof(out->bio), profile->bio != NULL ? profile->bio : "");
}

/* Splits "<chainFamily>:<address>" the way the TypeScript SDK does: on the
 * first colon, rejecting unknown chains and an empty address. */
static evergram_status_t parse_identity_key(const char *key,
                                            Evergram__ChainIdentity *identity) {
    if (key == NULL || identity == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    const char *separator = strchr(key, ':');
    if (separator == NULL || separator == key) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    char family_text[8];
    size_t family_len = (size_t)(separator - key);
    if (family_len >= sizeof(family_text)) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    memcpy(family_text, key, family_len);
    family_text[family_len] = '\0';

    char *end = NULL;
    long family = strtol(family_text, &end, 10);
    if (end == family_text || *end != '\0' || family < EVERGRAM__CHAIN_FAMILY__XRPL ||
        family > EVERGRAM__CHAIN_FAMILY__SOL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    const char *address = separator + 1;
    if (address[0] == '\0') {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    evergram__chain_identity__init(identity);
    identity->has_chain_family = 1;
    identity->chain_family = (Evergram__ChainFamily)family;
    identity->address = (char *)address;
    return EVERGRAM_OK;
}

static evergram_status_t watch_identities(evergram_t *eg, const char *const *identities,
                                          size_t count, bool watching) {
    if (identities == NULL || count == 0) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    evergram_status_t status = require_connected(eg);
    if (status != EVERGRAM_OK) {
        return status;
    }

    char **names = NULL;
    status = copy_participants(identities, count, &names);
    if (status != EVERGRAM_OK) {
        return status;
    }

    Evergram__WatchIdentities watch;
    evergram__watch_identities__init(&watch);
    watch.identities = names;
    watch.n_identities = count;

    Evergram__UnwatchIdentities unwatch;
    evergram__unwatch_identities__init(&unwatch);
    unwatch.identities = names;
    unwatch.n_identities = count;

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    if (watching) {
        message.watch_identities = &watch;
        message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_WATCH_IDENTITIES;
    } else {
        message.unwatch_identities = &unwatch;
        message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_UNWATCH_IDENTITIES;
    }
    evergram_set_request_id(&message, evergram_take_request_id(eg));

    /* No response on the wire: this is fire-and-forget, like the TS SDK. */
    status = evergram_send_client_message(eg, &message, watching ? "watchIdentities"
                                                                : "unwatchIdentities");

    free_participant_copies(names, count);
    return status;
}

evergram_status_t evergram_identities_watch(evergram_t *eg, const char *const *identities,
                                            size_t count) {
    return watch_identities(eg, identities, count, true);
}

evergram_status_t evergram_identities_unwatch(evergram_t *eg, const char *const *identities,
                                              size_t count) {
    return watch_identities(eg, identities, count, false);
}

evergram_status_t evergram_profile_get(evergram_t *eg, const char *identity_key, int timeout_ms,
                                       evergram_profile_t *out) {
    Evergram__ChainIdentity identity;
    evergram_status_t status = parse_identity_key(identity_key, &identity);
    if (status != EVERGRAM_OK) {
        return status;
    }
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
    }

    Evergram__GetProfile request;
    evergram__get_profile__init(&request);
    request.remote_identity = &identity;

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.get_profile = &request;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_GET_PROFILE;

    Evergram__ServerMessage *response = NULL;
    status = plain_request(eg, &message, EVERGRAM__SERVER_MESSAGE__PAYLOAD_GET_PROFILE_RESPONSE,
                           timeout_ms, &response);
    if (status != EVERGRAM_OK) {
        return status;
    }

    const Evergram__GetProfileResponse *result = response->get_profile_response;
    status = evergram_check_status(eg, result != NULL ? result->status : NULL);
    if (status == EVERGRAM_OK && out != NULL) {
        evergram_profile_from_message(out, result != NULL ? result->profile : NULL);
    }
    evergram_call_finish(eg);
    return status;
}

evergram_status_t evergram_profile_set(evergram_t *eg, const char *nickname,
                                       const char *avatar_url, const char *bio, int timeout_ms,
                                       evergram_profile_t *out) {
    if (nickname == NULL && avatar_url == NULL && bio == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
    }

    Evergram__ChangeProfileRequest request;
    evergram__change_profile_request__init(&request);
    /* NULL leaves a field untouched; the gateway merges. */
    request.nickname = (char *)nickname;
    request.avatar_url = (char *)avatar_url;
    request.bio = (char *)bio;

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.change_profile = &request;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_CHANGE_PROFILE;

    Evergram__ServerMessage *response = NULL;
    evergram_status_t status =
        plain_request(eg, &message, EVERGRAM__SERVER_MESSAGE__PAYLOAD_CHANGE_PROFILE_RESPONSE,
                      timeout_ms, &response);
    if (status != EVERGRAM_OK) {
        return status;
    }

    const Evergram__ChangeProfileResponse *result = response->change_profile_response;
    status = evergram_check_status(eg, result != NULL ? result->status : NULL);
    if (status == EVERGRAM_OK && out != NULL) {
        evergram_profile_from_message(out, result != NULL ? result->profile : NULL);
    }
    evergram_call_finish(eg);
    return status;
}

void evergram_on_presence(evergram_t *eg, evergram_presence_fn fn) {
    if (eg != NULL) {
        eg->on_presence = fn;
    }
}

void evergram_on_profile_updated(evergram_t *eg, evergram_profile_fn fn) {
    if (eg != NULL) {
        eg->on_profile_updated = fn;
    }
}

evergram_status_t evergram_chat_rotate_key(evergram_t *eg, const char *chat_id, int timeout_ms) {
    Evergram__RotateChatVersion request;
    evergram__rotate_chat_version__init(&request);
    request.chat_id = (char *)chat_id;

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.rotate_chat_version = &request;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_ROTATE_CHAT_VERSION;

    Evergram__ServerMessage *response = NULL;
    evergram_status_t status =
        chat_request(eg, chat_id, &message,
                     EVERGRAM__SERVER_MESSAGE__PAYLOAD_ROTATE_CHAT_VERSION_RESPONSE, timeout_ms,
                     &response);
    if (status != EVERGRAM_OK) {
        return status;
    }

    /* The parser already stored the rotated key while handling this response. */
    const Evergram__RotateChatVersionResponse *result = response->rotate_chat_version_response;
    status = evergram_check_status(eg, result != NULL ? result->status : NULL);
    evergram_call_finish(eg);
    return status;
}

void evergram_set_defer_hook(evergram_t *eg, evergram_defer_fn fn, void *context) {
    if (eg != NULL) {
        eg->defer = fn;
        eg->defer_context = context;
    }
}

evergram_status_t evergram_report_user(evergram_t *eg, const char *identity, const char *reason,
                                       int timeout_ms) {
    if (identity == NULL || identity[0] == '\0') {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    Evergram__ReportUser request;
    evergram__report_user__init(&request);
    request.target_identity = (char *)identity;
    request.reason = (char *)(reason != NULL ? reason : "");

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.report_user = &request;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_REPORT_USER;

    Evergram__ServerMessage *response = NULL;
    evergram_status_t status =
        plain_request(eg, &message, EVERGRAM__SERVER_MESSAGE__PAYLOAD_REPORT_USER_RESPONSE,
                      timeout_ms, &response);
    if (status != EVERGRAM_OK) {
        return status;
    }

    const Evergram__ReportUserResponse *result = response->report_user_response;
    status = evergram_check_status(eg, result != NULL ? result->status : NULL);
    evergram_call_finish(eg);
    return status;
}

/* --- chat requests, group invites and removed chats ------------------------ */

/*
 * Both pending stores are bounded and identity-keyed: the boot sync replays
 * everything still awaiting a decision, and a bot must not be asked to decide
 * the same request on every reconnect. Repeats only refresh the timestamp.
 */
#define EVERGRAM_MAX_PENDING_REQUESTS 64u
#define EVERGRAM_MAX_PENDING_INVITES 64u

void evergram_note_chat_request(evergram_t *eg, const evergram_chat_request_t *request) {
    if (eg == NULL || request == NULL || request->from_identity[0] == '\0') {
        return;
    }

    for (size_t i = 0; i < eg->pending_request_count; i++) {
        if (strcmp(eg->pending_requests[i].from_identity, request->from_identity) == 0) {
            eg->pending_requests[i] = *request;
            return;
        }
    }

    if (eg->pending_request_count == eg->pending_request_capacity) {
        if (eg->pending_request_capacity >= EVERGRAM_MAX_PENDING_REQUESTS) {
            EG_WARN("chat request table full, dropping one from %s", request->from_identity);
            return;
        }
        size_t capacity = eg->pending_request_capacity == 0 ? 8u : eg->pending_request_capacity * 2u;
        if (capacity > EVERGRAM_MAX_PENDING_REQUESTS) {
            capacity = EVERGRAM_MAX_PENDING_REQUESTS;
        }
        evergram_chat_request_t *grown =
            realloc(eg->pending_requests, capacity * sizeof(*grown));
        if (grown == NULL) {
            EG_WARN("cannot grow the chat request table");
            return;
        }
        eg->pending_requests = grown;
        eg->pending_request_capacity = capacity;
    }

    eg->pending_requests[eg->pending_request_count++] = *request;
    if (eg->on_chat_request != NULL) {
        eg->on_chat_request(eg, request);
    }
}

void evergram_note_group_invite(evergram_t *eg, const evergram_group_invite_t *invite) {
    if (eg == NULL || invite == NULL || invite->chat_id[0] == '\0') {
        return;
    }

    for (size_t i = 0; i < eg->pending_invite_count; i++) {
        if (strcmp(eg->pending_invites[i].chat_id, invite->chat_id) == 0) {
            eg->pending_invites[i] = *invite;
            return;
        }
    }

    if (eg->pending_invite_count == eg->pending_invite_capacity) {
        if (eg->pending_invite_capacity >= EVERGRAM_MAX_PENDING_INVITES) {
            EG_WARN("group invite table full, dropping the one for %s", invite->chat_id);
            return;
        }
        size_t capacity = eg->pending_invite_capacity == 0 ? 8u : eg->pending_invite_capacity * 2u;
        if (capacity > EVERGRAM_MAX_PENDING_INVITES) {
            capacity = EVERGRAM_MAX_PENDING_INVITES;
        }
        evergram_group_invite_t *grown = realloc(eg->pending_invites, capacity * sizeof(*grown));
        if (grown == NULL) {
            EG_WARN("cannot grow the group invite table");
            return;
        }
        eg->pending_invites = grown;
        eg->pending_invite_capacity = capacity;
    }

    eg->pending_invites[eg->pending_invite_count++] = *invite;
    if (eg->on_group_invite != NULL) {
        eg->on_group_invite(eg, invite);
    }
}

static void forget_chat_request(evergram_t *eg, const char *from_identity) {
    for (size_t i = 0; i < eg->pending_request_count; i++) {
        if (strcmp(eg->pending_requests[i].from_identity, from_identity) == 0) {
            eg->pending_requests[i] = eg->pending_requests[eg->pending_request_count - 1u];
            eg->pending_request_count--;
            return;
        }
    }
}

static void forget_group_invite(evergram_t *eg, const char *chat_id) {
    for (size_t i = 0; i < eg->pending_invite_count; i++) {
        if (strcmp(eg->pending_invites[i].chat_id, chat_id) == 0) {
            eg->pending_invites[i] = eg->pending_invites[eg->pending_invite_count - 1u];
            eg->pending_invite_count--;
            return;
        }
    }
}

/* A chat the gateway no longer knows: drop the metadata and, crucially, the key
 * that went with it, then say so. */
void evergram_forget_chat(evergram_t *eg, const char *chat_id) {
    if (eg == NULL || chat_id == NULL || chat_id[0] == '\0') {
        return;
    }

    bool known = evergram_chat_get(eg, chat_id) != NULL;
    chats_remove(eg->chats, chat_id);
    chatkeys_remove(eg->chat_keys, chat_id);
    if (known && eg->on_chat_removed != NULL) {
        eg->on_chat_removed(eg, chat_id);
    }
}

void evergram_on_chat_request(evergram_t *eg, evergram_chat_request_fn fn) {
    if (eg != NULL) {
        eg->on_chat_request = fn;
    }
}

void evergram_on_group_invite(evergram_t *eg, evergram_group_invite_fn fn) {
    if (eg != NULL) {
        eg->on_group_invite = fn;
    }
}

void evergram_on_chat_removed(evergram_t *eg, evergram_chat_removed_fn fn) {
    if (eg != NULL) {
        eg->on_chat_removed = fn;
    }
}

size_t evergram_pending_chat_request_count(const evergram_t *eg) {
    return eg != NULL ? eg->pending_request_count : 0;
}

size_t evergram_pending_group_invite_count(const evergram_t *eg) {
    return eg != NULL ? eg->pending_invite_count : 0;
}

/* Approving creates the chat; the response carries it, so the store learns the
 * key while the response is dispatched (see the parser). */
evergram_status_t evergram_chat_request_accept(evergram_t *eg, const char *from_identity,
                                              int timeout_ms,
                                              const evergram_chat_info_t **out) {
    if (eg == NULL || from_identity == NULL || from_identity[0] == '\0') {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (out != NULL) {
        *out = NULL;
    }

    Evergram__AcceptChatRequest request;
    evergram__accept_chat_request__init(&request);
    request.from_identity = (char *)from_identity;

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.accept_chat_request = &request;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_ACCEPT_CHAT_REQUEST;

    Evergram__ServerMessage *response = NULL;
    evergram_status_t status = evergram_call(
        eg, &message, EVERGRAM__SERVER_MESSAGE__PAYLOAD_ACCEPT_CHAT_REQUEST_RESPONSE, timeout_ms,
        &response);
    if (status == EVERGRAM_OK) {
        const Evergram__AcceptChatRequestResponse *result = response->accept_chat_request_response;
        status = evergram_check_status(eg, result != NULL ? result->status : NULL);
        if (status == EVERGRAM_OK && result != NULL && result->chat != NULL &&
            result->chat->chat_id != NULL && out != NULL) {
            *out = evergram_chat_get(eg, result->chat->chat_id);
        }
    }

    /* The request stops being pending whether or not the gateway agreed to it:
     * a refusal means "decide again later", not "ask me forever". */
    forget_chat_request(eg, from_identity);
    evergram_call_finish(eg);
    return status;
}

evergram_status_t evergram_chat_request_decline(evergram_t *eg, const char *from_identity,
                                               int timeout_ms) {
    if (eg == NULL || from_identity == NULL || from_identity[0] == '\0') {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    Evergram__DeclineChatRequest request;
    evergram__decline_chat_request__init(&request);
    request.from_identity = (char *)from_identity;

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.decline_chat_request = &request;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_DECLINE_CHAT_REQUEST;

    Evergram__ServerMessage *response = NULL;
    evergram_status_t status = evergram_call(
        eg, &message, EVERGRAM__SERVER_MESSAGE__PAYLOAD_DECLINE_CHAT_REQUEST_RESPONSE, timeout_ms,
        &response);
    if (status == EVERGRAM_OK) {
        const Evergram__DeclineChatRequestResponse *result =
            response->decline_chat_request_response;
        status = evergram_check_status(eg, result != NULL ? result->status : NULL);
    }

    forget_chat_request(eg, from_identity);
    evergram_call_finish(eg);
    return status;
}

evergram_status_t evergram_group_invite_accept(evergram_t *eg, const char *chat_id,
                                              int timeout_ms) {
    if (eg == NULL || chat_id == NULL || chat_id[0] == '\0') {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    Evergram__AcceptGroupInvite request;
    evergram__accept_group_invite__init(&request);
    request.chat_id = (char *)chat_id;

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.accept_group_invite = &request;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_ACCEPT_GROUP_INVITE;

    Evergram__ServerMessage *response = NULL;
    evergram_status_t status = evergram_call(
        eg, &message, EVERGRAM__SERVER_MESSAGE__PAYLOAD_ACCEPT_GROUP_INVITE_RESPONSE, timeout_ms,
        &response);
    if (status == EVERGRAM_OK) {
        const Evergram__AcceptGroupInviteResponse *result = response->accept_group_invite_response;
        status = evergram_check_status(eg, result != NULL ? result->status : NULL);
    }

    forget_group_invite(eg, chat_id);
    evergram_call_finish(eg);
    return status;
}

evergram_status_t evergram_group_invite_decline(evergram_t *eg, const char *chat_id,
                                               int timeout_ms) {
    if (eg == NULL || chat_id == NULL || chat_id[0] == '\0') {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    Evergram__DeclineGroupInvite request;
    evergram__decline_group_invite__init(&request);
    request.chat_id = (char *)chat_id;

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.decline_group_invite = &request;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_DECLINE_GROUP_INVITE;

    Evergram__ServerMessage *response = NULL;
    evergram_status_t status = evergram_call(
        eg, &message, EVERGRAM__SERVER_MESSAGE__PAYLOAD_DECLINE_GROUP_INVITE_RESPONSE, timeout_ms,
        &response);
    if (status == EVERGRAM_OK) {
        const Evergram__DeclineGroupInviteResponse *result =
            response->decline_group_invite_response;
        status = evergram_check_status(eg, result != NULL ? result->status : NULL);
    }

    forget_group_invite(eg, chat_id);
    evergram_call_finish(eg);
    return status;
}

/* True while a decision is outstanding for this identity / chat. */
bool evergram_chat_request_is_pending(const evergram_t *eg, const char *from_identity) {
    if (eg == NULL || from_identity == NULL) {
        return false;
    }
    for (size_t i = 0; i < eg->pending_request_count; i++) {
        if (strcmp(eg->pending_requests[i].from_identity, from_identity) == 0) {
            return true;
        }
    }
    return false;
}

bool evergram_group_invite_is_pending(const evergram_t *eg, const char *chat_id) {
    if (eg == NULL || chat_id == NULL) {
        return false;
    }
    for (size_t i = 0; i < eg->pending_invite_count; i++) {
        if (strcmp(eg->pending_invites[i].chat_id, chat_id) == 0) {
            return true;
        }
    }
    return false;
}

/* --- visitor rooms (ephemeral relay) -------------------------------------- */

void evergram_on_visitor_room(evergram_t *eg, evergram_visitor_room_fn fn) {
    if (eg != NULL) {
        eg->on_visitor_room = fn;
    }
}

void evergram_on_visitor_text(evergram_t *eg, evergram_visitor_text_fn fn) {
    if (eg != NULL) {
        eg->on_visitor_text = fn;
    }
}

void evergram_on_visitor_react(evergram_t *eg, evergram_visitor_react_fn fn) {
    if (eg != NULL) {
        eg->on_visitor_react = fn;
    }
}

void evergram_on_visitor_edit(evergram_t *eg, evergram_visitor_edit_fn fn) {
    if (eg != NULL) {
        eg->on_visitor_edit = fn;
    }
}

void evergram_on_visitor_remove(evergram_t *eg, evergram_visitor_remove_fn fn) {
    if (eg != NULL) {
        eg->on_visitor_remove = fn;
    }
}

void evergram_on_visitor_typing(evergram_t *eg, evergram_visitor_typing_fn fn) {
    if (eg != NULL) {
        eg->on_visitor_typing = fn;
    }
}

void evergram_on_visitor_state(evergram_t *eg, evergram_visitor_state_fn fn) {
    if (eg != NULL) {
        eg->on_visitor_state = fn;
    }
}

void evergram_on_visitor_presence(evergram_t *eg, evergram_visitor_presence_fn fn) {
    if (eg != NULL) {
        eg->on_visitor_presence = fn;
    }
}

void evergram_on_visitor_moderation(evergram_t *eg, evergram_visitor_moderation_fn fn) {
    if (eg != NULL) {
        eg->on_visitor_moderation = fn;
    }
}

void evergram_on_visitor_timed_out(evergram_t *eg, evergram_visitor_timed_out_fn fn) {
    if (eg != NULL) {
        eg->on_visitor_timed_out = fn;
    }
}

/*
 * A channel answers with the state we joined into: everyone listed is present,
 * plus the current moderation snapshot. The string arrays stay owned by the
 * response, which is why the callbacks must treat them as borrowed. These run
 * inside a synchronous call, so a handler must not start another request.
 */
void evergram_visitor_report_snapshot(evergram_t *eg, const char *room_token,
                                      char *const *participants, size_t participant_count,
                                      bool moderated, char *const *ops, size_t ops_count,
                                      char *const *voiced, size_t voiced_count) {
    if (eg == NULL || room_token == NULL) {
        return;
    }

    evergram_relay_presence_t presence;
    for (size_t i = 0; i < participant_count && eg->on_visitor_presence != NULL; i++) {
        if (participants == NULL || participants[i] == NULL) {
            continue;
        }
        memset(&presence, 0, sizeof(presence));
        evergram_copy_bounded(presence.sender, sizeof(presence.sender), participants[i]);
        eg->on_visitor_presence(eg, room_token, &presence, true);
    }

    if (eg->on_visitor_moderation == NULL ||
        (!moderated && ops_count == 0 && voiced_count == 0)) {
        return;
    }

    evergram_relay_moderation_t snapshot;
    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.moderated = moderated;
    snapshot.ops = (char **)ops;
    snapshot.ops_count = ops_count;
    snapshot.voiced = (char **)voiced;
    snapshot.voiced_count = voiced_count;
    eg->on_visitor_moderation(eg, room_token, &snapshot);
}

/* Joiner role: this process claims the room again as soon as it reconnects. */
evergram_status_t evergram_visitor_register_room(evergram_t *eg, const char *room_token,
                                                const uint8_t key[EVERGRAM_SYM_KEY_SIZE]) {
    if (eg == NULL || room_token == NULL || room_token[0] == '\0' || key == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    return chatkeys_set_tagged(eg->room_keys, room_token, key, EVERGRAM_ROOM_ROLE_JOINER);
}

bool evergram_visitor_has_room(const evergram_t *eg, const char *room_token) {
    if (eg == NULL || room_token == NULL) {
        return false;
    }
    return chatkeys_has(eg->room_keys, room_token);
}

evergram_status_t evergram_visitor_room_key(const evergram_t *eg, const char *room_token,
                                            uint8_t out[E2EE_KEY_BYTES]) {
    if (eg == NULL || room_token == NULL || out == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    const uint8_t *key = chatkeys_get(eg->room_keys, room_token);
    if (key == NULL) {
        return EVERGRAM_ERR_NO_ROOM_KEY;
    }
    memcpy(out, key, E2EE_KEY_BYTES);
    return EVERGRAM_OK;
}

/* Fire-and-forget: the gateway never answers a relay frame. */
evergram_status_t evergram_visitor_send_frame(evergram_t *eg, const char *room_token,
                                             evergram_relay_kind_t kind, const char *payload) {
    if (eg == NULL || room_token == NULL || room_token[0] == '\0') {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (eg->state != EG_STATE_AUTHENTICATED) {
        return EVERGRAM_ERR_NOT_CONNECTED;
    }

    Evergram__RelayMessage relay;
    evergram_relay_fill_message(&relay, room_token, kind, payload);

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.relay_message = &relay;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_RELAY_MESSAGE;
    return evergram_send_client_message(eg, &message, "relayMessage");
}

evergram_status_t evergram_visitor_send_text(evergram_t *eg, const char *room_token,
                                             const char *sender, const char *text) {
    if (eg == NULL || room_token == NULL || text == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    const uint8_t *key = chatkeys_get(eg->room_keys, room_token);
    if (key == NULL) {
        return EVERGRAM_ERR_NO_ROOM_KEY;
    }

    char payload[EVERGRAM_RELAY_PAYLOAD_MAX];
    evergram_status_t status =
        evergram_relay_build_text(key, sender != NULL ? sender : eg->identity_key, text, payload,
                                  sizeof(payload), NULL);
    if (status != EVERGRAM_OK) {
        return status;
    }
    return evergram_visitor_send_frame(eg, room_token, EVERGRAM_RELAY_KIND_TEXT, payload);
}

evergram_status_t evergram_visitor_send_react(evergram_t *eg, const char *room_token,
                                              const char *msg_id, const char *emoji) {
    if (eg == NULL || room_token == NULL || msg_id == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    const uint8_t *key = chatkeys_get(eg->room_keys, room_token);
    if (key == NULL) {
        return EVERGRAM_ERR_NO_ROOM_KEY;
    }

    char payload[EVERGRAM_RELAY_PAYLOAD_MAX];
    evergram_status_t status = evergram_relay_build_react(key, msg_id, emoji, emoji == NULL,
                                                          payload, sizeof(payload));
    if (status != EVERGRAM_OK) {
        return status;
    }
    return evergram_visitor_send_frame(eg, room_token, EVERGRAM_RELAY_KIND_REACT, payload);
}

evergram_status_t evergram_visitor_send_edit(evergram_t *eg, const char *room_token,
                                             const char *msg_id, const char *text) {
    if (eg == NULL || room_token == NULL || msg_id == NULL || text == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    const uint8_t *key = chatkeys_get(eg->room_keys, room_token);
    if (key == NULL) {
        return EVERGRAM_ERR_NO_ROOM_KEY;
    }

    char payload[EVERGRAM_RELAY_PAYLOAD_MAX];
    evergram_status_t status =
        evergram_relay_build_edit(key, msg_id, text, payload, sizeof(payload));
    if (status != EVERGRAM_OK) {
        return status;
    }
    return evergram_visitor_send_frame(eg, room_token, EVERGRAM_RELAY_KIND_EDIT, payload);
}

evergram_status_t evergram_visitor_send_remove(evergram_t *eg, const char *room_token,
                                               const char *msg_id) {
    if (eg == NULL || room_token == NULL || msg_id == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    const uint8_t *key = chatkeys_get(eg->room_keys, room_token);
    if (key == NULL) {
        return EVERGRAM_ERR_NO_ROOM_KEY;
    }

    char payload[EVERGRAM_RELAY_PAYLOAD_MAX];
    evergram_status_t status = evergram_relay_build_remove(key, msg_id, payload, sizeof(payload));
    if (status != EVERGRAM_OK) {
        return status;
    }
    return evergram_visitor_send_frame(eg, room_token, EVERGRAM_RELAY_KIND_REMOVE, payload);
}

evergram_status_t evergram_visitor_send_typing(evergram_t *eg, const char *room_token,
                                               bool is_typing, const char *sender) {
    if (eg == NULL || room_token == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    char payload[EVERGRAM_RELAY_PAYLOAD_MAX];
    evergram_status_t status = evergram_relay_build_typing(is_typing, sender, payload,
                                                           sizeof(payload));
    if (status != EVERGRAM_OK) {
        return status;
    }
    return evergram_visitor_send_frame(eg, room_token, EVERGRAM_RELAY_KIND_TYPING, payload);
}

/* Closes the room for both sides and forgets the key. */
evergram_status_t evergram_visitor_end_room(evergram_t *eg, const char *room_token) {
    if (eg == NULL || room_token == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    evergram_status_t status =
        evergram_visitor_send_frame(eg, room_token, EVERGRAM_RELAY_KIND_END, NULL);
    chatkeys_remove(eg->room_keys, room_token);
    return status;
}

/*
 * Visitor side of a 1:1 room: mints the room key, asks the gateway to reach the
 * widget's devices and keeps the key for the session. `first_message`, when not
 * NULL, is sealed here with the freshly minted key.
 */
evergram_status_t evergram_visitor_room_create(evergram_t *eg, const char *widget_id,
                                              const char *visitor_label,
                                              const char *first_message, int timeout_ms,
                                              evergram_visitor_room_t *out) {
    if (eg == NULL || widget_id == NULL || widget_id[0] == '\0') {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
    }

    uint8_t key[E2EE_KEY_BYTES];
    randombytes_buf(key, sizeof(key));

    char payload[EVERGRAM_RELAY_PAYLOAD_MAX];
    bool has_payload = false;
    if (first_message != NULL) {
        evergram_status_t built = evergram_relay_build_text(key, eg->identity_key, first_message,
                                                            payload, sizeof(payload), NULL);
        if (built != EVERGRAM_OK) {
            sodium_memzero(key, sizeof(key));
            return built;
        }
        has_payload = true;
    }

    Evergram__CreateVisitorRoom request;
    evergram__create_visitor_room__init(&request);
    request.widget_id = (char *)widget_id;
    request.visitor_label = (char *)(visitor_label != NULL ? visitor_label : "");
    request.has_sym_key = 1;
    request.sym_key.data = key;
    request.sym_key.len = sizeof(key);
    if (has_payload) {
        request.has_first_message_payload = 1;
        request.first_message_payload.data = (uint8_t *)payload;
        request.first_message_payload.len = strlen(payload);
    }

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.create_visitor_room = &request;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_CREATE_VISITOR_ROOM;

    Evergram__ServerMessage *response = NULL;
    evergram_status_t status = evergram_call(eg, &message,
                                             EVERGRAM__SERVER_MESSAGE__PAYLOAD_CREATE_VISITOR_ROOM_RESPONSE,
                                             timeout_ms, &response);
    if (status == EVERGRAM_OK) {
        const Evergram__CreateVisitorRoomResponse *result = response->create_visitor_room_response;
        status = evergram_check_status(eg, result != NULL ? result->status : NULL);
        if (status == EVERGRAM_OK &&
            (result == NULL || result->room_token == NULL || result->room_token[0] == '\0')) {
            status = EVERGRAM_ERR_PROTOCOL; /* the room token is the whole point */
        }
        if (status == EVERGRAM_OK) {
            status = chatkeys_set_tagged(eg->room_keys, result->room_token, key,
                                         EVERGRAM_ROOM_ROLE_CREATOR);
            if (status == EVERGRAM_OK && out != NULL) {
                evergram_copy_bounded(out->room_token, sizeof(out->room_token), result->room_token);
                evergram_copy_bounded(out->widget_id, sizeof(out->widget_id), widget_id);
                evergram_copy_bounded(out->visitor_label, sizeof(out->visitor_label),
                                      visitor_label != NULL ? visitor_label : "");
                evergram_copy_bounded(out->origin, sizeof(out->origin), eg->identity_key);
                out->timestamp_ms = evergram_now_ms();
                out->has_first_message = has_payload;
                if (has_payload) {
                    evergram_relay_parse_text(key, payload, &out->first_message);
                }
            }

            /* The state we joined into, reported before this call returns. */
            if (status == EVERGRAM_OK && result != NULL) {
                evergram_visitor_report_snapshot(eg, result->room_token, result->participants,
                                                 result->n_participants, result->moderated,
                                                 result->ops, result->n_ops, result->voiced,
                                                 result->n_voiced);
            }
        }
    }

    sodium_memzero(key, sizeof(key));
    sodium_memzero(payload, sizeof(payload));
    evergram_call_finish(eg);
    return status;
}

/*
 * Re-claims every room this client is the joiner of. A room slot is bound to a
 * socket, so after a reconnect the gateway has no memory of us holding it until
 * we say so again — the reference SDK does the same on every authentication.
 * A creator-side room is left alone: claiming its joiner slot would take it away
 * from the actual visitor.
 */
void evergram_rooms_rejoin(evergram_t *eg) {
    if (eg == NULL || eg->state != EG_STATE_AUTHENTICATED) {
        return;
    }

    const char *room_token = NULL;
    for (size_t i = 0; chatkeys_at(eg->room_keys, i, &room_token); i++) {
        if (chatkeys_tag(eg->room_keys, room_token) != EVERGRAM_ROOM_ROLE_JOINER) {
            continue;
        }
        evergram_status_t status =
            evergram_visitor_send_frame(eg, room_token, EVERGRAM_RELAY_KIND_JOINED, NULL);
        if (status != EVERGRAM_OK) {
            EG_WARN("cannot re-claim room %s: %s", room_token, evergram_status_str(status));
        }
    }
}

/*
 * A channel's room key is its channel key, handed out by the operator's widget
 * configuration and replaced by the gateway's copy when it has gone stale.
 */
evergram_status_t evergram_visitor_subscribe_channel(evergram_t *eg, const char *widget_id,
                                                    const char *channel_key_hex, int timeout_ms,
                                                    evergram_visitor_room_t *out) {
    if (eg == NULL || widget_id == NULL || widget_id[0] == '\0' || channel_key_hex == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
    }

    uint8_t key[EVERGRAM_SYM_KEY_SIZE];
    if (sodium_hex2bin(key, sizeof(key), channel_key_hex, strlen(channel_key_hex), NULL, NULL,
                       NULL) != 0) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    Evergram__SubscribePublicChannel request;
    evergram__subscribe_public_channel__init(&request);
    request.widget_id = (char *)widget_id;
    request.channel_key = (char *)channel_key_hex;

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.subscribe_public_channel = &request;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_SUBSCRIBE_PUBLIC_CHANNEL;

    Evergram__ServerMessage *response = NULL;
    evergram_status_t status = evergram_call(
        eg, &message, EVERGRAM__SERVER_MESSAGE__PAYLOAD_SUBSCRIBE_PUBLIC_CHANNEL_RESPONSE,
        timeout_ms, &response);
    if (status == EVERGRAM_OK) {
        const Evergram__SubscribePublicChannelResponse *result =
            response->subscribe_public_channel_response;
        status = evergram_check_status(eg, result != NULL ? result->status : NULL);
        if (status == EVERGRAM_OK &&
            (result == NULL || result->room_token == NULL || result->room_token[0] == '\0')) {
            status = EVERGRAM_ERR_PROTOCOL;
        }
        if (status == EVERGRAM_OK) {
            /* The gateway may hand back a refreshed key; prefer it. */
            if (result->channel_key != NULL && result->channel_key[0] != '\0' &&
                sodium_hex2bin(key, sizeof(key), result->channel_key, strlen(result->channel_key),
                               NULL, NULL, NULL) != 0) {
                status = EVERGRAM_ERR_INVALID_ARG;
            }
        }
        if (status == EVERGRAM_OK) {
            status = chatkeys_set_tagged(eg->room_keys, result->room_token, key,
                                         EVERGRAM_ROOM_ROLE_CHANNEL);
        }
        if (status == EVERGRAM_OK) {
            if (out != NULL) {
                evergram_copy_bounded(out->room_token, sizeof(out->room_token),
                                      result->room_token);
                evergram_copy_bounded(out->widget_id, sizeof(out->widget_id), widget_id);
                out->timestamp_ms = evergram_now_ms();
            }
            evergram_visitor_report_snapshot(eg, result->room_token, result->participants,
                                             result->n_participants, result->moderated,
                                             result->ops, result->n_ops, result->voiced,
                                             result->n_voiced);
        }
    }

    sodium_memzero(key, sizeof(key));
    evergram_call_finish(eg);
    return status;
}

evergram_status_t evergram_visitor_moderate_channel(evergram_t *eg, const char *room_token,
                                                   evergram_moderation_action_t action,
                                                   const char *target_participant,
                                                   int timeout_ms) {
    if (eg == NULL || room_token == NULL || room_token[0] == '\0') {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    Evergram__ModerateChannel request;
    evergram__moderate_channel__init(&request);
    request.room_token = (char *)room_token;
    request.has_action = 1;
    request.action = (Evergram__ModerationAction)action;
    request.target_participant = (char *)(target_participant != NULL ? target_participant : "");

    Evergram__ClientMessage message;
    evergram__client_message__init(&message);
    message.moderate_channel = &request;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_MODERATE_CHANNEL;

    Evergram__ServerMessage *response = NULL;
    evergram_status_t status =
        evergram_call(eg, &message, EVERGRAM__SERVER_MESSAGE__PAYLOAD_MODERATE_CHANNEL_RESPONSE,
                      timeout_ms, &response);
    if (status == EVERGRAM_OK) {
        const Evergram__ModerateChannelResponse *result = response->moderate_channel_response;
        status = evergram_check_status(eg, result != NULL ? result->status : NULL);
        if (status == EVERGRAM_OK) {
            /* The roster is not repeated on a moderation response, only the
             * moderation state, so no presence events are emitted here. */
            evergram_visitor_report_snapshot(eg, room_token, NULL, 0, result->moderated,
                                             result->ops, result->n_ops, result->voiced,
                                             result->n_voiced);
        }
    }

    evergram_call_finish(eg);
    return status;
}

evergram_status_t evergram_visitor_announce_presence(evergram_t *eg, const char *room_token,
                                                    const char *sender,
                                                    const char *previous_sender) {
    if (eg == NULL || room_token == NULL || sender == NULL || sender[0] == '\0') {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    char payload[EVERGRAM_RELAY_PAYLOAD_MAX];
    evergram_status_t status = evergram_relay_build_presence(sender, previous_sender, payload,
                                                            sizeof(payload));
    if (status != EVERGRAM_OK) {
        return status;
    }
    return evergram_visitor_send_frame(eg, room_token, EVERGRAM_RELAY_KIND_CHANNEL_JOIN, payload);
}
