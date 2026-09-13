#include <sodium.h>
#include <string.h>

#include "chatkeys.h"
#include "e2ee.h"
#include "evergram.pb-c.h"
#include "internal.h"
#include "relay.h"

/*
 * ServerMessage dispatch.
 *
 * protobuf-c keeps every oneof in a union: all variant pointers share one
 * address, so *_case is the only valid discriminator. Reading a variant
 * pointer instead would reinterpret another variant's payload.
 *
 * Chat keys arrive inside ChatInfo.sym_key_encrypted[identityKey]
 * .devices[deviceId], sealed for this device; apply_chat_info() is called for
 * every message that can carry a ChatInfo.
 */

static uint64_t envelope_timestamp(const Evergram__Envelope *envelope) {
    if (envelope->has_ts && envelope->ts > 0) {
        return (uint64_t)envelope->ts;
    }
    return evergram_now_ms();
}

static const char *status_code(const Evergram__ResponseStatus *status) {
    return (status != NULL && status->code != NULL) ? status->code : "";
}

static const char *status_message(const Evergram__ResponseStatus *status, const char *fallback) {
    return (status != NULL && status->message != NULL) ? status->message : fallback;
}

/* --- chat keys and metadata ----------------------------------------------- */

/* Opens the copy of the chat key sealed for this device, if present. */
static bool apply_chat_key(evergram_t *eg, const Evergram__ChatInfo *chat) {
    for (size_t i = 0; i < chat->n_sym_key_encrypted; i++) {
        const Evergram__ChatInfo__SymKeyEncryptedEntry *account = chat->sym_key_encrypted[i];
        if (account == NULL || account->key == NULL || account->value == NULL) {
            continue;
        }
        if (strcmp(account->key, eg->identity_key) != 0) {
            continue;
        }

        for (size_t j = 0; j < account->value->n_devices; j++) {
            const Evergram__AccountSymKeys__DevicesEntry *device = account->value->devices[j];
            if (device == NULL || device->key == NULL || device->value == NULL) {
                continue;
            }
            if (strcmp(device->key, eg->device.device_id) != 0) {
                continue;
            }

            uint8_t key[E2EE_KEY_BYTES];
            evergram_status_t status =
                e2ee_open_sealed_key(device->value->ciphertext, device->value->nonce,
                                     device->value->ephemeral_pubkey, eg->device.private_key_hex,
                                     key);
            if (status != EVERGRAM_OK) {
                EG_WARN("cannot open chat key for %s: %s", chat->chat_id,
                        evergram_status_str(status));
                sodium_memzero(key, sizeof(key));
                return false;
            }

            status = chatkeys_set(eg->chat_keys, chat->chat_id, key);
            sodium_memzero(key, sizeof(key));
            return status == EVERGRAM_OK;
        }
    }

    EG_DEBUG("chat %s carries no key sealed for this device yet", chat->chat_id);
    return false;
}

/* Stores metadata and, when available, the chat key. */
static void apply_chat_info(evergram_t *eg, const Evergram__ChatInfo *chat) {
    if (chat == NULL || chat->chat_id == NULL || chat->chat_id[0] == '\0') {
        return;
    }

    evergram_chat_info_t record;
    memset(&record, 0, sizeof(record));
    evergram_copy_bounded(record.chat_id, sizeof(record.chat_id), chat->chat_id);
    evergram_copy_bounded(record.type, sizeof(record.type), chat->type != NULL ? chat->type : "");
    evergram_copy_bounded(record.created_by, sizeof(record.created_by),
                 chat->created_by != NULL ? chat->created_by : "");
    if (chat->meta != NULL && chat->meta->name != NULL) {
        evergram_copy_bounded(record.name, sizeof(record.name), chat->meta->name);
    }
    record.chat_version =
        chat->has_chat_version && chat->chat_version > 0 ? (uint64_t)chat->chat_version : 0;
    record.meta_version =
        chat->has_meta_version && chat->meta_version > 0 ? (uint64_t)chat->meta_version : 0;
    record.participant_count = chat->n_participants;
    record.participants = chat->participants;

    const Evergram__Meta *meta = chat->meta;
    if (meta != NULL && meta->roles != NULL) {
        record.admin_count = meta->roles->n_admins;
        record.admins = meta->roles->admins;
        record.moderator_count = meta->roles->n_moderators;
        record.moderators = meta->roles->moderators;
    }

    if (evergram_apply_chat_record(eg, &record) != EVERGRAM_OK) {
        EG_WARN("cannot store chat %s", chat->chat_id);
    }

    apply_chat_key(eg, chat);
}

/* Returns the decrypted body, or NULL when the key is unknown or the payload
 * is not decryptable. Callers must treat NULL as "content unavailable". */
static const char *decrypt_body(evergram_t *eg, const char *chat_id, const char *ciphertext_b64,
                                const char *nonce_b64, bool *deferred) {
    if (deferred != NULL) {
        *deferred = false;
    }
    if (chat_id == NULL || ciphertext_b64 == NULL || nonce_b64 == NULL ||
        ciphertext_b64[0] == '\0') {
        return NULL;
    }

    const uint8_t *key = chatkeys_get(eg->chat_keys, chat_id);
    if (key == NULL) {
        EG_DEBUG("no chat key for %s yet, payload stays encrypted", chat_id);
        /* With a mailbox attached the frame is held and delivered once the key
         * lands, so it must NOT be emitted now as an empty message. Without one,
         * the caller still sees the chat/sender with text == NULL. */
        if (eg->defer != NULL && eg->frame != NULL) {
            eg->defer(eg->defer_context, chat_id, eg->frame, eg->frame_len);
            if (deferred != NULL) {
                *deferred = true;
            }
        }
        return NULL;
    }

    size_t len = 0;
    evergram_status_t status = e2ee_decrypt(key, nonce_b64, ciphertext_b64, eg->text_buffer,
                                            sizeof(eg->text_buffer), &len);
    if (status != EVERGRAM_OK) {
        EG_WARN("cannot decrypt payload for chat %s: %s", chat_id, evergram_status_str(status));
        return NULL;
    }
    return eg->text_buffer;
}

/* --- auth and lifecycle --------------------------------------------------- */

static void handle_auth_challenge(evergram_t *eg, const Evergram__AuthChallenge *challenge) {
    if (challenge == NULL || challenge->nonce == NULL) {
        evergram_emit_error(eg, EVERGRAM_ERR_PROTOCOL, "auth challenge without nonce");
        return;
    }

    size_t len = strlen(challenge->nonce);
    if (len == 0 || len > EVERGRAM_CHALLENGE_SIZE) {
        evergram_emit_error(eg, EVERGRAM_ERR_PROTOCOL, "auth challenge nonce out of range");
        return;
    }

    memcpy(eg->challenge, challenge->nonce, len);
    eg->challenge[len] = '\0';
    eg->challenge_len = len;
    EG_DEBUG("auth challenge received (%zu chars)", len);

    evergram_status_t status = handshake_send_auth(eg);
    if (status != EVERGRAM_OK) {
        evergram_emit_error(eg, status, "cannot answer auth challenge");
    }
}

static void handle_auth_response(evergram_t *eg, const Evergram__AuthResponse *response) {
    const Evergram__ResponseStatus *status = response != NULL ? response->status : NULL;

    if (status != NULL && status->ok) {
        eg->state = EG_STATE_AUTHENTICATED;
        EG_INFO("authenticated as %s", eg->wallet.address);

        /* What this identity is allowed to do, so a caller can check instead of
         * learning it from a refusal. */
        eg->has_access = response->access != NULL;
        memset(&eg->access, 0, sizeof(eg->access));
        const Evergram__AccessInfo *access = response->access;
        if (access != NULL) {
            evergram_copy_bounded(eg->access.tier, sizeof(eg->access.tier),
                                  access->tier != NULL ? access->tier : "");
            eg->access.is_admin = access->is_admin;
            eg->access.is_restricted = access->is_restricted;
            eg->access.has_max_devices = access->has_max_devices;
            eg->access.max_devices =
                access->has_max_devices && access->max_devices > 0
                    ? (uint64_t)access->max_devices
                    : 0;
            eg->access.joined_at_ms =
                access->has_joined_at && access->joined_at > 0 ? (uint64_t)access->joined_at : 0;
            evergram_copy_bounded(eg->access.invited_by, sizeof(eg->access.invited_by),
                                  access->invited_by != NULL ? access->invited_by : "");
            eg->access.subscription_count = access->n_subscriptions;
            for (size_t i = 0; i < access->n_capabilities &&
                               eg->access.capability_count < EVERGRAM_MAX_CAPABILITIES;
                 i++) {
                if (access->capabilities[i] == NULL) {
                    continue;
                }
                evergram_copy_bounded(
                    eg->access.capabilities[eg->access.capability_count],
                    EVERGRAM_CAPABILITY_SIZE, access->capabilities[i]);
                eg->access.capability_count++;
            }
        }

        /* Learn chat keys for conversations that already exist (bot-layer
         * behaviour from the TypeScript SDK) before handing control back. */
        eg->sync_pages = 1;
        evergram_status_t synced = evergram_sync_chats_page(eg, "");
        if (synced != EVERGRAM_OK) {
            EG_WARN("initial chat sync failed: %s", evergram_status_str(synced));
        }

        /* A room slot is tied to a live socket, so every (re)authentication
         * re-claims the rooms this client is the joiner of. */
        evergram_rooms_rejoin(eg);

        if (eg->on_connected != NULL) {
            eg->on_connected(eg);
        }
        return;
    }

    if (strstr(status_code(status), "device_not_registered") != NULL) {
        EG_INFO("device not registered, registering");
        evergram_status_t sent = handshake_send_register_device(eg);
        if (sent != EVERGRAM_OK) {
            evergram_emit_error(eg, sent, "cannot send registerDevice");
        }
        return;
    }

    evergram_emit_error(eg, EVERGRAM_ERR_AUTH, status_message(status, "authentication rejected"));
}

static void handle_register_device_response(evergram_t *eg,
                                             const Evergram__RegisterDeviceResponse *response) {
    const Evergram__ResponseStatus *status = response != NULL ? response->status : NULL;

    if (status != NULL && status->ok) {
        /* A fresh device learns every chat key it was just granted here. */
        if (response->n_rotated_sym_keys > 0) {
            for (size_t i = 0; i < response->n_rotated_sym_keys; i++) {
                apply_chat_info(eg, response->rotated_sym_keys[i]);
            }
        }

        /* The device is on the ledger now; the same challenge is still valid. */
        EG_INFO("device registered, retrying auth");
        evergram_status_t sent = handshake_send_auth(eg);
        if (sent != EVERGRAM_OK) {
            evergram_emit_error(eg, sent, "cannot retry auth");
        }
        return;
    }

    evergram_emit_error(eg, EVERGRAM_ERR_AUTH,
                        status_message(status, "device registration rejected"));
}

static void handle_error(evergram_t *eg, const Evergram__Error *error) {
    const char *code = (error != NULL && error->code != NULL) ? error->code : "";
    const char *message =
        (error != NULL && error->message != NULL) ? error->message : "gateway error";

    if (strstr(code, "device_not_registered") != NULL || strstr(code, "invalid_device") != NULL) {
        EG_INFO("gateway reports unknown device, registering");
        evergram_status_t sent = handshake_send_register_device(eg);
        if (sent != EVERGRAM_OK) {
            evergram_emit_error(eg, sent, "cannot send registerDevice");
        }
        return;
    }

    evergram_emit_error(eg, EVERGRAM_ERR_PROTOCOL, message);
}

/* --- envelopes ------------------------------------------------------------ */

static void handle_send(evergram_t *eg, const Evergram__Envelope *envelope) {
    const Evergram__SendContent *send = envelope->send;
    if (send == NULL || eg->on_message == NULL) {
        return;
    }

    evergram_message_t message;
    memset(&message, 0, sizeof(message));
    evergram_copy_bounded(message.chat_id, sizeof(message.chat_id), envelope->chat_id);
    evergram_copy_bounded(message.sender, sizeof(message.sender), envelope->sender);
    if (send->msg_id != NULL) {
        evergram_copy_bounded(message.message_id, sizeof(message.message_id), send->msg_id);
    }
    message.timestamp_ms = envelope_timestamp(envelope);

    bool deferred = false;
    message.text = decrypt_body(eg, envelope->chat_id, send->ciphertext, send->nonce, &deferred);
    if (deferred) {
        return; /* promised to the mailbox */
    }
    if (send->reply_to_msg_id != NULL && send->reply_to_msg_id[0] != '\0') {
        message.reply_to_message_id = send->reply_to_msg_id;
    }

    eg->on_message(eg, &message);
}

static void handle_edit(evergram_t *eg, const Evergram__Envelope *envelope) {
    const Evergram__EditContent *edit = envelope->edit;
    if (edit == NULL) {
        return;
    }

    uint64_t timestamp =
        edit->has_edited_at && edit->edited_at > 0 ? (uint64_t)edit->edited_at
                                                   : envelope_timestamp(envelope);

    if (edit->removed) {
        if (eg->on_message_deleted == NULL) {
            return;
        }

        evergram_message_deleted_t event;
        memset(&event, 0, sizeof(event));
        evergram_copy_bounded(event.chat_id, sizeof(event.chat_id), envelope->chat_id);
        evergram_copy_bounded(event.sender, sizeof(event.sender), envelope->sender);
        if (edit->msg_id != NULL) {
            evergram_copy_bounded(event.message_id, sizeof(event.message_id), edit->msg_id);
        }
        event.timestamp_ms = timestamp;
        eg->on_message_deleted(eg, &event);
        return;
    }

    if (eg->on_message_edited == NULL) {
        return;
    }

    evergram_message_edited_t event;
    memset(&event, 0, sizeof(event));
    evergram_copy_bounded(event.chat_id, sizeof(event.chat_id), envelope->chat_id);
    evergram_copy_bounded(event.sender, sizeof(event.sender), envelope->sender);
    if (edit->msg_id != NULL) {
        evergram_copy_bounded(event.message_id, sizeof(event.message_id), edit->msg_id);
    }
    event.edited_at_ms = timestamp;

    bool deferred = false;
    event.text = decrypt_body(eg, envelope->chat_id, edit->ciphertext, edit->nonce, &deferred);
    if (deferred) {
        return;
    }
    eg->on_message_edited(eg, &event);
}

static void handle_typing(evergram_t *eg, const Evergram__Envelope *envelope) {
    const Evergram__TypingContent *typing = envelope->typing;
    if (typing == NULL || eg->on_typing == NULL) {
        return;
    }

    evergram_typing_event_t event;
    memset(&event, 0, sizeof(event));
    evergram_copy_bounded(event.chat_id, sizeof(event.chat_id), envelope->chat_id);
    evergram_copy_bounded(event.sender, sizeof(event.sender), envelope->sender);
    event.is_typing = typing->is_typing != 0;
    event.timestamp_ms = envelope_timestamp(envelope);

    eg->on_typing(eg, &event);
}

static void handle_reaction(evergram_t *eg, const Evergram__Envelope *envelope) {
    const Evergram__ReactContent *reaction = envelope->react;
    if (reaction == NULL || eg->on_reaction == NULL) {
        return;
    }

    evergram_reaction_t event;
    memset(&event, 0, sizeof(event));
    evergram_copy_bounded(event.chat_id, sizeof(event.chat_id), envelope->chat_id);
    evergram_copy_bounded(event.sender, sizeof(event.sender), envelope->sender);
    if (reaction->msg_id != NULL) {
        evergram_copy_bounded(event.message_id, sizeof(event.message_id), reaction->msg_id);
    }
    event.removed = reaction->removed != 0;
    event.timestamp_ms = envelope_timestamp(envelope);

    if (!event.removed) {
        bool deferred = false;
        const char *emoji = decrypt_body(eg, envelope->chat_id, reaction->ciphertext,
                                         reaction->nonce, &deferred);
        if (deferred) {
            return;
        }
        if (emoji != NULL) {
            evergram_copy_bounded(event.emoji, sizeof(event.emoji), emoji);
        }
    }

    eg->on_reaction(eg, &event);
}

static void handle_envelope(evergram_t *eg, const Evergram__Envelope *envelope) {
    if (envelope == NULL) {
        return;
    }

    EG_DEBUG("envelope %s (content_case=%d)", envelope->type != NULL ? envelope->type : "?",
             (int)envelope->content_case);

    if (envelope->chat_id == NULL || envelope->sender == NULL) {
        EG_WARN("envelope without chat_id/sender ignored");
        return;
    }

    switch (envelope->content_case) {
    case EVERGRAM__ENVELOPE__CONTENT_SEND:
        handle_send(eg, envelope);
        break;
    case EVERGRAM__ENVELOPE__CONTENT_EDIT:
        handle_edit(eg, envelope);
        break;
    case EVERGRAM__ENVELOPE__CONTENT_TYPING:
        handle_typing(eg, envelope);
        break;
    case EVERGRAM__ENVELOPE__CONTENT_REACT:
        handle_reaction(eg, envelope);
        break;
    default:
        EG_TRACE("envelope content_case %d has no handler", (int)envelope->content_case);
        break;
    }
}

/* --- pushes --------------------------------------------------------------- */

static void handle_join_requested(evergram_t *eg, const Evergram__JoinRequestedEvent *event) {
    if (event == NULL || eg->on_join_request == NULL) {
        return;
    }

    evergram_join_request_t request;
    memset(&request, 0, sizeof(request));
    evergram_copy_bounded(request.chat_id, sizeof(request.chat_id),
                          event->chat_id != NULL ? event->chat_id : "");
    evergram_copy_bounded(request.identity, sizeof(request.identity),
                          event->identity != NULL ? event->identity : "");
    evergram_copy_bounded(request.name, sizeof(request.name),
                          event->name != NULL ? event->name : "");
    request.timestamp_ms = event->has_ts && event->ts > 0 ? (uint64_t)event->ts : evergram_now_ms();

    eg->on_join_request(eg, &request);
}

static void handle_presence(evergram_t *eg, const Evergram__AccountPresence *presence) {
    if (presence == NULL || eg->on_presence == NULL) {
        return;
    }

    evergram_presence_t event;
    memset(&event, 0, sizeof(event));
    evergram_copy_bounded(event.identity_key, sizeof(event.identity_key),
                          presence->identity_key != NULL ? presence->identity_key : "");
    event.online = presence->has_status &&
                   presence->status == EVERGRAM__ACCOUNT_PRESENCE__STATUS__ONLINE;
    event.timestamp_ms =
        presence->has_ts && presence->ts > 0 ? (uint64_t)presence->ts : evergram_now_ms();

    eg->on_presence(eg, &event);
}

static void handle_profile_updated(evergram_t *eg, const Evergram__ProfileUpdatedEvent *event) {
    if (event == NULL || eg->on_profile_updated == NULL) {
        return;
    }

    evergram_profile_t profile;
    evergram_profile_from_message(&profile, event->profile);
    eg->on_profile_updated(eg, &profile);
}


/* --- chat requests and group invites --------------------------------------- */

/* Meta carries the group name on both a request and an invite. */
static const char *meta_name(const Evergram__Meta *meta, char *out, size_t out_size) {
    out[0] = '\0';
    if (meta != NULL && meta->name != NULL) {
        evergram_copy_bounded(out, out_size, meta->name);
    }
    return out;
}

/*
 * A reputation change can restrict the account (or lift the restriction). Only
 * the transition into "restricted" is reported, because that is the one a bot
 * has to react to; polling evergram_is_restricted() covers the rest.
 */
static void handle_reputation_updated(evergram_t *eg, const Evergram__ReputationUpdated *event) {
    if (event == NULL) {
        return;
    }

    bool was_restricted = eg->has_access && eg->access.is_restricted;
    bool now_restricted = event->has_is_restricted ? event->is_restricted : was_restricted;

    eg->access.is_restricted = now_restricted;
    eg->has_access = true;

    EG_INFO("reputation updated: restricted=%s", now_restricted ? "yes" : "no");
    if (!now_restricted || was_restricted || eg->on_restricted == NULL) {
        return;
    }

    evergram_reputation_t record;
    memset(&record, 0, sizeof(record));
    evergram_copy_bounded(record.identity, sizeof(record.identity),
                          event->identity != NULL ? event->identity : "");
    record.is_restricted = now_restricted;
    record.has_score = event->has_score;
    record.score = event->score;
    evergram_copy_bounded(record.reason, sizeof(record.reason),
                          event->reason != NULL ? event->reason : "");
    eg->on_restricted(eg, &record);
}

static void handle_chat_request_received(evergram_t *eg, const Evergram__ChatRequestReceivedEvent *event) {
    const Evergram__PendingChatRequest *request = event != NULL ? event->request : NULL;
    if (request == NULL || request->from_identity == NULL || request->from_identity[0] == '\0') {
        return;
    }

    evergram_chat_request_t record;
    memset(&record, 0, sizeof(record));
    evergram_copy_bounded(record.from_identity, sizeof(record.from_identity),
                          request->from_identity);
    meta_name(request->meta, record.nickname, sizeof(record.nickname));
    record.requested_at_ms = request->has_requested_at && request->requested_at > 0
                                 ? (uint64_t)request->requested_at
                                 : 0;

    evergram_note_chat_request(eg, &record);
}

static void handle_group_invite_received(evergram_t *eg, const Evergram__GroupInviteReceivedEvent *event) {
    const Evergram__PendingGroupInvite *invite = event != NULL ? event->invite : NULL;
    if (invite == NULL || invite->chat_id == NULL || invite->chat_id[0] == '\0') {
        return;
    }

    evergram_group_invite_t record;
    memset(&record, 0, sizeof(record));
    evergram_copy_bounded(record.chat_id, sizeof(record.chat_id), invite->chat_id);
    evergram_copy_bounded(record.invited_by, sizeof(record.invited_by),
                          invite->invited_by != NULL ? invite->invited_by : "");
    meta_name(invite->meta, record.name, sizeof(record.name));
    record.invited_at_ms =
        invite->has_invited_at && invite->invited_at > 0 ? (uint64_t)invite->invited_at : 0;

    evergram_note_group_invite(eg, &record);
}

/* --- visitor rooms (ephemeral relay) -------------------------------------- */

/* Copies a protobuf bytes field into a NUL-terminated C string. The wire type is
 * unchecked, so a payload that fills or overflows the buffer is rejected. */
static const char *payload_text(const ProtobufCBinaryData *payload, char *buffer,
                                size_t buffer_size) {
    if (buffer_size == 0) {
        return NULL;
    }
    size_t len = (payload != NULL) ? payload->len : 0;
    if (len >= buffer_size) {
        return NULL;
    }
    if (len > 0 && payload->data != NULL) {
        memcpy(buffer, payload->data, len);
    }
    buffer[len] = '\0';
    return buffer;
}

/* Opens the copy of a room key sealed for this device. */
static bool open_room_key(evergram_t *eg, const char *room_token,
                          const Evergram__VisitorRoomRequestedEvent *event, uint8_t key_out[E2EE_KEY_BYTES]) {
    for (size_t i = 0; i < event->n_sealed_key_by_device; i++) {
        const Evergram__VisitorRoomRequestedEvent__SealedKeyByDeviceEntry *entry =
            event->sealed_key_by_device[i];
        if (entry == NULL || entry->key == NULL || entry->value == NULL) {
            continue;
        }
        if (strcmp(entry->key, eg->device.device_id) != 0) {
            continue;
        }
        const Evergram__SealedKeyForDevice *sealed = entry->value;
        evergram_status_t status =
            e2ee_open_sealed_key(sealed->ciphertext, sealed->nonce, sealed->ephemeral_pubkey,
                                 eg->device.private_key_hex, key_out);
        if (status != EVERGRAM_OK) {
            EG_WARN("cannot open room key for %s: %s", room_token, evergram_status_str(status));
            return false;
        }
        return true;
    }

    EG_DEBUG("room %s carries no key sealed for this device", room_token);
    return false;
}

/* A room offered to one of our widgets. Only the device that claims the room
 * gets it, but every device is told, so a failure here is not fatal. */
static void handle_visitor_room_requested(evergram_t *eg,
                                          const Evergram__VisitorRoomRequestedEvent *event) {
    if (event == NULL || event->room_token == NULL || event->room_token[0] == '\0') {
        return;
    }

    uint8_t key[E2EE_KEY_BYTES];
    if (!open_room_key(eg, event->room_token, event, key)) {
        return;
    }

    if (chatkeys_set_tagged(eg->room_keys, event->room_token, key,
                            EVERGRAM_ROOM_ROLE_JOINER) != EVERGRAM_OK) {
        EG_WARN("cannot store room key for %s", event->room_token);
        sodium_memzero(key, sizeof(key));
        return;
    }

    evergram_visitor_room_t room;
    memset(&room, 0, sizeof(room));
    evergram_copy_bounded(room.room_token, sizeof(room.room_token), event->room_token);
    evergram_copy_bounded(room.widget_id, sizeof(room.widget_id),
                          event->widget_id != NULL ? event->widget_id : "");
    evergram_copy_bounded(room.visitor_label, sizeof(room.visitor_label),
                          event->visitor_label != NULL ? event->visitor_label : "");
    evergram_copy_bounded(room.origin, sizeof(room.origin),
                          event->origin != NULL ? event->origin : "");
    room.timestamp_ms = event->has_ts && event->ts > 0 ? (uint64_t)event->ts : 0;

    /* The first message arrives sealed with the room key, never with a chat key. */
    char payload[EVERGRAM_RELAY_PAYLOAD_MAX];
    const char *text = payload_text(event->has_first_message_payload
                                        ? &event->first_message_payload
                                        : NULL,
                                    payload, sizeof(payload));
    if (text != NULL && text[0] != '\0' &&
        evergram_relay_parse_text(key, text, &room.first_message) == EVERGRAM_OK) {
        room.has_first_message = true;
    }
    sodium_memzero(key, sizeof(key));

    /*
     * Claim the room before reporting it: the slot belongs to a socket, and the
     * visitor's UI only flips to "connected" once a JOINED frame arrives.
     */
    evergram_status_t joined = evergram_visitor_send_frame(eg, event->room_token,
                                                           EVERGRAM_RELAY_KIND_JOINED, NULL);
    if (joined != EVERGRAM_OK) {
        EG_WARN("cannot claim room %s: %s", event->room_token, evergram_status_str(joined));
    }

    if (eg->on_visitor_room != NULL) {
        eg->on_visitor_room(eg, &room);
    }
}

static void handle_visitor_room_timed_out(evergram_t *eg,
                                          const Evergram__VisitorRoomTimedOutEvent *event) {
    if (event == NULL || event->room_token == NULL) {
        return;
    }
    chatkeys_remove(eg->room_keys, event->room_token);
    if (eg->on_visitor_timed_out != NULL) {
        eg->on_visitor_timed_out(eg, event->room_token);
    }
}

/* One relay frame. Content-bearing kinds need the room key; the rest are
 * plaintext by design, so they are delivered even before a key exists. */
static void handle_relay_message(evergram_t *eg, const Evergram__RelayMessage *relay) {
    if (relay == NULL || relay->room_token == NULL || relay->room_token[0] == '\0') {
        return;
    }

    const char *room_token = relay->room_token;
    evergram_relay_kind_t kind =
        evergram_relay_kind_from_wire(relay->has_kind ? (int)relay->kind : -1);
    char payload[EVERGRAM_RELAY_PAYLOAD_MAX];
    const char *text =
        payload_text(relay->has_payload ? &relay->payload : NULL, payload, sizeof(payload));
    if (text == NULL) {
        EG_WARN("relay frame for %s has an oversized payload", room_token);
        return;
    }

    evergram_visitor_state_event_t state;
    memset(&state, 0, sizeof(state));

    if (evergram_relay_kind_is_content(kind)) {
        const uint8_t *key = chatkeys_get(eg->room_keys, room_token);
        if (key == NULL) {
            /*
             * Unlike a chat, a room's key always arrives with the room itself
             * (VisitorRoomRequestedEvent), so a frame for an unknown room means
             * the room is not ours, was already ended, or was claimed by another
             * device. There is nothing to wait for, so it is dropped rather than
             * held in the mailbox — the reference SDK ignores it for the same
             * reason.
             */
            EG_DEBUG("relay frame for unknown room %s ignored", room_token);
            return;
        }

        switch (kind) {
        case EVERGRAM_RELAY_KIND_TEXT: {
            evergram_relay_text_t event;
            if (evergram_relay_parse_text(key, text, &event) == EVERGRAM_OK &&
                eg->on_visitor_text != NULL) {
                eg->on_visitor_text(eg, room_token, &event);
            }
            break;
        }
        case EVERGRAM_RELAY_KIND_REACT: {
            evergram_relay_react_t event;
            if (evergram_relay_parse_react(key, text, &event) == EVERGRAM_OK &&
                eg->on_visitor_react != NULL) {
                eg->on_visitor_react(eg, room_token, &event);
            }
            break;
        }
        case EVERGRAM_RELAY_KIND_EDIT: {
            evergram_relay_edit_t event;
            if (evergram_relay_parse_edit(key, text, &event) == EVERGRAM_OK &&
                eg->on_visitor_edit != NULL) {
                eg->on_visitor_edit(eg, room_token, &event);
            }
            break;
        }
        case EVERGRAM_RELAY_KIND_REMOVE: {
            evergram_relay_remove_t event;
            if (evergram_relay_parse_remove(key, text, &event) == EVERGRAM_OK &&
                eg->on_visitor_remove != NULL) {
                eg->on_visitor_remove(eg, room_token, &event);
            }
            break;
        }
        default:
            break;
        }
        return;
    }

    switch (kind) {
    case EVERGRAM_RELAY_KIND_JOINED:
    case EVERGRAM_RELAY_KIND_RECLAIM:
        state.state = EVERGRAM_VISITOR_STATE_CONNECTED;
        break;
    case EVERGRAM_RELAY_KIND_LEFT:
        state.state = EVERGRAM_VISITOR_STATE_PEER_LEFT;
        evergram_relay_parse_left(text, &state.deadline_ms);
        break;
    case EVERGRAM_RELAY_KIND_END:
        state.state = EVERGRAM_VISITOR_STATE_ENDED;
        chatkeys_remove(eg->room_keys, room_token);
        break;
    case EVERGRAM_RELAY_KIND_CLAIMED_ELSEWHERE:
        state.state = EVERGRAM_VISITOR_STATE_CLAIMED_ELSEWHERE;
        chatkeys_remove(eg->room_keys, room_token);
        break;
    case EVERGRAM_RELAY_KIND_CHANNEL_KICKED: {
        evergram_relay_kicked_t kicked;
        memset(&kicked, 0, sizeof(kicked));
        evergram_relay_parse_kicked(text, &kicked);
        state.state = EVERGRAM_VISITOR_STATE_KICKED;
        evergram_copy_bounded(state.reason, sizeof(state.reason),
                              kicked.banned ? "banned" : "kicked");
        chatkeys_remove(eg->room_keys, room_token);
        break;
    }
    case EVERGRAM_RELAY_KIND_TYPING: {
        evergram_relay_typing_t event;
        memset(&event, 0, sizeof(event));
        if (evergram_relay_parse_typing(text, &event) == EVERGRAM_OK &&
            eg->on_visitor_typing != NULL) {
            eg->on_visitor_typing(eg, room_token, &event);
        }
        return;
    }
    case EVERGRAM_RELAY_KIND_CHANNEL_JOIN:
    case EVERGRAM_RELAY_KIND_CHANNEL_PART: {
        evergram_relay_presence_t event;
        memset(&event, 0, sizeof(event));
        if (evergram_relay_parse_presence(text, &event) == EVERGRAM_OK &&
            eg->on_visitor_presence != NULL) {
            eg->on_visitor_presence(eg, room_token, &event,
                                    kind == EVERGRAM_RELAY_KIND_CHANNEL_JOIN);
        }
        return;
    }
    case EVERGRAM_RELAY_KIND_CHANNEL_MODE: {
        evergram_relay_moderation_t event;
        memset(&event, 0, sizeof(event));
        if (evergram_relay_parse_moderation(text, &event) == EVERGRAM_OK) {
            if (eg->on_visitor_moderation != NULL) {
                eg->on_visitor_moderation(eg, room_token, &event);
            }
            evergram_relay_moderation_dispose(&event);
        }
        return;
    }
    default:
        EG_TRACE("ignoring relay kind %d for %s", (int)kind, room_token);
        return;
    }

    if (eg->on_visitor_state != NULL) {
        eg->on_visitor_state(eg, room_token, &state);
    }
}

/* --- entry point ---------------------------------------------------------- */

static void dispatch_message(evergram_t *eg, const uint8_t *data, size_t len) {
    if (eg == NULL || data == NULL || len == 0) {
        return;
    }

    Evergram__ServerMessage *message = evergram__server_message__unpack(NULL, len, data);
    if (message == NULL) {
        evergram_emit_error(eg, EVERGRAM_ERR_PROTOCOL, "cannot decode ServerMessage");
        return;
    }

    switch (message->payload_case) {
    case EVERGRAM__SERVER_MESSAGE__PAYLOAD_AUTH_CHALLENGE:
        handle_auth_challenge(eg, message->auth_challenge);
        break;
    case EVERGRAM__SERVER_MESSAGE__PAYLOAD_AUTH_RESPONSE:
        handle_auth_response(eg, message->auth_response);
        break;
    case EVERGRAM__SERVER_MESSAGE__PAYLOAD_REGISTER_DEVICE_RESPONSE:
        handle_register_device_response(eg, message->register_device_response);
        break;
    case EVERGRAM__SERVER_MESSAGE__PAYLOAD_ENVELOPE:
        handle_envelope(eg, message->envelope);
        break;
    case EVERGRAM__SERVER_MESSAGE__PAYLOAD_ERROR:
        handle_error(eg, message->error);
        break;
    case EVERGRAM__SERVER_MESSAGE__PAYLOAD_JOIN_REQUESTED_EVENT:
        handle_join_requested(eg, message->join_requested_event);
        break;
    case EVERGRAM__SERVER_MESSAGE__PAYLOAD_REPUTATION_UPDATED:
        handle_reputation_updated(eg, message->reputation_updated);
        break;
    case EVERGRAM__SERVER_MESSAGE__PAYLOAD_CHAT_REQUEST_RECEIVED:
        handle_chat_request_received(eg, message->chat_request_received);
        break;
    case EVERGRAM__SERVER_MESSAGE__PAYLOAD_GROUP_INVITE_RECEIVED:
        handle_group_invite_received(eg, message->group_invite_received);
        break;
    case EVERGRAM__SERVER_MESSAGE__PAYLOAD_ACCOUNT_PRESENCE:
        handle_presence(eg, message->account_presence);
        break;
    case EVERGRAM__SERVER_MESSAGE__PAYLOAD_PROFILE_UPDATED:
        handle_profile_updated(eg, message->profile_updated);
        break;

    /* Visitor rooms (ephemeral relay). */
    case EVERGRAM__SERVER_MESSAGE__PAYLOAD_VISITOR_ROOM_REQUESTED_EVENT:
        handle_visitor_room_requested(eg, message->visitor_room_requested_event);
        break;
    case EVERGRAM__SERVER_MESSAGE__PAYLOAD_VISITOR_ROOM_TIMED_OUT_EVENT:
        handle_visitor_room_timed_out(eg, message->visitor_room_timed_out_event);
        break;
    case EVERGRAM__SERVER_MESSAGE__PAYLOAD_RELAY_MESSAGE:
        handle_relay_message(eg, message->relay_message);
        break;

    /* Messages whose only effect here is teaching us chat keys. */
    case EVERGRAM__SERVER_MESSAGE__PAYLOAD_CREATE_CHAT_RESPONSE:
        apply_chat_info(eg, message->create_chat_response != NULL
                                ? message->create_chat_response->chat
                                : NULL);
        break;
    case EVERGRAM__SERVER_MESSAGE__PAYLOAD_ACCEPT_CHAT_REQUEST_RESPONSE:
        apply_chat_info(eg, message->accept_chat_request_response != NULL
                                ? message->accept_chat_request_response->chat
                                : NULL);
        break;
    case EVERGRAM__SERVER_MESSAGE__PAYLOAD_ROTATE_CHAT_VERSION_RESPONSE:
        apply_chat_info(eg, message->rotate_chat_version_response != NULL
                                ? message->rotate_chat_version_response->chat
                                : NULL);
        break;
    case EVERGRAM__SERVER_MESSAGE__PAYLOAD_QUERY_CHATS_RESPONSE:
        if (message->query_chats_response != NULL) {
            Evergram__QueryChatsResponse *response = message->query_chats_response;
            for (size_t i = 0; i < response->n_results; i++) {
                const Evergram__ChatSyncResult *result = response->results[i];
                if (result == NULL || result->chat_id == NULL) {
                    continue;
                }

                /*
                 * MISSING means the chat is gone server-side (left, deleted, or
                 * this identity was removed from it). Anything else carries the
                 * metadata, or carries none because we are already up to date.
                 */
                if (result->has_status &&
                    result->status == EVERGRAM__CHAT_SYNC_RESULT__STATUS__MISSING) {
                    evergram_forget_chat(eg, result->chat_id);
                    continue;
                }
                apply_chat_info(eg, result->chat);
            }

            /* Requests and invites that were pending before this process
             * started; already-known ones are not reported twice. */
            for (size_t i = 0; i < response->n_pending_chat_requests; i++) {
                const Evergram__PendingChatRequest *pending = response->pending_chat_requests[i];
                if (pending == NULL || pending->from_identity == NULL ||
                    pending->from_identity[0] == '\0') {
                    continue;
                }

                evergram_chat_request_t record;
                memset(&record, 0, sizeof(record));
                evergram_copy_bounded(record.from_identity, sizeof(record.from_identity),
                                      pending->from_identity);
                meta_name(pending->meta, record.nickname, sizeof(record.nickname));
                record.requested_at_ms = pending->has_requested_at && pending->requested_at > 0
                                             ? (uint64_t)pending->requested_at
                                             : 0;
                evergram_note_chat_request(eg, &record);
            }
            for (size_t i = 0; i < response->n_pending_group_invites; i++) {
                const Evergram__PendingGroupInvite *pending = response->pending_group_invites[i];
                if (pending == NULL || pending->chat_id == NULL || pending->chat_id[0] == '\0') {
                    continue;
                }

                evergram_group_invite_t record;
                memset(&record, 0, sizeof(record));
                evergram_copy_bounded(record.chat_id, sizeof(record.chat_id), pending->chat_id);
                evergram_copy_bounded(record.invited_by, sizeof(record.invited_by),
                                      pending->invited_by != NULL ? pending->invited_by : "");
                meta_name(pending->meta, record.name, sizeof(record.name));
                record.invited_at_ms = pending->has_invited_at && pending->invited_at > 0
                                           ? (uint64_t)pending->invited_at
                                           : 0;
                evergram_note_group_invite(eg, &record);
            }

            /* A non-empty cursor means the contract capped this page. */
            if (response->next_cursor != NULL && response->next_cursor[0] != '\0') {
                if (eg->sync_pages < EVERGRAM_MAX_SYNC_PAGES) {
                    eg->sync_pages++;
                    if (evergram_sync_chats_page(eg, response->next_cursor) != EVERGRAM_OK) {
                        EG_WARN("chat sync page %u could not be requested", eg->sync_pages);
                    }
                } else {
                    EG_WARN("chat sync stopped after %d pages", EVERGRAM_MAX_SYNC_PAGES);
                }
            }
        }
        break;

    default:
        EG_TRACE("ignoring server payload_case %d", (int)message->payload_case);
        break;
    }

    /*
     * A synchronous call may be waiting for this response. Side effects above
     * have already run, so ownership just moves to the caller.
     */
    if (eg->call.pending && !eg->call.resolved &&
        (uint32_t)message->payload_case == eg->call.expected_case &&
        (message->request_id == 0 || message->request_id == eg->call.request_id)) {
        eg->call.response = message;
        eg->call.resolved = true;
        return;
    }

    evergram__server_message__free_unpacked(message, NULL);
}

/* Tracks the frame being dispatched so decrypt_body() can hand it to the defer
 * hook, then restores the previous one (console calls may nest). */
void parser_dispatch(evergram_t *eg, const uint8_t *data, size_t len) {
    if (eg == NULL || data == NULL || len == 0) {
        return;
    }

    const uint8_t *previous_frame = eg->frame;
    size_t previous_len = eg->frame_len;
    eg->frame = data;
    eg->frame_len = len;

    dispatch_message(eg, data, len);

    eg->frame = previous_frame;
    eg->frame_len = previous_len;
}
