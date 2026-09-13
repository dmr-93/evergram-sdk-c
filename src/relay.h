#ifndef EVERGRAM_RELAY_H
#define EVERGRAM_RELAY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "e2ee.h"
#include "evergram/status.h"
#include "evergram/types.h"

/* Generated protobuf type, only needed by pointer here. */
struct Evergram__RelayMessage;

/*
 * Ephemeral relay codec (visitor rooms, widget channels).
 *
 * Frames travel as RelayMessage { room_token, kind, payload }. The kind is
 * visible to the gateway; content-bearing kinds (text, react, edit, remove)
 * carry {"nonce","ciphertext"} JSON produced with the ROOM's own symmetric key,
 * and the plaintext underneath is a small JSON envelope. Presence, typing,
 * moderation and lifecycle kinds are deliberately plaintext: they describe
 * liveness, not content.
 *
 * Enum values match the wire enum exactly, so the mapping is a range check.
 */

/* Frame kinds, event structs and the kind mapping live in the public header
 * because callbacks hand them to applications. */
/* Base64 ciphertext plus the JSON envelope around it. */
#define EVERGRAM_RELAY_PAYLOAD_MAX (E2EE_CIPHERTEXT_B64_SIZE(EVERGRAM_TEXT_SIZE) + 128)

/* Enum values are the wire values; anything outside the range is UNKNOWN. */
evergram_relay_kind_t evergram_relay_kind_from_wire(int wire_kind);
int evergram_relay_kind_to_wire(evergram_relay_kind_t kind);

/* True for the nacl-encrypted kinds (text, react, edit, remove). */
bool evergram_relay_kind_is_content(evergram_relay_kind_t kind);

/*
 * Fills the wire message for one frame. `payload` is passed through as-is (the
 * wire type is bytes, so it is NOT NUL-terminated on the wire) and may be NULL
 * or empty for the kinds that carry none.
 */
void evergram_relay_fill_message(struct Evergram__RelayMessage *relay, const char *room_token,
                                 evergram_relay_kind_t kind, const char *payload);

/* --- content frames (encrypted) -------------------------------------------- */

evergram_status_t evergram_relay_build_text(const uint8_t sym_key[E2EE_KEY_BYTES],
                                            const char *sender, const char *text, char *payload,
                                            size_t payload_size, evergram_relay_text_t *event_out);

evergram_status_t evergram_relay_build_react(const uint8_t sym_key[E2EE_KEY_BYTES],
                                             const char *msg_id, const char *emoji, bool removed,
                                             char *payload, size_t payload_size);

evergram_status_t evergram_relay_build_edit(const uint8_t sym_key[E2EE_KEY_BYTES],
                                            const char *msg_id, const char *text, char *payload,
                                            size_t payload_size);

evergram_status_t evergram_relay_build_remove(const uint8_t sym_key[E2EE_KEY_BYTES],
                                              const char *msg_id, char *payload, size_t payload_size);

evergram_status_t evergram_relay_parse_text(const uint8_t sym_key[E2EE_KEY_BYTES],
                                            const char *payload, evergram_relay_text_t *out);

evergram_status_t evergram_relay_parse_react(const uint8_t sym_key[E2EE_KEY_BYTES],
                                             const char *payload, evergram_relay_react_t *out);

evergram_status_t evergram_relay_parse_edit(const uint8_t sym_key[E2EE_KEY_BYTES],
                                            const char *payload, evergram_relay_edit_t *out);

evergram_status_t evergram_relay_parse_remove(const uint8_t sym_key[E2EE_KEY_BYTES],
                                              const char *payload, evergram_relay_remove_t *out);

/* --- liveness frames (plaintext) ------------------------------------------- */

evergram_status_t evergram_relay_build_typing(bool is_typing, const char *sender, char *payload,
                                              size_t payload_size);

evergram_status_t evergram_relay_build_presence(const char *sender, const char *previous_sender,
                                                char *payload, size_t payload_size);

evergram_status_t evergram_relay_parse_typing(const char *payload, evergram_relay_typing_t *out);

evergram_status_t evergram_relay_parse_presence(const char *payload,
                                                evergram_relay_presence_t *out);

evergram_status_t evergram_relay_parse_moderation(const char *payload,
                                                  evergram_relay_moderation_t *out);

void evergram_relay_moderation_dispose(evergram_relay_moderation_t *state);

/* Absent or unparseable payload means "no deadline known", not an error. */
evergram_status_t evergram_relay_parse_left(const char *payload, uint64_t *deadline_ms_out);

/* Anything but reason == "banned" is a plain kick. */
evergram_status_t evergram_relay_parse_kicked(const char *payload,
                                              evergram_relay_kicked_t *out);

#endif /* EVERGRAM_RELAY_H */
