#include <sodium.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "evergram.pb-c.h"
#include "internal.h"
#include "xrpl.h"

/*
 * Bootstrap messages: AuthChallenge -> AuthRequest -> (RegisterDevice) -> AuthRequest.
 *
 * Wire layout notes:
 *  - request_id is a correlation id; the gateway strips it before the contract.
 *  - protobuf-c drives every oneof through the *_case member, never through the
 *    union pointers (all members alias the same address).
 *  - the gateway requires the 0xED prefix on ed25519 public keys, and derives
 *    the account address from that same prefixed key.
 */

#define CHALLENGE_PREFIX "evergram-auth"
#define CHALLENGE_HEADROOM 256
#define IDENTITY_NETWORK_ID "0"

static void fill_identity(Evergram__ChainIdentity *identity, const evergram_t *eg) {
    identity->has_chain_family = 1;
    identity->chain_family = EVERGRAM__CHAIN_FAMILY__XRPL;
    identity->address = (char *)eg->wallet.address;
    identity->network_id = IDENTITY_NETWORK_ID;
}

static void fill_device(Evergram__Device *device, const evergram_t *eg) {
    device->device_id = (char *)eg->device.device_id;
    device->device_pub_hex = (char *)eg->device.public_key_hex;
    device->platform = (char *)eg->platform;
}

evergram_status_t handshake_send_auth(evergram_t *eg) {
    if (eg == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }
    if (eg->challenge_len == 0) {
        return EVERGRAM_ERR_STATE;
    }

    char challenge[EVERGRAM_CHALLENGE_SIZE + CHALLENGE_HEADROOM];
    int length = snprintf(challenge, sizeof(challenge), CHALLENGE_PREFIX ":%s:%s:%s",
                          eg->wallet.address, eg->device.device_id, eg->challenge);
    if (length < 0 || (size_t)length >= sizeof(challenge)) {
        sodium_memzero(challenge, sizeof(challenge));
        return EVERGRAM_ERR_BUFFER_TOO_SMALL;
    }

    char signature_hex[2u * XRPL_SIGNATURE_BYTES + 1u];
    EG_DEBUG("auth challenge: %s", challenge);
    EG_DEBUG("auth public key: %s (private key %zu chars, address %s, device %s)",
             eg->wallet.public_key_hex, strlen(eg->wallet.private_key_hex), eg->wallet.address,
             eg->device.device_id);
    evergram_status_t status =
        xrpl_sign(eg->wallet.private_key_hex, (const uint8_t *)challenge, (size_t)length,
                  signature_hex, sizeof(signature_hex));
    sodium_memzero(challenge, sizeof(challenge));
    if (status != EVERGRAM_OK) {
        EG_ERROR("cannot sign auth challenge: %s", evergram_status_str(status));
        return status;
    }

    Evergram__ChainIdentity identity = EVERGRAM__CHAIN_IDENTITY__INIT;
    fill_identity(&identity, eg);

    Evergram__SignedMessageProof signed_proof = EVERGRAM__SIGNED_MESSAGE_PROOF__INIT;
    signed_proof.public_key_hex = (char *)eg->wallet.public_key_hex;
    signed_proof.signature_hex = signature_hex;

    Evergram__AuthProof proof = EVERGRAM__AUTH_PROOF__INIT;
    proof.proof_case = EVERGRAM__AUTH_PROOF__PROOF_SIGNED_MESSAGE;
    proof.signed_message = &signed_proof;

    Evergram__Device device = EVERGRAM__DEVICE__INIT;
    fill_device(&device, eg);

    Evergram__Auth auth = EVERGRAM__AUTH__INIT;
    auth.identity = &identity;
    auth.proof = &proof;
    auth.device = &device;

    Evergram__ClientMessage message = EVERGRAM__CLIENT_MESSAGE__INIT;
    evergram_set_request_id(&message, evergram_take_request_id(eg));
    message.auth = &auth;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_AUTH;

    status = evergram_send_client_message(eg, &message, "auth");
    if (status == EVERGRAM_OK) {
        EG_DEBUG("auth signature: %s", signature_hex);
    }
    sodium_memzero(signature_hex, sizeof(signature_hex));

    if (status == EVERGRAM_OK) {
        eg->state = EG_STATE_AWAITING_AUTH;
    }
    return status;
}

evergram_status_t handshake_send_register_device(evergram_t *eg) {
    if (eg == NULL) {
        return EVERGRAM_ERR_INVALID_ARG;
    }

    Evergram__ChainIdentity identity = EVERGRAM__CHAIN_IDENTITY__INIT;
    fill_identity(&identity, eg);

    Evergram__Device device = EVERGRAM__DEVICE__INIT;
    fill_device(&device, eg);

    Evergram__RegisterDevice registration = EVERGRAM__REGISTER_DEVICE__INIT;
    registration.identity = &identity;
    registration.device = &device;

    Evergram__ClientMessage message = EVERGRAM__CLIENT_MESSAGE__INIT;
    evergram_set_request_id(&message, evergram_take_request_id(eg));
    message.register_device = &registration;
    message.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_REGISTER_DEVICE;

    evergram_status_t status = evergram_send_client_message(eg, &message, "registerDevice");
    if (status == EVERGRAM_OK) {
        eg->state = EG_STATE_REGISTERING;
    }
    return status;
}
