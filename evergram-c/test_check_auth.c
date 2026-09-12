#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include "src/proto/evergram.pb-c.h"

int main() {
    if (sodium_init() < 0) return 1;
    
    const char* seed_hex = "cf4e51fcb1100bd8e2620d496cfba8777a0b6f2ca65dc739a49d34909ff5cf88";
    const char* nonce_hex = "61cfd924da74c9d13825a98704fd709d";
    const char* address = "r3fbdvnvLzcDqGiGezdH87UQVZDrNK2Gjx";
    const char* device_id = "d58f50052b0ebe57026175807d61877c";
    
    // Construir challenge
    char challenge[512];
    int len = snprintf(challenge, sizeof(challenge), "evergram-auth:%s:%s:%s", address, device_id, nonce_hex);
    
    // Decodificar seed e derivar chaves
    unsigned char seed_bytes[32];
    size_t bin_len;
    sodium_hex2bin(seed_bytes, 32, seed_hex, strlen(seed_hex), NULL, &bin_len, NULL);
    
    unsigned char pk[32], sk[64];
    crypto_sign_seed_keypair(pk, sk, seed_bytes);
    
    // Assinar
    unsigned char signature[64];
    crypto_sign_detached(signature, NULL, (const unsigned char*)challenge, len, sk);
    
    char pk_hex[65], sig_hex[129];
    sodium_bin2hex(pk_hex, sizeof(pk_hex), pk, 32);
    sodium_bin2hex(sig_hex, sizeof(sig_hex), signature, 64);
    
    printf("Public Key Hex: %s\n", pk_hex);
    printf("Signature Hex:  %s\n\n", sig_hex);
    
    // Construir Auth message
    Evergram__ChainIdentity identity = EVERGRAM__CHAIN_IDENTITY__INIT;
    identity.has_chain_family = 1;
    identity.chain_family = EVERGRAM__CHAIN_FAMILY__XRPL;
    identity.address = (char*)address;
    identity.network_id = "0";
    
    Evergram__SignedMessageProof signed_proof = EVERGRAM__SIGNED_MESSAGE_PROOF__INIT;
    signed_proof.public_key_hex = pk_hex;
    signed_proof.signature_hex = sig_hex;
    
    Evergram__AuthProof proof = EVERGRAM__AUTH_PROOF__INIT;
    proof.proof_case = EVERGRAM__AUTH_PROOF__PROOF_SIGNED_MESSAGE;
    proof.signed_message = &signed_proof;
    
    Evergram__Device device = EVERGRAM__DEVICE__INIT;
    device.device_id = (char*)device_id;
    device.device_pub_hex = "38a8b03f2efbad5d0562f5b211875ff125ef36c275b9a8df41d0552a10fd610f";
    device.platform = "Terminal";
    
    Evergram__Auth auth = EVERGRAM__AUTH__INIT;
    auth.identity = &identity;
    auth.proof = &proof;
    auth.device = &device;
    
    Evergram__ClientMessage msg = EVERGRAM__CLIENT_MESSAGE__INIT;
    msg.request_id = 1;
    msg.auth = &auth;
    msg.payload_case = EVERGRAM__CLIENT_MESSAGE__PAYLOAD_AUTH;
    
    size_t packed_size = evergram__client_message__get_packed_size(&msg);
    uint8_t *packed = malloc(packed_size);
    evergram__client_message__pack(&msg, packed);
    
    printf("Tamanho da mensagem Auth: %zu bytes\n", packed_size);
    printf("Primeiros 50 bytes: ");
    for (size_t i = 0; i < (packed_size < 50 ? packed_size : 50); i++) {
        printf("%02x ", packed[i]);
    }
    printf("\n");
    
    free(packed);
    return 0;
}
