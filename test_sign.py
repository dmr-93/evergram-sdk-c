import hashlib
import binascii

# Seed do identity.json (32 bytes hex)
seed_hex = "a4ae5165c6e33b7e8977ee4da783638026eb712820509621a8f63be63e2aa513"
seed = binascii.unhexlify(seed_hex)

# Gerar chaves Ed25519 usando libsodium (mesmo que C SDK)
import nacl.signing as signing

signer = signing.SigningKey(seed)
verify_key = signer.verify_key

print(f"Public key: {verify_key.encode().hex()}")

# Challenge string
address = "rhVvUqMuF5JwKg9cev6WfrkeiahjiedhkM"
device_id = "0d926bfc9b3d87ec70ffe9abe5d1caac"
nonce = "05903b5dcc350a5b708be80668fb7df2"

challenge = f"evergram-auth:{address}:{device_id}:{nonce}"
print(f"\nChallenge string: {challenge}")
print(f"Challenge bytes (hex): {challenge.encode('utf-8').hex()}")

# Assinar
signature = signer.sign(challenge.encode('utf-8'))
print(f"\nSignature: {signature.signature.hex()}")
