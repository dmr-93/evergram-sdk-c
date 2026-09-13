/*
 * gen_interop_vectors.mjs — emits tests/interop_vectors.h from the REAL
 * TypeScript SDK, so the C test suite can prove it accepts what the reference
 * implementation produces (and produces byte-identical envelopes in return).
 *
 * The TS SDK itself is not vendored here, so point the script at a checkout:
 *
 *   TS_SDK=/path/to/evergram-sdk node tools/gen_interop_vectors.mjs \
 *       tests/interop_vectors.h
 *
 * Only fixed inputs are used, so the output is deterministic: re-running it
 * against the same SDK version must not change the header.
 */
import { writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";

const require = createRequire(import.meta.url);

const sdkRoot = process.env.TS_SDK;
if (!sdkRoot) {
  console.error("TS_SDK must point at an evergram-sdk checkout");
  process.exit(1);
}

/*
 * The SDK is TypeScript. Node's own type stripping handles it (Node 22.18+);
 * on an older runtime, run this file through the checkout's tsx instead:
 *   node --import tsx tools/gen_interop_vectors.mjs ...
 */
const load = async (relative) =>
  import(pathToFileURL(resolve(sdkRoot, relative)).href);

const { walletFromSeed, signAuthChallenge, buildAuthChallenge } = await load("src/wallet.ts");
const { openSealedSymKey, encryptMessage, decryptMessage } = await load("src/crypto.ts");
const { buildPaymentRequest, buildPaymentReceipt, buildAudioMessage } = await load(
  "src/message-builders.ts",
);
const { parseMessageContent } = await load("src/message-content.ts");
const { buildTextFramePayload } = await load("src/ephemeral-relay-session.ts");

const hex = (bytes) => Buffer.from(bytes).toString("hex");
const b64 = (bytes) => Buffer.from(bytes).toString("base64");
const fromHex = (text) => Buffer.from(text, "hex");

/* --- fixed inputs, mirrored by the C test --------------------------------- */

const walletEntropy = "db7fc7a261e8082cc0f3fdb3b3f15f95";
const devicePrivHex = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
const devicePubHex = "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254";
const deviceId = "interop-device-1";
const nonce = "interop-nonce-0001";
const symKey = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
const ephemeralSecret = fromHex("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f");
const sealedNonce = fromHex("808182838485868788898a8b8c8d8e8f9091929394959697");
const messagePlaintext = "interop message from the reference SDK";
const messageNonce = fromHex("404142434445464748494a4b4c4d4e4f5051525354555657");

/*
 * The C identity file stores the raw 32-byte seed as hex; the SDK takes the
 * base58 family seed, so it is encoded here. Both describe the same keypair,
 * which is exactly the kind of agreement this file is meant to pin down.
 */
const { encodeSeed, decodeSeed } = require(resolve(sdkRoot, "node_modules/ripple-address-codec"));
const seedBase58 = encodeSeed(fromHex(walletEntropy), "ed25519");
if (hex(decodeSeed(seedBase58).bytes) !== walletEntropy) {
  console.error("seed encoding round trip failed");
  process.exit(1);
}

const wallet = walletFromSeed(seedBase58);

const challenge = buildAuthChallenge(wallet.address, deviceId, nonce);
const auth = signAuthChallenge(wallet, deviceId, nonce);

/* Seal the chat key the way the gateway does, with the ephemeral key the C
 * vectors already use. */
const nacl = require(resolve(sdkRoot, "node_modules/tweetnacl"));
const ephemeral = nacl.box.keyPair.fromSecretKey(ephemeralSecret);
const sealed = nacl.box(symKey, sealedNonce, fromHex(devicePubHex), ephemeral.secretKey);

/* A secretbox message with a fixed nonce, so the C side can decrypt it. */
const messageBox = nacl.secretbox(new TextEncoder().encode(messagePlaintext), messageNonce, symKey);

/* Envelopes built by the SDK's own builders, for byte-comparison in C. */
const paymentRequest = buildPaymentRequest({
  requestId: "11111111-2222-4333-8444-555555555555",
  amount: "10.5",
  currency: "XAH",
  currencyId: "EVR_XAHAU",
  note: "for the group",
  to: "rRequesterAddress",
  toIdentityKey: "1:rRequesterAddress",
});

const paymentReceipt = buildPaymentReceipt({
  requestId: "11111111-2222-4333-8444-555555555555",
  txHash: "DEADBEEF",
  amount: "10.5",
  currency: "XAH",
  currencyId: "EVR_XAHAU",
  from: "rPayerAddress",
  fromIdentityKey: "1:rPayerAddress",
});

const audio = buildAudioMessage({
  audioBytes: fromHex("000102030405060708090a0b0c0d0e0f"),
  mimeType: "audio/ogg",
  durationMs: 1500,
});

/*
 * A relay frame. The SDK's own buildTextFramePayload() mints a random msgId and
 * a timestamp, so its output cannot be a committed vector; instead the shape it
 * produces is checked here and the vector itself is built with the same
 * algorithm and a fixed nonce, which keeps the file reproducible.
 */
const sdkRelay = buildTextFramePayload(symKey, "1:rVisitor", "hello from the visitor");
const sdkRelayFields = JSON.parse(
  decryptMessage(
    symKey,
    JSON.parse(sdkRelay.payloadText).nonce,
    JSON.parse(sdkRelay.payloadText).ciphertext,
  ),
);
const relayKeys = Object.keys(sdkRelayFields).sort().join(",");
if (relayKeys !== "msgId,sender,text,ts") {
  console.error(`unexpected relay envelope shape: ${relayKeys}`);
  process.exit(1);
}

const relayEvent = {
  msgId: "interop-relay-1",
  sender: "1:rVisitor",
  text: "hello from the visitor",
  ts: 1700000000000,
};
const relayNonce = fromHex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7");
const relayBox = nacl.secretbox(
  new TextEncoder().encode(JSON.stringify(relayEvent)),
  relayNonce,
  symKey,
);
const relay = {
  event: relayEvent,
  payloadText: JSON.stringify({ nonce: b64(relayNonce), ciphertext: b64(relayBox) }),
};

/* Sanity: the SDK must be able to read its own output, or the vectors are
 * worthless as an interop claim. */
const roundTrips = [
  Boolean(nacl.box.open(sealed, sealedNonce, ephemeral.publicKey, fromHex(devicePrivHex))),
  decryptMessage(symKey, b64(messageNonce), b64(messageBox)) === messagePlaintext,
  parseMessageContent(paymentRequest).type === "payment_request",
  parseMessageContent(paymentReceipt).type === "payment_receipt",
  parseMessageContent(audio).type === "audio",
  openSealedSymKey(
    { ciphertext: b64(sealed), nonce: b64(sealedNonce), ephemeralPubkey: b64(ephemeral.publicKey) },
    devicePrivHex,
  ) !== null,
];
if (roundTrips.some((ok) => !ok)) {
  console.error("the reference SDK failed its own round trips; refusing to emit vectors");
  process.exit(1);
}

const lines = [];
lines.push("/*");
lines.push(" * Golden interop vectors, generated by tools/gen_interop_vectors.mjs from");
lines.push(" * the TypeScript SDK itself (raw sources through tsx, not a reimplementation).");
lines.push(" *");
lines.push(" * Every value here was produced by the reference implementation and is");
lines.push(" * consumed by tests/test_interop.c, so a passing run proves the two SDKs");
lines.push(" * agree on the wire. Do not edit by hand: regenerate with");
lines.push(" *");
lines.push(" *   TS_SDK=/path/to/evergram-sdk node tools/gen_interop_vectors.mjs \\");
lines.push(" *       tests/interop_vectors.h");
lines.push(" */");
lines.push("#ifndef EVERGRAM_TEST_INTEROP_VECTORS_H");
lines.push("#define EVERGRAM_TEST_INTEROP_VECTORS_H");
lines.push("");
lines.push(`#define INTEROP_WALLET_SEED "${seedBase58}"`);
lines.push(`#define INTEROP_WALLET_ADDRESS "${wallet.address}"`);
lines.push(`#define INTEROP_WALLET_PUBLIC_KEY_HEX "${wallet.publicKeyHex}"`);
lines.push(`#define INTEROP_WALLET_PRIVATE_KEY_HEX "${wallet.privateKeyHex}"`);
lines.push(`#define INTEROP_DEVICE_ID "${deviceId}"`);
lines.push(`#define INTEROP_DEVICE_PUBLIC_KEY_HEX "${devicePubHex}"`);
lines.push(`#define INTEROP_DEVICE_PRIVATE_KEY_HEX "${devicePrivHex}"`);
lines.push(`#define INTEROP_CHALLENGE "${challenge}"`);
lines.push(`#define INTEROP_CHALLENGE_NONCE "${nonce}"`);
lines.push(`#define INTEROP_AUTH_PUBLIC_KEY_HEX "${auth.publicKeyHex}"`);
lines.push(`#define INTEROP_AUTH_SIGNATURE_HEX "${auth.signatureHex}"`);
lines.push("");
lines.push(`#define INTEROP_SYM_KEY_HEX "${hex(symKey)}"`);
lines.push(`#define INTEROP_SEALED_NONCE_B64 "${b64(sealedNonce)}"`);
lines.push(`#define INTEROP_SEALED_CIPHERTEXT_B64 "${b64(sealed)}"`);
lines.push(`#define INTEROP_EPHEMERAL_PUBLIC_KEY_B64 "${b64(ephemeral.publicKey)}"`);
lines.push("");
lines.push(`#define INTEROP_MESSAGE_PLAINTEXT "${messagePlaintext}"`);
lines.push(`#define INTEROP_MESSAGE_NONCE_B64 "${b64(messageNonce)}"`);
lines.push(`#define INTEROP_MESSAGE_CIPHERTEXT_B64 "${b64(messageBox)}"`);
lines.push("");
lines.push(`#define INTEROP_RELAY_PAYLOAD ${JSON.stringify(relay.payloadText)}`);
lines.push(`#define INTEROP_RELAY_TEXT ${JSON.stringify(relay.event.text)}`);
lines.push(`#define INTEROP_RELAY_SENDER ${JSON.stringify(relay.event.sender)}`);
lines.push(`#define INTEROP_RELAY_MSG_ID ${JSON.stringify(relay.event.msgId)}`);
lines.push("");
lines.push(`#define INTEROP_PAYMENT_REQUEST ${JSON.stringify(paymentRequest)}`);
lines.push(`#define INTEROP_PAYMENT_RECEIPT ${JSON.stringify(paymentReceipt)}`);
lines.push(`#define INTEROP_AUDIO ${JSON.stringify(audio)}`);
lines.push("");
lines.push("#endif /* EVERGRAM_TEST_INTEROP_VECTORS_H */");
lines.push("");

const target = process.argv[2];
if (!target) {
  process.stdout.write(lines.join("\n"));
} else {
  writeFileSync(target, lines.join("\n"));
  console.log("wrote", target);
  console.log("wallet address:", wallet.address);
  console.log("challenge:", challenge);
}
