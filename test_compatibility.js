const ripple = require('ripple-keypairs');
const crypto = require('crypto');

// Simular exatamente o que o C faz:
// 1. Seed de 32 bytes hex
// 2. Usar libsodium crypto_sign_seed_keypair equivalente

// Para testar, vamos usar uma seed fixa
const seedHex = 'db7fc7a261e8082cc0f3fdb3b3f15f95bb727ba9b533246eb4d46ec70604ea96';

// ripple-keypairs não aceita seed hex direta, precisa converter para Base58 primeiro
// OU podemos usar o método interno

// Hack: usar generateSeed com entropy fixa
const seedBytes = Buffer.from(seedHex, 'hex');

// ripple-address-codec encodeSeed
function encodeSeed(entropy, type = 'ed25519') {
    const rippleAddressCodec = require('ripple-address-codec');
    // entropy deve ser 16 bytes para encodeSeed
    // Mas temos 32 bytes... isso é o problema!
    
    // ripple-keypairs usa seed de 16 bytes (entropy) + aplica SHA512
    // Nosso C usa seed de 32 bytes direta
    
    // Solução: usar apenas 16 bytes da seed
    const entropy16 = seedBytes.slice(0, 16);
    return rippleAddressCodec.encodeSeed(entropy16, type);
}

const seedBase58 = encodeSeed(seedBytes.slice(0, 16));
console.log('Seed Base58 (16 bytes entropy):', seedBase58);

const kp = ripple.deriveKeypair(seedBase58);
console.log('Public Key:', kp.publicKey);
console.log('Private Key:', kp.privateKey);

// Assinar mensagem de teste
const address = 'rHuSNywCvi2BKVK1JcFL5WTjKh4cHMrXss';
const deviceId = '389a5006d4ad24cd5f35cbcd2cf7fb70';
const nonce = '48f55c342e81c3394a3fc62bd3d9cb46';

const message = `evergram-auth:${address}:${deviceId}:${nonce}`;
const messageHex = Buffer.from(message, 'utf8').toString('hex');

console.log('\nMensagem:', message);
console.log('Message Hex:', messageHex);

const signature = ripple.sign(messageHex, kp.privateKey);
console.log('Signature:', signature);

const valid = ripple.verify(messageHex, signature, kp.publicKey);
console.log('Valid?', valid);

// Output para o C usar
console.log('\n=== Dados para enviar ao servidor ===');
console.log('publicKeyHex:', kp.publicKey);
console.log('signatureHex:', signature);
