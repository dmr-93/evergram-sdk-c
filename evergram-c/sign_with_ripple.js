/**
 * Wrapper JavaScript para assinatura usando libsodium (compativel com Ed25519 puro)
 * Uso: node sign_with_sodium.js <message_hex> <seed_hex_32bytes>
 * Retorna: { publicKey, signature } em JSON
 * 
 * Este script usa libsodium diretamente porque:
 * - ripple-keypairs v3.x so aceita seeds de 16 bytes (entropy) ou Base58
 * - Nossa seed sao 32 bytes, formato nativo do Ed25519/libsodium
 */

const sodium = require('sodium-native');

// Argumentos da linha de comando
const messageHex = process.argv[2];
const seedHex = process.argv[3];

if (!messageHex || !seedHex) {
    console.error(JSON.stringify({ error: "Uso: node sign_with_sodium.js <message_hex> <seed_hex_32bytes>" }));
    process.exit(1);
}

try {
    // Validar seed (deve ser 64 chars hex = 32 bytes)
    if (seedHex.length !== 64) {
        throw new Error("Seed deve ser 64 caracteres hex (32 bytes)");
    }
    
    // Converter seed hex para bytes
    const seed = Buffer.from(seedHex, 'hex');
    if (seed.length !== 32) {
        throw new Error("Seed deve ter exatamente 32 bytes");
    }
    
    // Derivar par de chaves Ed25519 da seed
    const publicKey = Buffer.alloc(32);
    const secretKey = Buffer.alloc(64);
    
    sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed);
    
    // Converter mensagem hex para bytes
    const message = Buffer.from(messageHex, 'hex');
    
    // Assinar mensagem
    const signature = Buffer.alloc(64);
    sodium.crypto_sign_detached(signature, message, secretKey);
    
    // Retornar resultado em JSON
    // Remover prefixo ED da public key para ficar no formato esperado
    console.log(JSON.stringify({
        success: true,
        publicKey: publicKey.toString('hex'),  // 32 bytes hex sem prefixo
        signature: signature.toString('hex'),  // 64 bytes hex
        privateKey: secretKey.toString('hex')  // 64 bytes hex (secret key completa)
    }));
    
} catch (error) {
    console.error(JSON.stringify({
        success: false,
        error: error.message
    }));
    process.exit(1);
}
