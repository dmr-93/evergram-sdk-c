const ripple = require('ripple-keypairs');

const args = process.argv.slice(2);
if (args.length !== 2) {
    console.error("Uso: node sign_wrapper.js <seed_hex> <message_hex>");
    process.exit(1);
}

const seedHex = args[0];
const messageHex = args[1];

try {
    const seedBytes = Buffer.from(seedHex, 'hex');
    
    // Obter as versões corretas decodificando uma seed gerada
    const tempSeed = ripple.generateSeed();
    const decodedTemp = ripple.decodeSeed(tempSeed);
    const versionBytes = decodedTemp.version; // [1, 225, 75] para Ed25519
    
    console.error("DEBUG: Version bytes:", versionBytes);
    
    // Payload = version + seed bytes
    const payload = Buffer.concat([Buffer.from(versionBytes), seedBytes]);
    
    // Checksum = primeiros 4 bytes de SHA256(SHA256(payload))
    const crypto = require('crypto');
    const hash1 = crypto.createHash('sha256').update(payload).digest();
    const hash2 = crypto.createHash('sha256').update(hash1).digest();
    const checksum = hash2.slice(0, 4);
    
    const fullPayload = Buffer.concat([payload, checksum]);
    
    // Base58 encode
    const ALPHABET = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz';
    let num = BigInt('0x' + fullPayload.toString('hex'));
    let encoded = '';
    
    while (num > 0n) {
        const remainder = num % 58n;
        num = num / 58n;
        encoded = ALPHABET[Number(remainder)] + encoded;
    }
    
    for (let i = 0; i < fullPayload.length && fullPayload[i] === 0; i++) {
        encoded = '1' + encoded;
    }
    
    const seedBase58 = encoded;
    console.error("DEBUG: Seed base58:", seedBase58);
    
    // Verificar decodificação
    const decoded = ripple.decodeSeed(seedBase58);
    console.error("DEBUG: Decodificada:", decoded.type, decoded.bytes.toString('hex'));
    
    // Derivar e assinar
    const keypair = ripple.deriveKeypair(seedBase58);
    const signature = ripple.sign(messageHex, keypair.privateKey);
    const verified = ripple.verify(messageHex, signature, keypair.publicKey);
    
    console.log(JSON.stringify({
        publicKey: keypair.publicKey,
        signature: signature,
        verified: verified
    }));
    
} catch (error) {
    console.error("Erro:", error.message);
    process.exit(1);
}
