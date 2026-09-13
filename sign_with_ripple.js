const ripple = require('ripple-keypairs');

// Lê argumentos da linha de comando
const args = process.argv.slice(2);
const action = args[0];

if (action === 'sign') {
    // sign <seed_base58> <message_hex>
    const seedBase58 = args[1];
    const messageHex = args[2];
    
    if (!seedBase58 || !seedBase58.startsWith('sEd')) {
        console.error("ERRO: Seed deve ser Base58 e começar com 'sEd'");
        process.exit(1);
    }
    
    if (!messageHex) {
        console.error("ERRO: Message hex é obrigatória");
        process.exit(1);
    }
    
    try {
        // Deriva o par de chaves da seed Base58
        const keypair = ripple.deriveKeypair(seedBase58);
        
        // Assina a mensagem
        const signature = ripple.sign(messageHex, keypair.privateKey);
        
        // Verifica a assinatura
        const isValid = ripple.verify(messageHex, signature, keypair.publicKey);
        
        console.log(JSON.stringify({
            signature: signature,
            publicKey: keypair.publicKey,
            verified: isValid
        }));
    } catch (e) {
        console.error("ERRO ao assinar:", e.message);
        process.exit(1);
    }
} else if (action === 'test') {
    // test - apenas para teste, gera uma seed e assina uma mensagem
    const seed = ripple.generateSeed({algorithm: 'ed25519'});
    const keypair = ripple.deriveKeypair(seed);
    const msg = '68656c6c6f'; // 'hello'
    const sig = ripple.sign(msg, keypair.privateKey);
    const verified = ripple.verify(msg, sig, keypair.publicKey);
    
    console.log(JSON.stringify({
        seed: seed,
        privateKey: keypair.privateKey,
        publicKey: keypair.publicKey,
        signature: sig,
        verified: verified
    }));
} else {
    console.error("Uso: node sign_with_ripple.js sign <seed_base58> <message_hex>");
    console.error("   ou: node sign_with_ripple.js test");
    process.exit(1);
}
