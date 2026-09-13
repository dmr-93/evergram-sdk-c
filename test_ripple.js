const ripple = require('ripple-keypairs');

// Testar quais funções estão disponíveis
console.log("Funções disponíveis no ripple-keypairs:");
console.log(Object.keys(ripple));

// Testar com seed em base58 diretamente (formato XRPL)
// Seed hex: cf48255fe16b4af10bf50a4bdf1f670033e0fff8f357e7fa7f9cdea9dca49a82
// Vamos tentar usar a função deriveKeypair com uma seed no formato correto

// Primeiro, vamos ver se conseguimos importar o módulo xrpl-tagged-address-codec ou similar
// para codificar a seed corretamente

// Alternativa: usar o próprio ripple-keypairs para gerar uma seed e ver o formato
const generated = ripple.generateSeed();
console.log("\nSeed gerada:", generated);

const keypair = ripple.deriveKeypair(generated);
console.log("Keypair derivado:", keypair);

// Agora assinar uma mensagem de teste
const msg = "48656c6c6f"; // "Hello" em hex
const sig = ripple.sign(msg, keypair.privateKey);
console.log("Assinatura:", sig);
console.log("Verificação:", ripple.verify(msg, sig, keypair.publicKey));
