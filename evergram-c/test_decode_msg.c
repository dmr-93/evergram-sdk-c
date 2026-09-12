#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "proto/evergram.pb-c.h"

int main() {
    // Mensagem hex capturada do log
    const char* msg_hex = "12e6020a29 08011222 724b33565556747378323845746a6e3547547054687635776243707a59674137746a1a013012c801 12c5010a40 62623436663236323563...";
    
    // Vamos decodificar manualmente os campos importantes
    // O formato protobuf é: tag + type + length + data
    
    // Field 2 (auth) = tag 0x12, length varint
    // Dentro de auth:
    //   Field 1 (identity) = tag 0x0a
    //   Field 2 (proof) = tag 0x12  
    //   Field 3 (device) = tag 0x1a
    
    // O problema pode estar no publicKeyHex que está sendo enviado
    // No log vemos: 0a40 62623436663236323563... 
    // 0a = field 1, type string
    // 40 = 64 bytes (length)
    // 62623436663236323563... = "bb46f2625c..." em ASCII hex
    
    printf("Analisando mensagem...\n\n");
    
    // A public key está sendo enviada como string HEX de 64 caracteres
    // Mas talvez o servidor espere bytes binários de 32 bytes?
    
    // Vamos verificar o TypeScript SDK
    // Em wallet.ts, publicKeyHex é realmente uma string hexadecimal
    
    // O problema pode estar na assinatura!
    // Estamos assinando os bytes UTF-8 da mensagem challenge
    // Mas talvez precisemos assinar algo diferente
    
    printf("Possiveis problemas:\n");
    printf("1. Assinatura sendo feita sobre dados errados\n");
    printf("2. Public key format errado (hex vs binary)\n");
    printf("3. Nonce sendo usado incorretamente\n");
    
    return 0;
}
