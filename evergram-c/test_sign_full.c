#include <stdio.h>
#include <string.h>
#include <sodium.h>

// Copia da funcao evergram_sign_with_xrpl_seed simplificada
int sign_message(const char* message_hex, const char* private_key_hex, char* signature_hex) {
    // Decodificar mensagem hex para bytes
    size_t msg_len = strlen(message_hex);
    if (msg_len % 2 != 0) return -1;
    
    unsigned char message[msg_len / 2];
    size_t bin_msg_len;
    if (sodium_hex2bin(message, sizeof(message), message_hex, msg_len, NULL, &bin_msg_len, NULL) != 0) {
        return -1;
    }
    
    printf("Mensagem para assinar (%zu bytes): ", bin_msg_len);
    for (size_t i = 0; i < bin_msg_len && i < 50; i++) {
        printf("%02x ", message[i]);
    }
    printf("\n");
    
    // Decodificar private key hex
    unsigned char sk_bytes[64];
    size_t sk_bin_len;
    
    if (strlen(private_key_hex) == 64) {
        // Seed de 32 bytes
        if (sodium_hex2bin(sk_bytes, 32, private_key_hex, 64, NULL, &sk_bin_len, NULL) != 0) {
            return -1;
        }
        
        printf("Seed (32 bytes): ");
        for (int i = 0; i < 32; i++) {
            printf("%02x", sk_bytes[i]);
        }
        printf("\n");
        
        // Derivar par de chaves
        unsigned char pk[32];
        unsigned char sk[64];
        crypto_sign_seed_keypair(pk, sk, sk_bytes);
        
        printf("Public key derivada: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", pk[i]);
        }
        printf("...\n");
        
        // Assinar
        unsigned char signature[64];
        crypto_sign_detached(signature, NULL, message, bin_msg_len, sk);
        
        sodium_bin2hex(signature_hex, 129, signature, 64);
        
        // Verificar
        if (crypto_sign_verify_detached(signature, message, bin_msg_len, pk) != 0) {
            printf("ERRO: Verificacao falhou!\n");
            return -1;
        }
        printf("Assinatura verificada com sucesso!\n");
        return 0;
    }
    
    printf("Private key deve ter 64 caracteres hex\n");
    return -1;
}

int main() {
    sodium_init();
    
    // Seed do identity.json
    const char* seed_hex = "cf4e51fcb1100bd8e2620d496cfba8777a0b6f2ca65dc739a49d34909ff5cf88";
    
    // Mensagem a ser assinada (como string UTF-8)
    const char* message_utf8 = "evergram-auth:r3fbdvnvLzcDqGiGezdH87UQVZDrNK2Gjx:d58f50052b0ebe57026175807d61877c:c0b090c98af864a14770481c68c08451";
    
    printf("Mensagem UTF-8: %s\n", message_utf8);
    printf("Comprimento: %zu\n", strlen(message_utf8));
    
    // Converter mensagem para hex
    char message_hex[1025];
    sodium_bin2hex(message_hex, sizeof(message_hex), (const unsigned char*)message_utf8, strlen(message_utf8));
    
    printf("Mensagem em hex: %s\n", message_hex);
    
    // Assinar
    char signature_hex[129];
    int ret = sign_message(message_hex, seed_hex, signature_hex);
    
    if (ret == 0) {
        printf("\nAssinatura final: %s\n", signature_hex);
    } else {
        printf("\nERRO ao assinar!\n");
    }
    
    return 0;
}
