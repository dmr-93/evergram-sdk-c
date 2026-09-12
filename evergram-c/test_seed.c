#include <stdio.h>
#include <string.h>
#include <sodium.h>

int main() {
    const char* seed_hex = "9dbf497f6ef259b193942716e3b6f1791cb7115609b459fb3449d63cd97744c0";
    unsigned char temp[32];
    size_t bin_len;
    
    int ret = sodium_hex2bin(temp, sizeof(temp), seed_hex, strlen(seed_hex), NULL, &bin_len, NULL);
    printf("sodium_hex2bin returned: %d\n", ret);
    printf("bin_len: %zu\n", bin_len);
    
    if (ret == 0) {
        printf("Seed (32 bytes): ");
        for (int i = 0; i < 32; i++) printf("%02x", temp[i]);
        printf("\n");
        
        printf("Seed (16 bytes): ");
        for (int i = 0; i < 16; i++) printf("%02x", temp[i]);
        printf("\n");
    }
    
    return 0;
}
