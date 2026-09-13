#include <stdio.h>
#include <string.h>
#include <sodium.h>

int main() {
    const char* seed_hex = "e82d7d3fb458c60663578e3de933c2a8a157395e4838596605f2932e563c781e";
    printf("Seed hex length: %zu\n", strlen(seed_hex));
    
    unsigned char seed[32];
    size_t bin_len;
    int ret = sodium_hex2bin(seed, 32, seed_hex, strlen(seed_hex), NULL, &bin_len, NULL);
    printf("sodium_hex2bin result: %d\n", ret);
    printf("bin_len: %zu\n", bin_len);
    
    if (ret == 0) {
        printf("Seed bytes: ");
        for (int i = 0; i < 32; i++) {
            printf("%02x", seed[i]);
        }
        printf("\n");
    }
    
    return 0;
}
