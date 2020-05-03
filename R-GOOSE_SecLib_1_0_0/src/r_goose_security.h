
#include "hmac_functions.h"
#include "gmac_functions.h"

// Analisar de mudar 1 -> 0x01 tem impacto na performance

#define HMAC_SHA256_80 		0
#define HMAC_SHA256_128 	1
#define HMAC_SHA256_256 	2

#define HMAC_BLAKE2B_80 	3
#define HMAC_BLAKE2S_80 	4

#define GMAC_AES128_64 		5
#define GMAC_AES128_128 	6
#define GMAC_AES256_64 		7
#define GMAC_AES256_128 	8

extern const int MAC_SIZES[];

void r_gooseMessage_InsertHMAC(uint8_t* buffer, uint8_t* key, size_t key_size, int alg);
void r_gooseMessage_InsertGMAC(uint8_t* buffer, uint8_t* key, size_t key_size, int alg);