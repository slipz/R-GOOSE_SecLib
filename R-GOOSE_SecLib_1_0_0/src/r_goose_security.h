
#include "hmac_functions.h"
#include "gmac_functions.h"

#include "aux.h"


// Analisar de mudar 1 -> 0x01 tem impacto na performance
#define MAC_NONE			0
#define HMAC_SHA256_80 		1
#define HMAC_SHA256_128 	2
#define HMAC_SHA256_256 	3
#define GMAC_AES256_64 		4
#define GMAC_AES256_128 	5

#define HMAC_BLAKE2B_80 	6
#define HMAC_BLAKE2S_80 	7

#define GMAC_AES128_64 		8
#define GMAC_AES128_128 	9


// R-GOOSE message field indexes
#define INDEX_SPDU_LENGTH			6
#define INDEX_SECURITY_INFO			16
#define INDEX_ENCRYPTION_ALG		22
#define INDEX_MAC_ALG				23				



extern const int MAC_SIZES[];

int r_gooseMessage_InsertHMAC(uint8_t* buffer, uint8_t* key, size_t key_size, int alg);
void r_gooseMessage_InsertGMAC(uint8_t* buffer, uint8_t* key, size_t key_size, int alg);
int r_gooseMessage_ValidateHMAC(uint8_t* buffer, uint8_t* key, size_t key_size);
int r_gooseMessage_ValidateGMAC(uint8_t* buffer, uint8_t* key, size_t key_size);

int r_gooseMessage_Encrypt(uint8_t* buffer, uint8_t* key, int alg, uint32_t timeOfCurrentKey, uint16_t timeToNextKey, uint32_t key_id);


int decode_4bytesToInt(uint8_t* buffer, int index);
void encodeInt2Bytes(uint8_t* buffer, uint16_t value, int index);
void encodeInt4Bytes(uint8_t* buffer, uint32_t value, int index);
