
#include "hmac_functions.h"
#include "gmac_functions.h"
#include "aes_crypto.h"

#include "aux_funcs.h"


// Analisar de mudar 1 -> 0x01 tem impacto na performance
// MAC Tag Algorithms Defined Values
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


// Encryption Algorithms Defined Values
#define ENC_NONE			0
#define AES_128_GCM			1
#define AES_256_GCM			2


// R-GOOSE message field indexes
#define INDEX_SPDU_LENGTH			6
#define INDEX_SPDU_NUMBER			10
#define INDEX_VERSION_NUMBER		14

#define INDEX_SECURITY_INFO			16

#define INDEX_TIMECURKEY			16
#define INDEX_TIMENEXTKEY			20
#define INDEX_ENCRYPTION_ALG		22
#define INDEX_MAC_ALG				23
#define INDEX_KEYID					24

#define INDEX_LENGTH				28

#define INDEX_PAYLOAD_TYPE			32
#define INDEX_SIMULATION			33
#define INDEX_APPID					34
#define INDEX_APDU_LENGTH			36		
#define INDEX_PAYLOAD				38		

// Mapping between defined MAC Tag Algorithms and MAC Tag sizes
extern const int MAC_SIZES[];

int r_gooseMessage_InsertHMAC(uint8_t* buffer, uint8_t* key, size_t key_size, int alg);
int r_gooseMessage_InsertGMAC(uint8_t* buffer, uint8_t* key, size_t key_size, int alg);
int r_gooseMessage_ValidateHMAC(uint8_t* buffer, uint8_t* key, size_t key_size);
int r_gooseMessage_ValidateGMAC(uint8_t* buffer, uint8_t* key, size_t key_size);

int r_gooseMessage_Encrypt(uint8_t* buffer, uint8_t* key, int alg, uint32_t timeOfCurrentKey, uint16_t timeToNextKey, uint32_t key_id, uint8_t* iv, int iv_size);
int r_gooseMessage_Decrypt(uint8_t* buffer, uint8_t* key, uint8_t* iv, int iv_size);
void r_goose_dissect(uint8_t* buffer);