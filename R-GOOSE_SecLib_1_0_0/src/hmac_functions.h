/*
	File declaring hmac functions pointed in IEC 62351-6:2020 	
*/

#include <stdio.h>
#include <string.h>

//openssl headers
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/engine.h>


void 
hmac_SHA256_80(uint8_t* data, uint8_t* key, size_t data_size, size_t key_size, void** dest);

void
hmac_SHA256_128(uint8_t* data, uint8_t* key, size_t data_size, size_t key_size, void** dest);

void
hmac_SHA256_256(uint8_t* data, uint8_t* key, size_t data_size, size_t key_size, void** dest);

void
hmac_BLAKE2b_80(uint8_t* data, uint8_t* key, size_t data_size, size_t key_size, void** dest);

void
hmac_BLAKE2s_80(uint8_t* data, uint8_t* key, size_t data_size, size_t key_size, void** dest);
