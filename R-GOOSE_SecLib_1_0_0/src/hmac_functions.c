/*
	File defining hmac functions pointed in IEC 62351-6:2020 
	
	hmac_XYZ functions receive pointer to original data

	Function special behaviors:
		IF(KEY OR DATA == NULL):
			KEY OR DATA = seq('0x00');

		IF(KEY AND DATA == NULL):
			DIGEST = 000..000 -> Key and Data are both seq('0x00')

		IF(KEY OR/AND DATA NOT INITIALIZED):
			UNDEFINED BEHAVIOR -> Data must be provided on both inputs

		IF(DEST NOT INITIALIZED):
			ALL OK -> Functions allocate dynamic memory to DEST
		
	NOTES:
		-- DEST is a pointer to where the MAC Tag should be written. 
		To hmac_xyz functions, should be passed memory address of such pointer (&dest)
		
*/

#include "hmac_functions.h"

void
hmac_SHA256_80(uint8_t* data, uint8_t* key, size_t data_size, size_t key_size, uint8_t** dest){
	unsigned char* tmp = (unsigned char*)calloc(32, sizeof(char));
	
	if(*dest == NULL){
		// Malloc and prepare
		*dest = (uint8_t*)malloc(sizeof(char)*10);
	}

	HMAC(EVP_sha256(), key, key_size, data, data_size, tmp, NULL);

	memcpy(*dest, tmp, 10);

	free(tmp);
}


void
hmac_SHA256_128(uint8_t* data, uint8_t* key, size_t data_size, size_t key_size, uint8_t** dest){
	unsigned char* tmp = (unsigned char*)calloc(32, sizeof(char));
	
	if(*dest == NULL){
		// Malloc and prepare
		*dest = (uint8_t*)malloc(sizeof(char)*16);
	}

	HMAC(EVP_sha256(), key, key_size, data, data_size, tmp, NULL);

	memcpy(*dest, tmp, 16);

	free(tmp);
}


void
hmac_SHA256_256(uint8_t* data, uint8_t* key, size_t data_size, size_t key_size, uint8_t** dest){
	unsigned char* tmp = (unsigned char*)calloc(32, sizeof(char));
	
	if(*dest == NULL){
		// Malloc and prepare
		*dest = (uint8_t*)malloc(sizeof(char)*32);
	}

	HMAC(EVP_sha256(), key, key_size, data, data_size, tmp, NULL);

	memcpy(*dest, tmp, 32);

	free(tmp);
}


// Custom/Off-Standard Hash functions

// BLAKE2 variants
void
hmac_BLAKE2b_80(uint8_t* data, uint8_t* key, size_t data_size, size_t key_size, uint8_t** dest){
	unsigned char* tmp = (unsigned char*)calloc(64, sizeof(char));
	
	if(*dest == NULL){
		// Malloc and prepare
		*dest = (uint8_t*)malloc(sizeof(char)*10);
	}

	HMAC(EVP_blake2b512(), key, key_size, data, data_size, tmp, NULL);

	memcpy(*dest, tmp, 10);

	free(tmp);
}

void
hmac_BLAKE2s_80(uint8_t* data, uint8_t* key, size_t data_size, size_t key_size, uint8_t** dest){
	unsigned char* tmp = (unsigned char*)calloc(32, sizeof(char));
	
	if(*dest == NULL){
		// Malloc and prepare
		*dest = (uint8_t*)malloc(sizeof(char)*10);
	}

	HMAC(EVP_blake2s256(), key, key_size, data, data_size, tmp, NULL);

	memcpy(*dest, tmp, 10);

	free(tmp);
}


// MD5 Variants

// Other Hashing Algorithms