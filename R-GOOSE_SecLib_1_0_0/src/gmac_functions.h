/*
	File declaring gmac functions pointed in IEC 62351-6:2020 	
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include <assert.h>
#include <limits.h>
#include <errno.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#define ASSERT(x) assert(x)

int
gmac_AES128_64(uint8_t* data, uint8_t* key, uint8_t* iv ,size_t data_size, size_t iv_size, void** dest);

int
gmac_AES128_128(uint8_t* data, uint8_t* key, uint8_t* iv ,size_t data_size, size_t iv_size, void** dest);

int
gmac_AES256_64(uint8_t* data, uint8_t* key, uint8_t* iv ,size_t data_size, size_t iv_size, void** dest);

int
gmac_AES256_128(uint8_t* data, uint8_t* key, uint8_t* iv ,size_t data_size, size_t iv_size, void** dest);