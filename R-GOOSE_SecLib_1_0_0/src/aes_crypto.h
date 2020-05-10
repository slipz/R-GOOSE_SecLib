#include <stdio.h>
#include <string.h>

#include "aux.h"

//openssl headers
#include <openssl/evp.h>
#include <openssl/bio.h>

int aes_256_gcm_encrypt(uint8_t* data, uint8_t* key, uint8_t* iv, int data_size, int iv_size, void** dest);
int aes_128_gcm_encrypt(uint8_t* data, uint8_t* key, uint8_t* iv, int data_size, int iv_size, void** dest);
int aes_256_gcm_decrypt(uint8_t* data, uint8_t* key, uint8_t* iv, int data_size, int iv_size, void** dest);
int aes_128_gcm_decrypt(uint8_t* data, uint8_t* key, uint8_t* iv, int data_size, int iv_size, void** dest);

uint8_t* hexStringToBytes(char hex[], size_t len);