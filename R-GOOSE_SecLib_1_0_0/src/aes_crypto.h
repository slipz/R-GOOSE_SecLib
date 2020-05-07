#include <stdio.h>
#include <string.h>

//openssl headers
#include <openssl/evp.h>
#include <openssl/bio.h>

int aes_256_gcm(uint8_t* data, uint8_t* key, uint8_t* iv, int data_size, int iv_size);