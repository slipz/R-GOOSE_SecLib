/*
    File defining gmac functions pointed in IEC 62351-6:2020 
    
    gmac_XYZ functions receive pointer to original data
*/

#include "gmac_functions.h"


int
gmac_AES128_64(uint8_t* data, uint8_t* key, uint8_t* iv ,size_t data_size, size_t iv_size, uint8_t** dest){

	int rc = 0, unused;

    uint8_t* tmp = (uint8_t*)calloc(16, sizeof(uint8_t));
   
    if(*dest == NULL){
    	*dest = (uint8_t*)malloc(sizeof(uint8_t)*8);
    }

    EVP_CIPHER_CTX *ctx = NULL;
   
    ctx = EVP_CIPHER_CTX_new();
    ASSERT(ctx != NULL);
    if(ctx == NULL) {
        return 1;
    }
    
    rc = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    ASSERT(rc == 1);
    if(rc != 1) {
        return 1;
    }
   
    rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_size, NULL);
    ASSERT(rc == 1);
    if(rc != 1) {
        return 1;
    }
   
    rc = EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    ASSERT(rc == 1);
    if(rc != 1) {
        return 1;
    }
   
    rc = EVP_EncryptUpdate(ctx, NULL, &unused, data, data_size);
    ASSERT(rc == 1);
    if(rc != 1) {
        return 1;
    }
   
    rc = EVP_EncryptFinal_ex(ctx, NULL, &unused);
    ASSERT(rc == 1);
    if(rc != 1) {
        return 1;
    }
   
    rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tmp);
    ASSERT(rc == 1);
    if(rc != 1) {
        return 1;
    }
      
    if(ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }

    memcpy(*dest, tmp, 8);
    
    return 0;
}

int
gmac_AES128_128(uint8_t* data, uint8_t* key, uint8_t* iv ,size_t data_size, size_t iv_size, uint8_t** dest){

    int rc = 0, unused;
   
    if(*dest == NULL){
        *dest = (uint8_t*)malloc(sizeof(uint8_t)*16);
    }

    EVP_CIPHER_CTX *ctx = NULL;
   
    ctx = EVP_CIPHER_CTX_new();
    ASSERT(ctx != NULL);
    if(ctx == NULL) {
        return 1;
    }
    
    rc = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    ASSERT(rc == 1);
    if(rc != 1) {
        return 1;
    }
   
    rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_size, NULL);
    ASSERT(rc == 1);
    if(rc != 1) {
        return 1;
    }
   
    rc = EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    ASSERT(rc == 1);
    if(rc != 1) {
        return 1;
    }
   
    rc = EVP_EncryptUpdate(ctx, NULL, &unused, data, data_size);
    ASSERT(rc == 1);
    if(rc != 1) {
        return 1;
    }
   
    rc = EVP_EncryptFinal_ex(ctx, NULL, &unused);
    ASSERT(rc == 1);
    if(rc != 1) {
        return 1;
    }
   
    rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, *dest);
    ASSERT(rc == 1);
    if(rc != 1) {
        return 1;
    }
      
    if(ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }


    return 0;
}

int
gmac_AES256_64(uint8_t* data, uint8_t* key, uint8_t* iv ,size_t data_size, size_t iv_size, uint8_t** dest){

    /* Note: Key should be 256bits long */

    int rc = 0, unused;

    uint8_t* tmp = (uint8_t*)calloc(16, sizeof(uint8_t));
   
    if(*dest == NULL){
        *dest = (uint8_t*)malloc(sizeof(uint8_t)*8);
    }

    EVP_CIPHER_CTX *ctx = NULL;
   
    ctx = EVP_CIPHER_CTX_new();
    ASSERT(ctx != NULL);
    if(ctx == NULL) {
        return 1;
    }
    
    rc = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    ASSERT(rc == 1);
    if(rc != 1) {
        return 1;
    }
   
    rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_size, NULL);
    ASSERT(rc == 1);
    if(rc != 1) {
        return 1;
    }
   
    rc = EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    ASSERT(rc == 1);
    if(rc != 1) {
        return 1;
    }
   
    rc = EVP_EncryptUpdate(ctx, NULL, &unused, data, data_size);
    ASSERT(rc == 1);
    if(rc != 1) {
        return 1;
    }
   
    rc = EVP_EncryptFinal_ex(ctx, NULL, &unused);
    ASSERT(rc == 1);
    if(rc != 1) {
        return 1;
    }
   
    rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tmp);
    ASSERT(rc == 1);
    if(rc != 1) {
        return 1;
    }
      
    if(ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }

    memcpy(*dest, tmp, 8);
    
    return 0;
}

int
gmac_AES256_128(uint8_t* data, uint8_t* key, uint8_t* iv ,size_t data_size, size_t iv_size, uint8_t** dest){

    /* Note: Key should be 256bits long */

    int rc = 0, unused;
   
    if(*dest == NULL){
        *dest = (uint8_t*)malloc(sizeof(uint8_t)*16);
    }

    EVP_CIPHER_CTX *ctx = NULL;
   
    ctx = EVP_CIPHER_CTX_new();
    ASSERT(ctx != NULL);
    if(ctx == NULL) {
        return 1;
    }
    
    rc = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    ASSERT(rc == 1);
    if(rc != 1) {
        return 1;
    }
   
    rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_size, NULL);
    ASSERT(rc == 1);
    if(rc != 1) {
        return 1;
    }
   
    rc = EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    ASSERT(rc == 1);
    if(rc != 1) {
        return 1;
    }
   
    rc = EVP_EncryptUpdate(ctx, NULL, &unused, data, data_size);
    ASSERT(rc == 1);
    if(rc != 1) {
        return 1;
    }
   
    rc = EVP_EncryptFinal_ex(ctx, NULL, &unused);
    ASSERT(rc == 1);
    if(rc != 1) {
        return 1;
    }
   
    rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, *dest);
    ASSERT(rc == 1);
    if(rc != 1) {
        return 1;
    }
      
    if(ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }

    return 0;
}
