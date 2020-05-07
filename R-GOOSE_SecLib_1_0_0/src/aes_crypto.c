#include "aes_crypto.h"


void handleErrors(){
	printf("error\n");
}


int aes_256_gcm(uint8_t* data, uint8_t* key, uint8_t* iv, int data_size, int iv_size){

	EVP_CIPHER_CTX *ctx;

	int len;

	int ciphertext_len;

	int block_size = EVP_CIPHER_block_size(EVP_aes_256_gcm());

	uint8_t* ciphertext = (uint8_t*)malloc(sizeof(char)*(data_size+block_size));

	/* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_size, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, data, data_size))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    printf("Calculated enc:\n  ");
    for(int i = 0; i < ciphertext_len; i++){
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;

}

void aes_128_gcm(uint8_t* data, uint8_t* key, uint8_t* iv, int data_size, int iv_size){

}