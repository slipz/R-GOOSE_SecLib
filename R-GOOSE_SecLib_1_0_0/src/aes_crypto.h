/**
 * @file aes_crypto.h
 * @author Eduardo Andrade
 * @date Mar 2020
 * @brief File containing OpenSSL and Standard includes, as well as the declarations of all AES Algorithm functions
 *
 * This header file declares the several funtions implemented on the file aes_crypto.c.
 * Also, this file includes all of the other files and libraries used on the AES context (OpenSSL, C Standard Libraries).
 * @note This library was tested using OpenSSL 1.1.1 library. 
 * @see https://www.openssl.org/docs/man1.1.1/man7/evp.html
 */

#include <stdio.h>
#include <string.h>

#include "aux_funcs.h"

//openssl headers
#include <openssl/evp.h>
#include <openssl/bio.h>


/**
 * @brief Function that encrypts feeded data using AES-GCM with 256 bits long key
 *
 * This functions encrypts feeded data using AES-GCM-256, producing an output with the same 
 * length as the original. It receives @p data, @p key and @p dest as pointers, and @p iv,
 * @p data_size and @p iv_size as integers. The function calculates the encrypted data
 * and stores it on @p dest. It uses OpenSSL Library to implement such algorithm.
 *
 * Below is an example of usage:
 * @code
 *
 * uint8_t* dest = NULL;
 * uint8_t* key = (uint8_t*)malloc(sizeof(uint8_t)*32);
 * set_key(key); 											// pseudo-function that populates key 
 * uint8_t* data = (uint8_t*)malloc(sizeof(uint8_t)*8);
 * set_data(data); 										// pseudo-function that populates data 
 * uint8_t* iv = (uint8_t*)malloc(sizeof(uint8_t)*20);	
 * set_data(iv);											// pseudo-function that populates iv
 *
 * int data_size = 8, key_size = 32, iv_size = 20;
 *
 * int len = aes_256_gcm_encrypt(data, key, iv, data_size, iv_size, &dest);
 *
 * print_array_hex(dest,len);								// pseudo-function that prints dest in hex format
 * @endcode
 * @param data Pointer (<tt>uint8_t*</tt>) containg the data that will be encrypted
 * @param key Pointer (<tt>uint8_t*</tt>) containg the key that will be used encrypt data
 * @param iv Pointer (<tt>uint8_t*</tt>) containg the Initialization Vector to be used by AES
 * @param data_size Variable (<tt>size_t</tt>) that hold the size in bytes of data. 
 * @param iv_size Variable (<tt>size_t</tt>) that hold the size in bytes of IV. 
 * @param dest key Pointer (<tt>uint8_t**</tt>) pointing to the destiny memory address where encrypted data should be stored
 * @return An integer containing the length of the encrypted data
 * @warning @p dest should be create as a data type capable of storing the encrypted data (ex. <tt>uint8_t*</tt>). However, it's 
 * memory address must be passed to the function and not the pointer itself (<b><tt>&dest</tt></b>)
 * @note It is not required to manually allocate/reserve memory for @p dest, this functions allocates the necessary memory
 * to store the encrypted data. 
 */
int aes_256_gcm_encrypt(uint8_t* data, uint8_t* key, uint8_t* iv, int data_size, int iv_size, uint8_t** dest);


/**
 * @brief Function that encrypts feeded data using AES-GCM with 128 bits long key
 *
 * This functions encrypts feeded data using AES-GCM-128, producing an output with the same 
 * length as the original. It receives @p data, @p key and @p dest as pointers, and @p iv,
 * @p data_size and @p iv_size as integers. The function calculates the encrypted data
 * and stores it on @p dest. It uses OpenSSL Library to implement such algorithm.
 *
 * Below is an example of usage:
 * @code
 *
 * uint8_t* dest = NULL;
 * uint8_t* key = (uint8_t*)malloc(sizeof(uint8_t)*16);
 * set_key(key); 											// pseudo-function that populates key 
 * uint8_t* data = (uint8_t*)malloc(sizeof(uint8_t)*8);
 * set_data(data); 										// pseudo-function that populates data 
 * uint8_t* iv = (uint8_t*)malloc(sizeof(uint8_t)*20);	
 * set_data(iv);											// pseudo-function that populates iv
 *
 * int data_size = 8, key_size = 16, iv_size = 20;
 *
 * int len = aes_128_gcm_encrypt(data, key, iv, data_size, iv_size, &dest);
 *
 * print_array_hex(dest,len);								// pseudo-function that prints dest in hex format
 * @endcode
 * @param data Pointer (<tt>uint8_t*</tt>) containg the data that will be encrypted
 * @param key Pointer (<tt>uint8_t*</tt>) containg the key that will be used encrypt data
 * @param iv Pointer (<tt>uint8_t*</tt>) containg the Initialization Vector to be used by AES
 * @param data_size Variable (<tt>size_t</tt>) that hold the size in bytes of data. 
 * @param iv_size Variable (<tt>size_t</tt>) that hold the size in bytes of IV. 
 * @param dest key Pointer (<tt>uint8_t**</tt>) pointing to the destiny memory address where encrypted data should be stored
 * @return An integer containing the length of the encrypted data
 * @warning @p dest should be create as a data type capable of storing the encrypted data (ex. <tt>uint8_t*</tt>). However, it's 
 * memory address must be passed to the function and not the pointer itself (<b><tt>&dest</tt></b>)
 * @note It is not required to manually allocate/reserve memory for @p dest, this functions allocates the necessary memory
 * to store the encrypted data. 
 */
int aes_128_gcm_encrypt(uint8_t* data, uint8_t* key, uint8_t* iv, int data_size, int iv_size, uint8_t** dest);


/**
 * @brief Function that decrypts feeded data using AES-GCM with 256 bits long key
 *
 * This functions decrypts feeded data using AES-GCM-256, producing an output with the same 
 * length as the encrypted (original). It receives @p data, @p key and @p dest as pointers, and @p iv,
 * @p data_size and @p iv_size as integers. The function calculates the decrypted data
 * and stores it on @p dest. It uses OpenSSL Library to implement such algorithm.
 *
 * Below is an example of usage:
 * @code
 *
 * uint8_t* dest = NULL;
 * uint8_t* key = (uint8_t*)malloc(sizeof(uint8_t)*32);
 * set_key(key); 											// pseudo-function that populates key 
 * uint8_t* data = (uint8_t*)malloc(sizeof(uint8_t)*8);
 * set_data(data); 										// pseudo-function that populates data 
 * uint8_t* iv = (uint8_t*)malloc(sizeof(uint8_t)*20);	
 * set_data(iv);											// pseudo-function that populates iv
 *
 * int data_size = 8, key_size = 32, iv_size = 20;
 *
 * int len = aes_256_gcm_decrypt(data, key, iv, data_size, iv_size, &dest);
 *
 * print_array_hex(dest,len);								// pseudo-function that prints dest in hex format
 * @endcode
 * @param data Pointer (<tt>uint8_t*</tt>) containg the data that will be decrypted
 * @param key Pointer (<tt>uint8_t*</tt>) containg the key that will be used decrypt data
 * @param iv Pointer (<tt>uint8_t*</tt>) containg the Initialization Vector to be used by AES
 * @param data_size Variable (<tt>size_t</tt>) that hold the size in bytes of data. 
 * @param iv_size Variable (<tt>size_t</tt>) that hold the size in bytes of IV. 
 * @param dest key Pointer (<tt>uint8_t**</tt>) pointing to the destiny memory address where decrypted data should be stored
 * @return An integer containing the length of the decrypted data
 * @warning @p dest should be create as a data type capable of storing the decrypted data (ex. <tt>uint8_t*</tt>). However, it's 
 * memory address must be passed to the function and not the pointer itself (<b><tt>&dest</tt></b>)
 * @note It is not required to manually allocate/reserve memory for @p dest, this functions allocates the necessary memory
 * to store the decrypted data. 
 */
int aes_256_gcm_decrypt(uint8_t* data, uint8_t* key, uint8_t* iv, int data_size, int iv_size, uint8_t** dest);


/**
 * @brief Function that decrypts feeded data using AES-GCM with 128 bits long key
 *
 * This functions decrypts feeded data using AES-GCM-128, producing an output with the same 
 * length as the encrypted (original). It receives @p data, @p key and @p dest as pointers, and @p iv,
 * @p data_size and @p iv_size as integers. The function calculates the decrypted data
 * and stores it on @p dest. It uses OpenSSL Library to implement such algorithm.
 *
 * Below is an example of usage:
 * @code
 *
 * uint8_t* dest = NULL;
 * uint8_t* key = (uint8_t*)malloc(sizeof(uint8_t)*16);
 * set_key(key); 											// pseudo-function that populates key 
 * uint8_t* data = (uint8_t*)malloc(sizeof(uint8_t)*8);
 * set_data(data); 										// pseudo-function that populates data 
 * uint8_t* iv = (uint8_t*)malloc(sizeof(uint8_t)*20);	
 * set_data(iv);											// pseudo-function that populates iv
 *
 * int data_size = 8, key_size = 16, iv_size = 20;
 *
 * int len = aes_128_gcm_decrypt(data, key, iv, data_size, iv_size, &dest);
 *
 * print_array_hex(dest,len);								// pseudo-function that prints dest in hex format
 * @endcode
 * @param data Pointer (<tt>uint8_t*</tt>) containg the data that will be decrypted
 * @param key Pointer (<tt>uint8_t*</tt>) containg the key that will be used decrypt data
 * @param iv Pointer (<tt>uint8_t*</tt>) containg the Initialization Vector to be used by AES
 * @param data_size Variable (<tt>size_t</tt>) that hold the size in bytes of data. 
 * @param iv_size Variable (<tt>size_t</tt>) that hold the size in bytes of IV. 
 * @param dest key Pointer (<tt>uint8_t**</tt>) pointing to the destiny memory address where decrypted data should be stored
 * @return An integer containing the length of the decrypted data
 * @warning @p dest should be create as a data type capable of storing the decrypted data (ex. <tt>uint8_t*</tt>). However, it's 
 * memory address must be passed to the function and not the pointer itself (<b><tt>&dest</tt></b>)
 * @note It is not required to manually allocate/reserve memory for @p dest, this functions allocates the necessary memory
 * to store the decrypted data. 
 */
int aes_128_gcm_decrypt(uint8_t* data, uint8_t* key, uint8_t* iv, int data_size, int iv_size, uint8_t** dest);


/**
 * @brief Auxiliary function that converts an hexadecimal string to byte array
 *
 * This function converts an hexadecimal string into a byte array, in <tt>uint8_t*</tt> type. 
 * It receives the hexadecimal string by @p hex and its length on @p len. A reference to
 * the resulting byte array is returned. 
 *
 * Below is an example of usage:
 * @code
 *
 * char keyHex[] = "219bcef0cd0f89a5e1297b99d956150f3128459f65312fdd71618f1177393e3f";
 * uint8_t* key = hexStringToBytes(keyHex, 64);
 *
 * @endcode
 * @param hex Array (<tt>char[]</tt>) contaning the hexadecimal string to be converted
 * @param len Variable (<tt>size_t</tt>) containg the length of the hexadecimal string (without terminator)
 * @return A pointer to the resulting byte array
 * @warning @p dest should be create as a data type capable of storing the decrypted data (ex. <tt>uint8_t*</tt>). However, it's 
 */
uint8_t* hexStringToBytes(char hex[], size_t len);