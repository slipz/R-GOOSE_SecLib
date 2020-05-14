/*
	File declaring gmac functions pointed in IEC 62351-6:2020 	
*/

/**
 * @file gmac_functions.h
 * @author Eduardo Andrade
 * @date Mar 2020
 * @brief File containing OpenSSL and Standard includes, as well as the declarations of all GMAC-Tag generation functions
 *
 * This header file declares the several funtions implemented on the file gmac_functions.c.
 * Also, this file includes all of the other files and libraries used on the GMAC context (OpenSSL, C Standard Libraries).
 * @note This library was tested using OpenSSL 1.1.1 library. 
 * @see https://www.openssl.org/docs/man1.1.1/
 *
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


/**
 * @brief Function that generates an gmac_AES128_64 Tag
 *
 * This function generates an GMAC Tag of 64bits (8bytes) long, using AES128 as
 * its base cryptographic algorithm. It receives @p data, @p key, @p iv and @p dest as pointers,
 * and both data and IV sizes as <tt>size_t</tt>. The functions calculates the MAC
 * tag and stores it on @p dest. It uses OpenSSL Library to implement such algorithms.
 * To provide only authentication and data integrity, data is passed to OpenSSL as 
 * AAD(Additional Authenticated Data), leaving the PT(Plain Text) empty.
 *
 * Below is and example of usage:
 * @code
 *
 * uint8_t* dest = NULL;
 * uint8_t* key = (uint8_t*)malloc(sizeof(uint8_t)*16);
 * set_key(key); 											// pseudo-function that populates key 
 * uint8_t* data = (uint8_t*)malloc(sizeof(uint8_t)*16);
 * set_data(data); 									 	// pseudo-function that populates data 
 * uint8_t* iv = (uint8_t*)malloc(sizeof(uint8_t)*12);
 * set_iv(iv);												// pseudo-function that populates IV 
 * 
 * int data_size = 16, iv_size = 12;
 *
 * gmac_AES128_64(data, key, iv, data_size, iv_size, &dest);
 *
 * print_array_hex(dest);									// pseudo-function that prints dest in hex format
 * @endcode
 *
 * @param data Pointer (<tt>uint8_t*</tt>) containg the data that will be used to generate the GMAC Tag
 * @param key Pointer (<tt>uint8_t*</tt>) containg the key that will be used to generate the GMAC Tag
 * @param iv Pointer (<tt>uint8_t*</tt>) containg the initialization vector that will be used to generate the GMAC Tag
 * @param data_size Variable (<tt>size_t</tt>) that hold the size in bytes of data. 
 * @param iv_size Variable (<tt>size_t</tt>) that hold the size in bytes of iv. 
 * @param dest key Pointer (<tt>uint8_t**</tt>) pointing to the destiny memory address where GMAC tag should be stored
 *
 * @return The function returns 0 if everything went as expected (no errors) or 1 if an error occured.
 *
 * @warning @p dest should be create as a data type capable of storing the GMAC Tag (ex. <tt>uint8_t*</tt>). However, it's 
 * memory address must be passed to the function and not the pointer itself (<b><tt>&dest</tt></b>)
 * @note It is not required to manually allocate/reserve memory for @p dest, this functions allocates the necessary memory
 * to store the GMAC tag. 
 */
int
gmac_AES128_64(uint8_t* data, uint8_t* key, uint8_t* iv ,size_t data_size, size_t iv_size, uint8_t** dest);

/**
 * @brief Function that generates an gmac_AES128_128 Tag
 *
 * This function generates an GMAC Tag of 128bits (16bytes) long, using AES128 as
 * its base cryptographic algorithm. It receives @p data, @p key, @p iv and @p dest as pointers,
 * and both data and IV sizes as <tt>size_t</tt>. The functions calculates the MAC
 * tag and stores it on @p dest. It uses OpenSSL Library to implement such algorithms.
 * To provide only authentication and data integrity, data is passed to OpenSSL as 
 * AAD(Additional Authenticated Data), leaving the PT(Plain Text) empty.
 *
 * Below is and example of usage:
 * @code
 *
 * uint8_t* dest = NULL;
 * uint8_t* key = (uint8_t*)malloc(sizeof(uint8_t)*16);
 * set_key(key); 											// pseudo-function that populates key 
 * uint8_t* data = (uint8_t*)malloc(sizeof(uint8_t)*16);
 * set_data(data); 									 	// pseudo-function that populates data 
 * uint8_t* iv = (uint8_t*)malloc(sizeof(uint8_t)*12);
 * set_iv(iv);												// pseudo-function that populates IV 
 * 
 * int data_size = 16, iv_size = 12;
 *
 * gmac_AES128_128(data, key, iv, data_size, iv_size, &dest);
 *
 * print_array_hex(dest);									// pseudo-function that prints dest in hex format
 * @endcode
 *
 * @param data Pointer (<tt>uint8_t*</tt>) containg the data that will be used to generate the GMAC Tag
 * @param key Pointer (<tt>uint8_t*</tt>) containg the key that will be used to generate the GMAC Tag
 * @param iv Pointer (<tt>uint8_t*</tt>) containg the initialization vector that will be used to generate the GMAC Tag
 * @param data_size Variable (<tt>size_t</tt>) that hold the size in bytes of data. 
 * @param iv_size Variable (<tt>size_t</tt>) that hold the size in bytes of iv. 
 * @param dest key Pointer (<tt>uint8_t**</tt>) pointing to the destiny memory address where GMAC tag should be stored
 *
 * @return The function returns 0 if everything went as expected (no errors) or 1 if an error occured.
 *
 * @warning @p dest should be create as a data type capable of storing the GMAC Tag (ex. <tt>uint8_t*</tt>). However, it's 
 * memory address must be passed to the function and not the pointer itself (<b><tt>&dest</tt></b>)
 * @note It is not required to manually allocate/reserve memory for @p dest, this functions allocates the necessary memory
 * to store the GMAC tag. 
 */
int
gmac_AES128_128(uint8_t* data, uint8_t* key, uint8_t* iv ,size_t data_size, size_t iv_size, uint8_t** dest);

/**
 * @brief Function that generates an gmac_AES256_64 Tag
 *
 * This function generates an GMAC Tag of 64bits (8bytes) long, using AES256 as
 * its base cryptographic algorithm. It receives @p data, @p key, @p iv and @p dest as pointers,
 * and both data and IV sizes as <tt>size_t</tt>. The functions calculates the MAC
 * tag and stores it on @p dest. It uses OpenSSL Library to implement such algorithms.
 * To provide only authentication and data integrity, data is passed to OpenSSL as 
 * AAD(Additional Authenticated Data), leaving the PT(Plain Text) empty.
 *
 * Below is and example of usage:
 * @code
 *
 * uint8_t* dest = NULL;
 * uint8_t* key = (uint8_t*)malloc(sizeof(uint8_t)*32);
 * set_key(key); 											// pseudo-function that populates key 
 * uint8_t* data = (uint8_t*)malloc(sizeof(uint8_t)*16);
 * set_data(data); 									 	// pseudo-function that populates data 
 * uint8_t* iv = (uint8_t*)malloc(sizeof(uint8_t)*12);
 * set_iv(iv);												// pseudo-function that populates IV 
 * 
 * int data_size = 16, iv_size = 12;
 *
 * gmac_AES256_64(data, key, iv, data_size, iv_size, &dest);
 *
 * print_array_hex(dest);									// pseudo-function that prints dest in hex format
 * @endcode
 *
 * @param data Pointer (<tt>uint8_t*</tt>) containg the data that will be used to generate the GMAC Tag
 * @param key Pointer (<tt>uint8_t*</tt>) containg the key that will be used to generate the GMAC Tag
 * @param iv Pointer (<tt>uint8_t*</tt>) containg the initialization vector that will be used to generate the GMAC Tag
 * @param data_size Variable (<tt>size_t</tt>) that hold the size in bytes of data. 
 * @param iv_size Variable (<tt>size_t</tt>) that hold the size in bytes of iv. 
 * @param dest key Pointer (<tt>uint8_t**</tt>) pointing to the destiny memory address where GMAC tag should be stored
 *
 * @return The function returns 0 if everything went as expected (no errors) or 1 if an error occured.
 *
 * @warning @p dest should be create as a data type capable of storing the GMAC Tag (ex. <tt>uint8_t*</tt>). However, it's 
 * memory address must be passed to the function and not the pointer itself (<b><tt>&dest</tt></b>)
 * @note It is not required to manually allocate/reserve memory for @p dest, this functions allocates the necessary memory
 * to store the GMAC tag. 
 */
int
gmac_AES256_64(uint8_t* data, uint8_t* key, uint8_t* iv ,size_t data_size, size_t iv_size, uint8_t** dest);

/**
 * @brief Function that generates an gmac_AES256_128 Tag
 *
 * This function generates an GMAC Tag of 128bits (16bytes) long, using AES256 as
 * its base cryptographic algorithm. It receives @p data, @p key, @p iv and @p dest as pointers,
 * and both data and IV sizes as <tt>size_t</tt>. The functions calculates the MAC
 * tag and stores it on @p dest. It uses OpenSSL Library to implement such algorithms.
 * To provide only authentication and data integrity, data is passed to OpenSSL as 
 * AAD(Additional Authenticated Data), leaving the PT(Plain Text) empty.
 *
 * Below is and example of usage:
 * @code
 *
 * uint8_t* dest = NULL;
 * uint8_t* key = (uint8_t*)malloc(sizeof(uint8_t)*32);
 * set_key(key); 											// pseudo-function that populates key 
 * uint8_t* data = (uint8_t*)malloc(sizeof(uint8_t)*16);
 * set_data(data); 									 	// pseudo-function that populates data 
 * uint8_t* iv = (uint8_t*)malloc(sizeof(uint8_t)*12);
 * set_iv(iv);												// pseudo-function that populates IV 
 * 
 * int data_size = 16, iv_size = 12;
 *
 * gmac_AES128_64(data, key, iv, data_size, iv_size, &dest);
 *
 * print_array_hex(dest);									// pseudo-function that prints dest in hex format
 * @endcode
 *
 * @param data Pointer (<tt>uint8_t*</tt>) containg the data that will be used to generate the GMAC Tag
 * @param key Pointer (<tt>uint8_t*</tt>) containg the key that will be used to generate the GMAC Tag
 * @param iv Pointer (<tt>uint8_t*</tt>) containg the initialization vector that will be used to generate the GMAC Tag
 * @param data_size Variable (<tt>size_t</tt>) that hold the size in bytes of data. 
 * @param iv_size Variable (<tt>size_t</tt>) that hold the size in bytes of iv. 
 * @param dest key Pointer (<tt>uint8_t**</tt>) pointing to the destiny memory address where GMAC tag should be stored
 *
 * @return The function returns 0 if everything went as expected (no errors) or 1 if an error occured.
 *
 * @warning @p dest should be create as a data type capable of storing the GMAC Tag (ex. <tt>uint8_t*</tt>). However, it's 
 * memory address must be passed to the function and not the pointer itself (<b><tt>&dest</tt></b>)
 * @note It is not required to manually allocate/reserve memory for @p dest, this functions allocates the necessary memory
 * to store the GMAC tag. 
 */
int
gmac_AES256_128(uint8_t* data, uint8_t* key, uint8_t* iv ,size_t data_size, size_t iv_size, uint8_t** dest);