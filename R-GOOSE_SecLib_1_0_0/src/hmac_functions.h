/*
	File declaring hmac functions pointed in IEC 62351-6:2020 	
*/

/**
 * @file hmac_functions.h
 * @author Eduardo Andrade
 * @date Mar 2020
 * @brief File containing OpenSSL and Standard includes, as well as the declarations of all HMAC-Tag generation functions
 *
 * This header file declares the several funtions implemented on the file hmac_functions.c.
 * Also, this file includes all of the other files and libraries used on the HMAC context (OpenSSL, C Standard Libraries).
 * @note This library was tested using OpenSSL 1.1.1 library. 
 * @see https://www.openssl.org/docs/man1.1.1/man3/HMAC.html
 * @see https://www.openssl.org/docs/man1.1.1/man7/evp.html
 */

#include <stdio.h>
#include <string.h>

//openssl headers
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

/**
 * @brief Function that generates an HMAC-SHA256-80 Tag
 *
 * This function generates an HMAC Tag of 80bits (10bytes) long, using SHA256 as
 * its base hashing algorithm. It receives @p data, @p key and @p dest as pointers,
 * and both data and key sizes as <tt>size_t</tt>. The functions calculates the MAC
 * tag and stores it on @p dest. It uses OpenSSL Library to implement such algorithms. 
 *
 * EXPECTED BEHAVIOR ?
 *
 * Below is and example of usage:
 * @code
 *
 * uint8_t* dest = NULL;
 * uint8_t* key = (uint8_t*)malloc(sizeof(uint8_t)*20);
 * set_key(key); 											// pseudo-function that populates key 
 * uint8_t* data = (uint8_t*)malloc(sizeof(uint8_t)*8);
 * set_data(data); 										// pseudo-function that populates data 
 * 
 * int data_size = 8, key_size = 20;
 *
 * hmac_SHA256_80(data, key, data_size, key_size, &dest);
 *
 * print_array_hex(dest);									// pseudo-function that prints dest in hex format
 * @endcode
 * @param data Pointer (<tt>uint8_t*</tt>) containg the data that will be used to generate the HMAC Tag
 * @param key Pointer (<tt>uint8_t*</tt>) containg the key that will be used to generate the HMAC Tag
 * @param data_size Variable (<tt>size_t</tt>) that hold the size in bytes of data. 
 * @param key_size Variable (<tt>size_t</tt>) that hold the size in bytes of key. 
 * @param dest key Pointer (<tt>void**</tt>) pointing to the destiny memory address where HMAC tag should be stored
 * @return The function doesn't return any value
 * @warning @p dest should be create as a data type capable of storing the HMAC Tag (ex. <tt>uint8_t*</tt>). However, it's 
 * memory address must be passed to the function and not the pointer itself (<b><tt>&dest</tt></b>)
 * @note It is not required to manually allocate/reserve memory for @p dest, this functions allocates the necessary memory
 * to store the HMAC tag. 
 */
void 
hmac_SHA256_80(uint8_t* data, uint8_t* key, size_t data_size, size_t key_size, void** dest);

/**
 * @brief Function that generates an HMAC-SHA256-128 Tag
 *
 * This function generates an HMAC Tag of 128bits (16bytes) long, using SHA256 as
 * its base hashing algorithm. It receives @p data, @p key and @p dest as pointers,
 * and both data and key sizes as <tt>size_t</tt>. The functions calculates the MAC
 * tag and stores it on @p dest. It uses OpenSSL Library to implement such algorithms.
 *
 * EXPECTED BEHAVIOR ?
 *
 * Below is and example of usage:
 * @code
 *
 * uint8_t* dest = NULL;
 * uint8_t* key = (uint8_t*)malloc(sizeof(uint8_t)*20);
 * set_key(key); 											// pseudo-function that populates key 
 * uint8_t* data = (uint8_t*)malloc(sizeof(uint8_t)*8);
 * set_data(data); 										// pseudo-function that populates data 
 * 
 * int data_size = 8, key_size = 20;
 *
 * hmac_SHA256_128(data, key, data_size, key_size, &dest);
 *
 * print_array_hex(dest);									// pseudo-function that prints dest in hex format
 * @endcode
 * @param data Pointer (<tt>uint8_t*</tt>) containg the data that will be used to generate the HMAC Tag
 * @param key Pointer (<tt>uint8_t*</tt>) containg the key that will be used to generate the HMAC Tag
 * @param data_size Variable (<tt>size_t</tt>) that hold the size in bytes of data. 
 * @param key_size Variable (<tt>size_t</tt>) that hold the size in bytes of key. 
 * @param dest key Pointer (<tt>void**</tt>) pointing to the destiny memory address where HMAC tag should be stored
 * @return The function doesn't return any value
 * @warning @p dest should be create as a data type capable of storing the HMAC Tag (ex. <tt>uint8_t*</tt>). However, it's 
 * memory address must be passed to the function and not the pointer itself (<b><tt>&dest</tt></b>)
 * @note It is not required to manually allocate/reserve memory for @p dest, this functions allocates the necessary memory
 * to store the HMAC tag. 
 */
hmac_SHA256_128(uint8_t* data, uint8_t* key, size_t data_size, size_t key_size, void** dest);

/**
 * @brief Function that generates an HMAC-SHA256-256 Tag
 * 
 * This function generates an HMAC Tag of 256bits (32bytes) long, using SHA256 as
 * its base hashing algorithm. It receives @p data, @p key and @p dest as pointers,
 * and both data and key sizes as <tt>size_t</tt>. The functions calculates the MAC
 * tag and stores it on @p dest. It uses OpenSSL Library to implement such algorithms.
 *
 * EXPECTED BEHAVIOR ?
 *
 * Below is and example of usage:
 * @code
 *
 * uint8_t* dest = NULL;
 * uint8_t* key = (uint8_t*)malloc(sizeof(uint8_t)*20);
 * set_key(key); 											// pseudo-function that populates key 
 * uint8_t* data = (uint8_t*)malloc(sizeof(uint8_t)*8);
 * set_data(data); 										// pseudo-function that populates data 
 * 
 * int data_size = 8, key_size = 20;
 *
 * hmac_SHA256_256(data, key, data_size, key_size, &dest);
 *
 * print_array_hex(dest);									// pseudo-function that prints dest in hex format
 * @endcode
 * @param data Pointer (<tt>uint8_t*</tt>) containg the data that will be used to generate the HMAC Tag
 * @param key Pointer (<tt>uint8_t*</tt>) containg the key that will be used to generate the HMAC Tag
 * @param data_size Variable (<tt>size_t</tt>) that hold the size in bytes of data. 
 * @param key_size Variable (<tt>size_t</tt>) that hold the size in bytes of key. 
 * @param dest key Pointer (<tt>void**</tt>) pointing to the destiny memory address where HMAC tag should be stored
 * @return The function doesn't return any value
 * @warning @p dest should be create as a data type capable of storing the HMAC Tag (ex. <tt>uint8_t*</tt>). However, it's 
 * memory address must be passed to the function and not the pointer itself (<b><tt>&dest</tt></b>)
 * @note It is not required to manually allocate/reserve memory for @p dest, this functions allocates the necessary memory
 * to store the HMAC tag. 
 */
void
hmac_SHA256_256(uint8_t* data, uint8_t* key, size_t data_size, size_t key_size, void** dest);

/**
 * @brief Function that generates an HMAC-BLAKE2b_80 Tag
 *
 * This function generates an HMAC Tag of 80bits (10bytes) long, using BLAKE2b as
 * its base hashing algorithm. It receives @p data, @p key and @p dest as pointers,
 * and both data and key sizes as <tt>size_t</tt>. The functions calculates the MAC
 * tag and stores it on @p dest. It uses OpenSSL Library to implement such algorithms.
 *
 * EXPECTED BEHAVIOR ?
 *
 * Below is and example of usage:
 * @code
 *
 * uint8_t* dest = NULL;
 * uint8_t* key = (uint8_t*)malloc(sizeof(uint8_t)*20);
 * set_key(key); 											// pseudo-function that populates key 
 * uint8_t* data = (uint8_t*)malloc(sizeof(uint8_t)*8);
 * set_data(data); 										// pseudo-function that populates data 
 * 
 * int data_size = 8, key_size = 20;
 *
 * hmac_BLAKE2b_80(data, key, data_size, key_size, &dest);
 *
 * print_array_hex(dest);									// pseudo-function that prints dest in hex format
 * @endcode
 * @param data Pointer (<tt>uint8_t*</tt>) containg the data that will be used to generate the HMAC Tag
 * @param key Pointer (<tt>uint8_t*</tt>) containg the key that will be used to generate the HMAC Tag
 * @param data_size Variable (<tt>size_t</tt>) that hold the size in bytes of data. 
 * @param key_size Variable (<tt>size_t</tt>) that hold the size in bytes of key. 
 * @param dest key Pointer (<tt>void**</tt>) pointing to the destiny memory address where HMAC tag should be stored
 * @return The function doesn't return any value
 * @warning @p dest should be create as a data type capable of storing the HMAC Tag (ex. <tt>uint8_t*</tt>). However, it's 
 * memory address must be passed to the function and not the pointer itself (<b><tt>&dest</tt></b>)
 */
void
hmac_BLAKE2b_80(uint8_t* data, uint8_t* key, size_t data_size, size_t key_size, void** dest);

/**
 * @brief Function that generates an HMAC-BLAKE2s_80 Tag
 *
 * This function generates an HMAC Tag of 80bits (10bytes) long, using BLAKE2s as
 * its base hashing algorithm. It receives @p data, @p key and @p dest as pointers,
 * and both data and key sizes as <tt>size_t</tt>. The functions calculates the MAC
 * tag and stores it on @p dest. It uses OpenSSL Library to implement such algorithms.
 *
 * EXPECTED BEHAVIOR ?
 *
 * Below is and example of usage:
 * @code
 *
 * uint8_t* dest = NULL;
 * uint8_t* key = (uint8_t*)malloc(sizeof(uint8_t)*20);
 * set_key(key); 											// pseudo-function that populates key 
 * uint8_t* data = (uint8_t*)malloc(sizeof(uint8_t)*8);
 * set_data(data); 										// pseudo-function that populates data 
 * 
 * int data_size = 8, key_size = 20;
 *
 * hmac_BLAKE2s_80(data, key, data_size, key_size, &dest);
 *
 * print_array_hex(dest);									// pseudo-function that prints dest in hex format
 * @endcode
 * @param data Pointer (<tt>uint8_t*</tt>) containg the data that will be used to generate the HMAC Tag
 * @param key Pointer (<tt>uint8_t*</tt>) containg the key that will be used to generate the HMAC Tag
 * @param data_size Variable (<tt>size_t</tt>) that hold the size in bytes of data. 
 * @param key_size Variable (<tt>size_t</tt>) that hold the size in bytes of key. 
 * @param dest key Pointer (<tt>void**</tt>) pointing to the destiny memory address where HMAC tag should be stored
 * @return The function doesn't return any value
 * @warning @p dest should be create as a data type capable of storing the HMAC Tag (ex. <tt>uint8_t*</tt>). However, it's 
 * memory address must be passed to the function and not the pointer itself (<b><tt>&dest</tt></b>)
 */
void
hmac_BLAKE2s_80(uint8_t* data, uint8_t* key, size_t data_size, size_t key_size, void** dest);
