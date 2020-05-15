/**
 * @file r_goose_security.h
 * @author Eduardo Andrade
 * @date Mar 2020
 * @brief File containing HMAC, GMAC and AES related imports, as well as the declarations of several 
 * R-GOOSE Protocol related constants. The functions on .c file are responsible to ensure security properties
 * to R-GOOSE messages. 
 * 
 * The functions implemented use the following R-GOOSE packet structure:
 * 
 *				- LI 							= 0x01
 *				- TI							= 0x40
 *				- Session Identifier 			= 1-byte
 *				- LI							= 1-byte
 *				- Common Header					= 1-byte
 *				- LI							= 1-byte
 *				- SPDU Length					= 4-byte
 *				- SPDU Number					= 4-byte
 *				- Version Number				= 2-byte
 *								
 *				- TimeOfCurrentKey				= 4-byte
 *				- TimeToNextKey					= 2-byte
 *				- Security Information		 
 *					- Encryption Algorithm		= 1-byte
 *					- MAC Algorithm				= 1-byte
 *				- Key ID						= 4-byte
 *				
 *				- Length						= 4-byte
 *				- Payload Type					= 1-byte
 *				- Simulation					= 1-byte
 *				- APPID							= 2-byte
 *				- APDU Length					= 2-byte
 *				- GOOSE PDU						= APDU Length - 2
 *				
 *				- Signature TAG					= 0x85
 *				- Signature Length				= 1-byte
 *				- Authentication Tag 			= Signature-length-bytes 
 *
 *
 * This header file declares the several funtions implemented on the file r_goose_security.c.
 * Also, this file includes all of the other files and libraries used to modify and secure R-GOOSE Messages (OpenSSL, C Standard Libraries).
 * @note This library was tested using OpenSSL 1.1.1 library. 
 */
 
 
#include "hmac_functions.h"
#include "gmac_functions.h"
#include "aes_crypto.h"

#include "aux_funcs.h"


// Analisar de mudar 1 -> 0x01 tem impacto na performance
// MAC Tag Algorithms Defined Values
#define MAC_NONE			0
#define HMAC_SHA256_80 		1
#define HMAC_SHA256_128 	2
#define HMAC_SHA256_256 	3
#define GMAC_AES256_64 		4
#define GMAC_AES256_128 	5

#define HMAC_BLAKE2B_80 	6
#define HMAC_BLAKE2S_80 	7

#define GMAC_AES128_64 		8
#define GMAC_AES128_128 	9


// Encryption Algorithms Defined Values
#define ENC_NONE			0
#define AES_128_GCM			1
#define AES_256_GCM			2


// R-GOOSE message field indexes
#define INDEX_SPDU_LENGTH			6
#define INDEX_SPDU_NUMBER			10
#define INDEX_VERSION_NUMBER		14

#define INDEX_SECURITY_INFO			16

#define INDEX_TIMECURKEY			16
#define INDEX_TIMENEXTKEY			20
#define INDEX_ENCRYPTION_ALG		22
#define INDEX_MAC_ALG				23
#define INDEX_KEYID					24

#define INDEX_LENGTH				28

#define INDEX_PAYLOAD_TYPE			32
#define INDEX_SIMULATION			33
#define INDEX_APPID					34
#define INDEX_APDU_LENGTH			36		
#define INDEX_PAYLOAD				38		

// Mapping between defined MAC Tag Algorithms and MAC Tag sizes
extern const int MAC_SIZES[];


/**
 * @brief Function that generate and insert an HMAC Tag into an R-GOOSE message.
 * 
 * This function generate an HMAC Tag and insert it into an R-GOOSE message, updating
 * the mutable fields of the protocol. The R-GOOSE message is received by a parameter,
 * @p buffer, a pointer to the message itself, and generates the HMAC acordding to the
 * specified algorithm (@p alg). The resulting tag is stored directly on the original 
 * message. The parameter @p alg, is a constant that could be found on r_goose_security.h.
 *
 * Below is and example of usage:
 * @code
 *
 * uint8_t* buffer = receive_packet();						// pseudo-function that receives a packet
 * uint8_t* key = (uint8_t*)malloc(sizeof(uint8_t)*20);
 * set_key(key); 											// pseudo-function that populates key 
 * 
 * int key_size = 20;
 *
 * r_gooseMessage_InsertHMAC(buffer, key, key_size, HMAC_SHA256_80);
 *
 * print_message(buffer);									// pseudo-function that prints the resulting message
 *
 * @endcode
 *
 * @param buffer Pointer (<tt>uint8_t*</tt>) containg to the R-GOOSE message
 * @param key Pointer (<tt>uint8_t*</tt>) containg the key that will be used to generate the HMAC Tag 
 * @param key_size Variable (<tt>size_t</tt>) that hold the size in bytes of key. 
 * @param alg Variable (<tt>int</tt>) that specifies the algorithm that will be used to generate de HMAC Tag. 
 * @return The function returns -1 if an error occurred and 1 if the HMAC tag was successfully generated and inserted.
 * @warning The packet format must be the same as specified on the top the this page.
 * @warning If an unknown @p alg is given (not specified on r_goose_security.h) the function returns -1, as an error. 
 */
int r_gooseMessage_InsertHMAC(uint8_t* buffer, uint8_t* key, size_t key_size, int alg);


/**
 * @brief Function that generate and insert an GMAC Tag into an R-GOOSE message.
 * 
 * This function generate an GMAC Tag and insert it into an R-GOOSE message, updating
 * the mutable fields of the protocol. The R-GOOSE message is received by a parameter,
 * @p buffer, a pointer to the message itself, and generates the GMAC acordding to the
 * specified algorithm (@p alg). The resulting tag is stored directly on the original 
 * message. The parameter @p alg, is a constant that could be found on r_goose_security.h.
 *
 * Below is and example of usage:
 * @code
 *
 * uint8_t* buffer = receive_packet();						// pseudo-function that receives a packet
 * uint8_t* key = (uint8_t*)malloc(sizeof(uint8_t)*16);
 * set_key(key); 											// pseudo-function that populates key 
 * 
 * int key_size = 16;
 *
 * r_gooseMessage_InsertGMAC(buffer, key, key_size, GMAC_AES128_128);
 *
 * print_message(buffer);									// pseudo-function that prints the resulting message
 *
 * @endcode
 *
 * @param buffer Pointer (<tt>uint8_t*</tt>) containg to the R-GOOSE message
 * @param key Pointer (<tt>uint8_t*</tt>) containg the key that will be used to generate the GMAC Tag 
 * @param key_size Variable (<tt>size_t</tt>) that hold the size in bytes of key. 
 * @param alg Variable (<tt>int</tt>) that specifies the algorithm that will be used to generate de GMAC Tag. 
 * @return The function returns -1 if an error occurred and 1 if the GMAC tag was successfully generated and inserted.
 * @warning The packet format must be the same as specified on the top the this page.
 * @warning If an unknown @p alg is given (not specified on r_goose_security.h) the function returns -1, as an error. 
 * @note @p key and @p key_size must be defined according the specified algorithm @p alg. If AES128-GCM is used, then a 16 bytes
 * long key should be given, although, if AES256-GCM is used, a 32 bytes key should be given. 
 * @note For now, the Initialization Vector (IV) is constant and defined inside the function as all-zeros byte array.
 */
int r_gooseMessage_InsertGMAC(uint8_t* buffer, uint8_t* key, size_t key_size, int alg);


/**
 * @brief Function that validates or invalidates an R-GOOSE message containing an HMAC Tag. 
 * 
 * This function analysis the HMAC Tag (if it exists) on a R-GOOSE message, and, if the tag 
 * is valid, it indicates the message as valid, otherwise, the message as invalid. This evaluation
 * is done by generating the expected HMAC Tag, according to the information in the packet 
 * (Security Information->MAC Algorithm [index 23]) and comparing it with the one appended to the message.
 * If both are equal, then the message is valid (the message was not changed during transportation), 
 * otherwise, the message was tampered, being invalid. The function receives R-GOOSE message (@p buffer),
 * the key that should be used to generate the HMAC (@p key) and the key size (@p key_size). The message
 * is only evaluated, meaning that the HMAC Tag is not removed. 
 *
 * Below is and example of usage:
 * @code
 *
 * uint8_t* buffer = receive_packet();						// pseudo-function that receives a packet
 * uint8_t* key = (uint8_t*)malloc(sizeof(uint8_t)*20);
 * set_key(key); 											// pseudo-function that populates key 
 * 
 * int key_size = 20;
 *
 * if((res = r_gooseMessage_ValidateHMAC(buffer, key, key_size)) == 1){
 *		printf("Tag is valid.\n");
 * }else if(res == 2){
 *		printf("Packet without Authentication Tag\n");
 * }else if(res = 0){
 *		printf("Invalid Tag/Packet\n");
 * }else{	
 *		printf("Invalid Tag/Packet - [Error]\n");
 * }
 *
 * @endcode
 *
 * @param buffer Pointer (<tt>uint8_t*</tt>) containg to the R-GOOSE message
 * @param key Pointer (<tt>uint8_t*</tt>) containg the key that will be used to generate the HMAC Tag 
 * @param key_size Variable (<tt>size_t</tt>) that hold the size in bytes of key.  
 * @return The function returns -1 if an error occurred, 0 if the generated HMAC doesn't matches the 
 * provided in the packet (message is invalid), 1 if the generated HMAC matches with the one provided (message is valid)
 * and 2 if the message doesn't contain the HMAC (not secured message)
 * @warning The packet format must be the same as specified on the top the this page.
 */
int r_gooseMessage_ValidateHMAC(uint8_t* buffer, uint8_t* key, size_t key_size);


/**
 * @brief Function that validates or invalidates an R-GOOSE message containing an GMAC Tag. 
 * 
 * This function analysis the GMAC Tag (if it exists) on a R-GOOSE message, and, if the tag 
 * is valid, it indicates the message as valid, otherwise, the message as invalid. This evaluation
 * is done by generating the expected GMAC Tag, according to the information in the packet 
 * (Security Information->MAC Algorithm [index 23]) and comparing it with the one appended to the message.
 * If both are equal, then the message is valid (the message was not changed during transportation), 
 * otherwise, the message was tampered, being invalid. The function receives R-GOOSE message (@p buffer),
 * the key that should be used to generate the GMAC (@p key) and the key size (@p key_size). The message
 * is only evaluated, meaning that the GMAC Tag is not removed. 
 *
 * Below is and example of usage:
 * @code
 *
 * uint8_t* buffer = receive_packet();						// pseudo-function that receives a packet
 * uint8_t* key = (uint8_t*)malloc(sizeof(uint8_t)*20);
 * set_key(key); 											// pseudo-function that populates key 
 * 
 * int key_size = 20;
 *
 * if((res = r_gooseMessage_ValidateGMAC(buffer, key, key_size)) == 1){
 *		printf("Tag is valid.\n");
 * }else if(res == 2){
 *		printf("Packet without Authentication Tag\n");
 * }else if(res = 0){
 *		printf("Invalid Tag/Packet\n");
 * }else{	
 *		printf("Invalid Tag/Packet - [Error]\n");
 * }
 *
 * @endcode
 *
 * @param buffer Pointer (<tt>uint8_t*</tt>) containg to the R-GOOSE message
 * @param key Pointer (<tt>uint8_t*</tt>) containg the key that will be used to generate the GMAC Tag 
 * @param key_size Variable (<tt>size_t</tt>) that hold the size in bytes of key.  
 * @return The function returns -1 if an error occurred, 0 if the generated GMAC doesn't matches the 
 * provided in the packet (message is invalid), 1 if the generated GMAC matches with the one provided (message is valid)
 * and 2 if the message doesn't contain the GMAC (not secured message)
 * @warning The packet format must be the same as specified on the top the this page.
 * @note For now, the Initialization Vector (IV) is constant and defined inside the function as all-zeros byte array.
 */
int r_gooseMessage_ValidateGMAC(uint8_t* buffer, uint8_t* key, size_t key_size);


/**
 * @brief Function that encrypts the GOOSE payload of an R-GOOSE message. 
 * 
 * This function encrypts the GOOSE payload inside an R-GOOSE message. It receives the R-GOOSE message
 * (@p buffer) and several security information related paramenters that are going to be updated on the
 * original message. The encryption algorithm to be used is also specified as an argument(@p alg), and the 
 * valid values can be found on r_goose_security.h. The security parameters are the specified in the R-GOOSE
 * protocol being TimeOfCurrentKey, TimeToNextKey and KeyID. 
 *
 * Below is and example of usage:
 * @code
 *
 * uint8_t* buffer = receive_packet();						// pseudo-function that receives a packet
 * uint8_t* key = (uint8_t*)malloc(sizeof(uint8_t)*32);
 * set_key(key); 											// pseudo-function that populates key 
 * 
 * int key_size = 32;
 *
 * int res = r_gooseMessage_Encrypt(buffer, key, AES_256_GCM, TimeOfCurrentKey, TimeToNextKey, KeyID, iv, iv_size);
 * 
 * if(res == 1){
 *		printf("Encryption success\n");
 * }else if(res == 0){
 *		printf("Non Encryption success\n");
 * }else{
 *		printf("Error while encrypting\n");
 * }
 *
 * @endcode
 *
 * @param buffer Pointer (<tt>uint8_t*</tt>) containg the R-GOOSE message
 * @param key Pointer (<tt>uint8_t*</tt>) containg the key that will be used to encrypt the GOOSE Payload
 * @param alg Variable (<tt>int</tt>) contaning the reference to the encryption algorithm to be used (specified in r_goose_security.h) 
 * @param timeOfCurrentKey Variable (<tt>uint32_t</tt>) contaning the value specifying the time value of the current key in use. Used to update R-GOOSE packet
 * @param timeToNextKey Variable (<tt>uint16_t</tt>) contaning the value specifying the time in minutes to the next key. Used to update R-GOOSE packet
 * @param key_id Variable (<tt>uint32_t</tt>) containing the ID of the key being used, as a reference to the Key Management Scheme in use. Used to update R-GOOSE packet
 * @param iv Pointer (<tt>uint8_t*</tt>) containg the Initialization Vector to be used in encryption
 * @param iv_size Variable (<tt>size_t</tt>) that hold the size in bytes of IV. 
 * @return The function returns -1 if an error occurred, 0 if the encryption algorithm was set to None Encryption and 1 if the GOOSE Payload was correctly encrypted. 
 * @warning The packet format must be the same as specified on the top the this page.
 */
int r_gooseMessage_Encrypt(uint8_t* buffer, uint8_t* key, int alg, uint32_t timeOfCurrentKey, uint16_t timeToNextKey, uint32_t key_id, uint8_t* iv, int iv_size);


/**
 * @brief Function that decrypts the GOOSE payload of an R-GOOSE message. 
 * 
 * This function decrypts the GOOSE payload inside an R-GOOSE message. It receives the R-GOOSE message
 * (@p buffer), the key that is going to be used (@p key), the Initialization Vector (@p iv) and its size (@p iv_size). 
 * The decryption algorithm to be used is also specified inside the message itself, and the 
 * supported algorithms can be found on r_goose_security.h. 
 *
 * Below is and example of usage:
 * @code
 *
 * uint8_t* buffer = receive_packet();						// pseudo-function that receives a packet
 * uint8_t* key = (uint8_t*)malloc(sizeof(uint8_t)*32);
 * set_key(key); 											// pseudo-function that populates key 
 * 
 * int key_size = 32;
 *
 * int res = r_gooseMessage_Decrypt(buffer, key, iv, iv_size);
 * 
 * if(res == 1){
 *		printf("Decrytpion success\n");
 * }else if(res == 0){
 *		printf("Non Encryption\n");
 * }else{
 *		printf("Error while decrypting\n");
 * }
 *
 * @endcode
 *
 * @param buffer Pointer (<tt>uint8_t*</tt>) containg the R-GOOSE message
 * @param key Pointer (<tt>uint8_t*</tt>) containg the key that will be used to decrypt the GOOSE Payload
 * @param iv Pointer (<tt>uint8_t*</tt>) containg the Initialization Vector to be used in decryption
 * @param iv_size Variable (<tt>size_t</tt>) that hold the size in bytes of IV. 
 * @return The function returns -1 if an error occurred, 0 if the decryption algorithm was set to None Encryption and 1 if the GOOSE Payload was correctly decrypted. 
 * @warning The packet format must be the same as specified on the top the this page.
 */
int r_gooseMessage_Decrypt(uint8_t* buffer, uint8_t* key, uint8_t* iv, int iv_size);



/**
 * @brief Function that dissects and prints the R-GOOSE message. 
 * 
 * This function dissects and prints the R-GOOSE message. It receives the message (@p buffer),
 * iterates over its data and presents it in a user-friendly way. This is an auxiliary function. 
 *
 * Below is and example of usage:
 * @code
 *
 * uint8_t* buffer = receive_packet();						// pseudo-function that receives a packet
 * 
 * r_goose_dissect(buffer);
 *
 * @endcode
 *
 * @param buffer Pointer (<tt>uint8_t*</tt>) containg the R-GOOSE message
 * @return The function doesn't return any value.
 * @warning The packet format must be the same as specified on the top the this page.
 */
void r_goose_dissect(uint8_t* buffer);