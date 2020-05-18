#include "r_goose_security.h"


const int MAC_SIZES[] = {0, 10, 16, 32, 8, 16, 10, 10, 8, 16};

/* Recebe apenas a mensagem r_goose, não o pacote inteiro 

	Packet: 
		Starts in: 	LI 						= 0x01
					TI						= 0x40
					Session Identifier 		= 1-byte
					...
					....
					...

		Ending:		GOOSE PDU
					Signature TAG			= 0x85
					Signature Length		= 1-byte
	
		To Add:		Authentication TAG		= Signature-length-bytes

*/		
int r_gooseMessage_InsertHMAC(uint8_t* buffer, uint8_t* key, size_t key_size, int alg){
	
	int macSize, messageSize, new_size;
	uint8_t* tmp;

	
	// Get length of MAC Tag from alg parameter
	macSize = MAC_SIZES[alg];

	
	/* Calculate total message size: [LI , TI, Session Identifier, ... , ... , Length of MAC Tag] 
			MAC Tag not considered as this packet should not contain such field
			However, if such field exists (possibly an error), messageSize will have it in 
			consideration
		- messageSize = SPDU_LENGTH + (Previous Header Fields [LI,TI,SI,LI,CH,LI,SPDU_L(4bytes)]) (10 bytes) 
	*/
	messageSize = decode_4bytesToInt(buffer,INDEX_SPDU_LENGTH) + 10;

	
	/* Calculate new message size 
			new_size = [LI , TI, Session Identifier, ... , ... , Length of MAC Tag] + [MAC Signature]
	*/
	new_size = messageSize + macSize;
	

	// Reallocate buffer to append MAC Signature field
	if((tmp = (uint8_t*)realloc(buffer, new_size)) == NULL){
		// This might occur due to following memory being already allocated
		// Then we need to allocate complete new buffer
		perror("realloc error");
		if((tmp = (uint8_t*)malloc(sizeof(char)*new_size)) == NULL){
			// Not possible to allocate more memory (system memory exausted)
			// Possible solutions ?
			perror("2nd malloc error\n");
			return -1;
		}else{
			// Able to malloc new memory
			// Copy old buffer content to new buffer
			memcpy(tmp,buffer,messageSize);
			// Reassign buffer pointer to new memory address
			buffer = tmp;
		}
	}else{
		buffer = tmp;
	}


	/* Updating Mutable Fields of R-GOOSE Message: 
			- Security Information:				
				+ Time of Current Key
				+ Time of Next Key
				+ Security Algorithm
					-> Encryption Algorithm
					-> MAC Signature Algorithm
				+ Key ID
			- SPDU Length
			- Length of Signature
	*/

	// Aux variable to keep track of current pos in buffer
	int index = INDEX_SECURITY_INFO; 							

	// Update TimeOfCurrentKey 		
	encodeInt4Bytes(buffer, (uint32_t)0, index);								// Index = 16
	index += 4;

	// Update TimeToNextKey	   									
	encodeInt2Bytes(buffer, (uint16_t)0, index);								// Index = 20
	index += 2;

	// Update Security Algorithm
	buffer[index] = 0x00;														// Index = 22
	index += 2;

	// Update Key ID
	encodeInt4Bytes(buffer, (uint32_t)0, index);								// Index = 24
	index += 4;

	// Update SPDU Length 
	encodeInt4Bytes(buffer, (uint32_t)(new_size-10), INDEX_SPDU_LENGTH);		// Index = 6
	index += 4;

	/* Update Signature Length
		Index = Total New Message Size (new_size) - Signature Size (macSize) - 1 

		Signature Length = macSize, depends on the algorithm passed by param
		VERIFICAR 
	*/
	index = new_size - macSize - 1;				
	buffer[index++] = macSize;			


	// Generate Authentication Tag

	// Malloc temporary/auxiliary buffer to store generated MAC Tag
	uint8_t* aux = (uint8_t*)malloc(sizeof(uint8_t)*macSize);

	/* 	Depending on the algorithm choosen (alg param), MAC Signature Algorithm field
		must be updated, and call respective HMAC generation function

		The following constants are defined in r_goose_security.h header file

		Generate and store HMAC tag on aux
			- Authenticated data:
				+ From Session Header [SI - Session Identifier] - Index = 2
				+ Until end of GOOSE PDU						
			- Data size = Initial Message Size - 2bytes (Signature TAG + Length of MAC) - 2bytes (LI, TI)
			- Key and key size are received by param
		
	*/
	if(alg == HMAC_SHA256_80){

		// MAC Algorithm - 0x01 - HMAC-SHA256-80 as per IEC 62351-6:2020 draft
		buffer[23] = 0x01;										
		
		hmac_SHA256_80(&buffer[2], key, messageSize-4, key_size, &aux);

	}else if(alg == HMAC_SHA256_128){

		// MAC Algorithm - 0x02 - HMAC-SHA256-128 as per IEC 62351-6:2020 draft
		buffer[23] = 0x02;										
		
		hmac_SHA256_128(&buffer[2], key, messageSize-4, key_size, &aux);

	}else if(alg == HMAC_SHA256_256){

		// MAC Algorithm - 0x03 - HMAC-SHA256-256 as per IEC 62351-6:2020 draft
		buffer[23] = 0x03;										
		
		hmac_SHA256_256(&buffer[2], key, messageSize-4, key_size, &aux);

	}else if(alg == HMAC_BLAKE2B_80){

		// MAC Algorithm - 0x06 - BLAKE2b padded to 10bytes - Custom made
		buffer[23] = 0x06;										
		
		hmac_BLAKE2b_80(&buffer[2], key, messageSize-4, key_size, &aux);

	}else if(alg == HMAC_BLAKE2S_80){

		// MAC Algorithm - 0x07 - BLAKE2s padded to 10 bytes - Custom made
		buffer[23] = 0x07;										
		
		hmac_BLAKE2s_80(&buffer[2], key, messageSize-4, key_size, &aux);

	}else{
		return -1;
	}
	
	// Append Authentication Tag to original buffer (already resized)
	memcpy(&buffer[new_size-macSize], aux, macSize);

	// Free memory
	free(aux);
	return 1;
}

int r_gooseMessage_ValidateHMAC(uint8_t* buffer, uint8_t* key, size_t key_size){

	int messageSize, alg, macSize, index_mac;

	messageSize = decode_4bytesToInt(buffer,INDEX_SPDU_LENGTH) + 10;

	alg = buffer[INDEX_MAC_ALG];

	macSize = MAC_SIZES[alg];

	index_mac = messageSize - macSize;

	/* Validate SPDU Length field -> must be higher than X */
	// Validade alg, must be a valid value otherwise, message tampered

	/* Get Security Info ... */

	/* Generate local HMAC from received data */
	if(alg == HMAC_SHA256_80){
		uint8_t* aux = (uint8_t*)malloc(sizeof(uint8_t)*macSize);

		hmac_SHA256_80(&buffer[2], key, messageSize-4-macSize, key_size, &aux);
		
		// MAC Tag comparison
		if(memcmp(aux, &buffer[index_mac], macSize) == 0){
			// MAC Tag is valid
			return 1;
		}else{
			return 0;
		}

	}else if(alg == HMAC_SHA256_128){
		uint8_t* aux = (uint8_t*)malloc(sizeof(uint8_t)*macSize);

		hmac_SHA256_128(&buffer[2], key, messageSize-4-macSize, key_size, &aux);
		
		// MAC Tag comparison
		if(memcmp(aux, &buffer[index_mac], macSize) == 0){
			// MAC Tag is valid
			return 1;
		}else{
			return 0;
		}

	}else if(alg == HMAC_SHA256_256){
		uint8_t* aux = (uint8_t*)malloc(sizeof(uint8_t)*macSize);

		hmac_SHA256_256(&buffer[2], key, messageSize-4-macSize, key_size, &aux);
	
		// MAC Tag comparison
		if(memcmp(aux, &buffer[index_mac], macSize) == 0){
			// MAC Tag is valid
			return 1;
		}else{
			return 0;
		}

	}else if(alg == HMAC_BLAKE2B_80){
		uint8_t* aux = (uint8_t*)malloc(sizeof(uint8_t)*macSize);

		hmac_BLAKE2b_80(&buffer[2], key, messageSize-4-macSize, key_size, &aux);
	
		// MAC Tag comparison
		if(memcmp(aux, &buffer[index_mac], macSize) == 0){
			// MAC Tag is valid
			return 1;
		}else{
			return 0;
		}

	}else if(alg == HMAC_BLAKE2S_80){
		uint8_t* aux = (uint8_t*)malloc(sizeof(uint8_t)*macSize);

		hmac_BLAKE2s_80(&buffer[2], key, messageSize-4-macSize, key_size, &aux);
	
		// MAC Tag comparison
		if(memcmp(aux, &buffer[index_mac], macSize) == 0){
			// MAC Tag is valid
			return 1;
		}else{
			return 0;
		}

	}else if(alg == MAC_NONE){
		// Nothing to do ... but not an error
		return 2;
	}else{
		// Invalid data
		return -1;
	}
}

int r_gooseMessage_InsertGMAC(uint8_t* buffer, uint8_t* key, size_t key_size, int alg){
	// Initialize IV - Can be changed
	uint8_t* iv = (uint8_t*)malloc(sizeof(uint8_t)*12);
	*(iv + 0) = 0x00;
	*(iv + 1) = 0x00;
	*(iv + 2) = 0x00;
	*(iv + 3) = 0x00;
	*(iv + 4) = 0x00;
	*(iv + 5) = 0x00;
	*(iv + 6) = 0x00;
	*(iv + 7) = 0x00;
	*(iv + 8) = 0x00;
	*(iv + 9) = 0x00;
	*(iv + 10) = 0x00;
	*(iv + 11) = 0x00;

	int iv_size = 12;

	int macSize = MAC_SIZES[alg];

	int messageSize = decode_4bytesToInt(buffer,6) + 10;

	int new_size = messageSize + macSize;
	
	uint8_t* tmp;

	// Reallocate buffer to append MAC Signature field
	if((tmp = (uint8_t*)realloc(buffer, new_size)) == NULL){
		// This might occur due to following memory being already allocated
		// Then we need to allocate complete new buffer
		perror("realloc error");
		if((tmp = (uint8_t*)malloc(sizeof(char)*new_size)) == NULL){
			// Not possible to allocate more memory (system memory exausted)
			// Possible solutions ?
			perror("2nd malloc error\n");
			return -1;
		}else{
			// Able to malloc new memory
			// Copy old buffer content to new buffer
			memcpy(tmp,buffer,messageSize);
			// Reassign buffer pointer to new memory address
			buffer = tmp;
		}
	}else{
		buffer = tmp;
	}

	int index = INDEX_SECURITY_INFO; 											// Aux variable to keep track of current pos in buffer

	// Update TimeOfCurrentKey 		- Index = 16
	encodeInt4Bytes(buffer, (uint32_t)0, index);
	index += 4;

	// Update TimeToNextKey	   		- Index = 20
	encodeInt2Bytes(buffer, (uint16_t)0, index);
	index += 2;

	// Update Security Algorithm
	buffer[index] = 0x00;										// Encryption Algorithm
	index += 2;

	// Update Key ID
	encodeInt4Bytes(buffer, (uint32_t)0, index);
	index += 4;

	// Update SPDU Length 
	encodeInt4Bytes(buffer, (uint32_t)(new_size-10), 6);		// Index = 6, SPDU Length index
	index += 4;

	// Update Signature Length 
	index = new_size - macSize - 1; 
	buffer[index++] = (uint8_t)macSize;

	// Generate Authentication Tag

	uint8_t* aux = (uint8_t*)malloc(sizeof(uint8_t)*macSize);

	if(alg == GMAC_AES256_64){

		buffer[23] = 0x04;										// MAC Algorithm - 0x04 - GMAC_AES256_64 as per IEC 62351-6:2020 draft
		
		gmac_AES256_64(&buffer[2], key, iv, messageSize-4, iv_size, &aux);

		/*printf("Calculated tag:\n  ");
	    for(int i = 0; i < 10; i++){
	        printf("%02x", aux[i]);
	    }
		printf("\n");*/

	}else if(alg == GMAC_AES256_128){

		buffer[23] = 0x05;										// MAC Algorithm - 0x05 - GMAC_AES256_128 as per IEC 62351-6:2020 draft
		
		gmac_AES256_128(&buffer[2], key, iv, messageSize-4, iv_size, &aux);

	}else if(alg == GMAC_AES128_64){

		buffer[23] = 0x08;										// MAC Algorithm - 0x08 - Custom made
		
		gmac_AES128_64(&buffer[2], key, iv, messageSize-4, iv_size, &aux);

	}else if(alg == GMAC_AES128_128){

		buffer[23] = 0x09;										// MAC Algorithm - 0x09 - Custom made
		
		gmac_AES128_128(&buffer[2], key, iv, messageSize-4, iv_size, &aux);

	}
	
	// Append Authentication Tag to buffer
	memcpy(&buffer[new_size-macSize], aux, macSize);
	return 1;
}

int r_gooseMessage_ValidateGMAC(uint8_t* buffer, uint8_t* key, size_t key_size){
	
	// Initialize IV - Can be changed
	uint8_t* iv = (uint8_t*)malloc(sizeof(uint8_t)*12);
	*(iv + 0) = 0x00;
	*(iv + 1) = 0x00;
	*(iv + 2) = 0x00;
	*(iv + 3) = 0x00;
	*(iv + 4) = 0x00;
	*(iv + 5) = 0x00;
	*(iv + 6) = 0x00;
	*(iv + 7) = 0x00;
	*(iv + 8) = 0x00;
	*(iv + 9) = 0x00;
	*(iv + 10) = 0x00;
	*(iv + 11) = 0x00;

	int iv_size = 12;

	int messageSize, alg, macSize, index_mac;

	messageSize = decode_4bytesToInt(buffer,INDEX_SPDU_LENGTH) + 10;

	alg = buffer[INDEX_MAC_ALG];

	macSize = MAC_SIZES[alg];

	index_mac = messageSize - macSize;

	/* Validate SPDU Length field -> must be higher than X */
	// Validade alg, must be a valid value otherwise, message tampered

	/* Get Security Info ... */

	/* Generate local HMAC from received data */
	if(alg == GMAC_AES256_64){
		uint8_t* aux = (uint8_t*)malloc(sizeof(uint8_t)*macSize);

		gmac_AES256_64(&buffer[2], key, iv, messageSize-4-macSize, iv_size, &aux);
	
		// MAC Tag comparison
		if(memcmp(aux, &buffer[index_mac], macSize) == 0){
			// MAC Tag is valid
			return 1;
		}else{
			return 0;
		}

	}else if(alg == GMAC_AES256_128){
		uint8_t* aux = (uint8_t*)malloc(sizeof(uint8_t)*macSize);

		gmac_AES256_128(&buffer[2], key, iv, messageSize-4-macSize, iv_size, &aux);
		
		// MAC Tag comparison
		if(memcmp(aux, &buffer[index_mac], macSize) == 0){
			// MAC Tag is valid
			return 1;
		}else{
			return 0;
		}

	}else if(alg == GMAC_AES128_64){
		uint8_t* aux = (uint8_t*)malloc(sizeof(uint8_t)*macSize);

		gmac_AES128_64(&buffer[2], key, iv, messageSize-4-macSize, iv_size, &aux);
		
		// MAC Tag comparison
		if(memcmp(aux, &buffer[index_mac], macSize) == 0){
			// MAC Tag is valid
			return 1;
		}else{
			return 0;
		}

	}else if(alg == GMAC_AES128_128){
		uint8_t* aux = (uint8_t*)malloc(sizeof(uint8_t)*macSize);

		gmac_AES128_128(&buffer[2], key, iv, messageSize-4-macSize, iv_size, &aux);;
	
		// MAC Tag comparison
		if(memcmp(aux, &buffer[index_mac], macSize) == 0){
			// MAC Tag is valid
			return 1;
		}else{
			return 0;
		}

	}else if(alg == MAC_NONE){
		// Verificar se Signature Length != 0
		if(buffer[index_mac-1] != 0){
			// MAC Length changed, packet invalid
			return 0;
		}else{
			return 2;
		}

		return 1;
	}else{
		// Invalid data
		return -1;
	}

}


int r_gooseMessage_Encrypt(uint8_t* buffer, uint8_t* key, int alg, uint32_t timeOfCurrentKey, uint16_t timeToNextKey, uint32_t key_id, uint8_t* iv, int iv_size){
	int encLen;

	uint8_t* encryptedPayload = NULL;

	int data_size;

	if(alg == 1){
		// AES-128-GCM

		data_size = decode_2bytesToInt(buffer,INDEX_APDU_LENGTH) - 2;

		encodeInt4Bytes(buffer,timeOfCurrentKey,INDEX_TIMECURKEY);
		encodeInt2Bytes(buffer,timeToNextKey,INDEX_TIMENEXTKEY);
		encodeInt4Bytes(buffer,key_id,INDEX_KEYID);

		buffer[INDEX_ENCRYPTION_ALG] = 0x01;
		encLen = aes_128_gcm_encrypt(&buffer[INDEX_PAYLOAD], key, iv, data_size, iv_size, &encryptedPayload);

		memcpy(&buffer[INDEX_PAYLOAD], encryptedPayload, encLen);

		return 1;

	}else if(alg == 2){
		// AES-256-GCM

		data_size = decode_2bytesToInt(buffer,INDEX_APDU_LENGTH) - 2;

		encodeInt4Bytes(buffer,timeOfCurrentKey,INDEX_TIMECURKEY);
		encodeInt2Bytes(buffer,timeToNextKey,INDEX_TIMENEXTKEY);
		encodeInt4Bytes(buffer,key_id,INDEX_KEYID);

		buffer[INDEX_ENCRYPTION_ALG] = 0x02;
		encLen = aes_256_gcm_encrypt(&buffer[INDEX_PAYLOAD], key, iv, data_size, iv_size, &encryptedPayload);

		memcpy(&buffer[INDEX_PAYLOAD], encryptedPayload, encLen);

		return 1;

	}else if(alg == 0){
		// Default case ? - None Encryption
		buffer[INDEX_ENCRYPTION_ALG] = 0x00;

		return 0;
	}


	return -1;
}

int r_gooseMessage_Decrypt(uint8_t* buffer, uint8_t* key, uint8_t* iv, int iv_size){
	int ptLen;

	uint8_t* plaintextPayload = NULL;

	uint8_t alg = buffer[INDEX_ENCRYPTION_ALG];

	int data_size;

	if(alg == 1){
		// AES-128-GCM	
		buffer[INDEX_ENCRYPTION_ALG] = 0x00;

		data_size = decode_2bytesToInt(buffer,INDEX_APDU_LENGTH) - 2;
		
		ptLen = aes_256_gcm_decrypt(&buffer[INDEX_PAYLOAD], key, iv, data_size, iv_size, &plaintextPayload);
		
		memcpy(&buffer[INDEX_PAYLOAD], plaintextPayload, ptLen);
		
		return 1;

	}else if(alg == 2){
		// AES-256-GCM
		buffer[INDEX_ENCRYPTION_ALG] = 0x00;
		data_size = decode_2bytesToInt(buffer,INDEX_APDU_LENGTH) - 2;
		
		ptLen = aes_256_gcm_decrypt(&buffer[INDEX_PAYLOAD], key, iv, data_size, iv_size, &plaintextPayload);
		
		memcpy(&buffer[INDEX_PAYLOAD], plaintextPayload, ptLen);
		
		return 1;

	}else if(alg == 0){
		// Default - None Encryption
		return 0;
	}

	return -1;
}


int print_hex_values(uint8_t* buffer, int index, int len){
	for(int i = 0; i < len; i++){
		printf("%02x ",buffer[index+i]);
	}
	return index+len;
}


void r_goose_dissect(uint8_t* buffer){

	int index = 0;

	int spduLength, spduNumber, versionNumber, timeOfCurrentKey, timeToNextKey;
	int key_id, sessionPayloadLen, appid, apduLength, signatureLength;

	printf("---- R-GOOSE Packet Start ---- \n");
	printf("Session Header - \n");
	printf("\tLI - %02x \n",buffer[index++]);
	printf("\tTI - %02x \n",buffer[index++]);
	printf("\tSession Identifier - %02x : [%d] \n",buffer[index], buffer[index]);index++;
	printf("\tLI - %02x \n",buffer[index++]);
	printf("\tCommon Header - %02x \n",buffer[index++]);
	printf("\tLI - %02x \n",buffer[index++]);
	printf("\n");
	printf("\tSPDU Length - "); index = print_hex_values(buffer, index, 4); spduLength = decode_4bytesToInt(buffer, INDEX_SPDU_LENGTH); printf(" : [%d]\n", spduLength); 
	printf("\tSPDU Number - "); index = print_hex_values(buffer, index, 4); spduNumber = decode_4bytesToInt(buffer, INDEX_SPDU_NUMBER); printf(" : [%d]\n", spduNumber); 
	printf("\tVersion Number - "); index = print_hex_values(buffer, index, 2); versionNumber = decode_2bytesToInt(buffer, INDEX_VERSION_NUMBER); printf(" : [%d]\n", versionNumber);
	printf("\tSecurity Information - \n");
	printf("\t\tTimeOfCurrentKey - "); index = print_hex_values(buffer, index, 4); timeOfCurrentKey = decode_4bytesToInt(buffer, INDEX_TIMECURKEY); printf(" : [%d]\n", timeOfCurrentKey);
	printf("\t\tTimeToNextKey - "); index = print_hex_values(buffer, index, 2); timeToNextKey = decode_2bytesToInt(buffer, INDEX_TIMENEXTKEY); printf(" : [%d]\n", timeToNextKey);
	printf("\t\tSecurity Algorithms - \n");
	printf("\t\t\tEncryption Algorithm - %02x\n", buffer[index++]);
	printf("\t\t\tMAC Tag Algorithm - %02x\n", buffer[index++]);
	printf("\t\tKey ID - "); index = print_hex_values(buffer, index, 4); key_id = decode_4bytesToInt(buffer, INDEX_KEYID); printf(" : [%d]\n\n", key_id);

	printf("Session User Information - \n");
	printf("\tSession Payload Length - "); index = print_hex_values(buffer, index, 4); sessionPayloadLen = decode_4bytesToInt(buffer, INDEX_LENGTH); printf(" : [%d]\n\n", sessionPayloadLen);

	printf("\tPayload Type - %02x : [%d] \n", buffer[index], buffer[index]); index++; 
	printf("\tSimulation - %02x : [%d] \n", buffer[index], buffer[index]); index++;
	printf("\tAPPID - "); index = print_hex_values(buffer, index, 2); appid = decode_2bytesToInt(buffer, INDEX_APPID); printf(" : [%d]\n", appid);
	printf("\tAPDU Length - "); index = print_hex_values(buffer, index, 2); apduLength = decode_2bytesToInt(buffer, INDEX_APDU_LENGTH); printf(" : [%d]\n", apduLength);
	printf("\tGOOSE PDU - \n\t\t"); index = print_hex_values(buffer, index, apduLength-2); 

	printf("\n\tSignature Fields - \n");
	printf("\t\tSignature TAG - %02x \n", buffer[index++]); 
	printf("\t\tSignature Length - %02x : [%d] \n", buffer[index], buffer[index]); signatureLength = buffer[index]; index++;
	printf("\t\tSignature - "); index = print_hex_values(buffer, index, signatureLength);

	printf("\n---- R-GOOSE Packet End ----\n\n");

}


