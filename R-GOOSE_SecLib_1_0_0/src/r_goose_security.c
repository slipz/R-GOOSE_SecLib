
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

	}
	
	// Append Authentication Tag to original buffer (already resized)
	memcpy(&buffer[new_size-macSize], aux, macSize);
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

	uint8_t* aux = (uint8_t*)malloc(sizeof(uint8_t)*macSize);

	if(alg == HMAC_SHA256_80){
		hmac_SHA256_80(&buffer[2], key, messageSize-4-macSize, key_size, &aux);
	}else if(alg == HMAC_SHA256_128){
		hmac_SHA256_128(&buffer[2], key, messageSize-4-macSize, key_size, &aux);
	}else if(alg == HMAC_SHA256_256){
		hmac_SHA256_256(&buffer[2], key, messageSize-4-macSize, key_size, &aux);
	}else if(alg == HMAC_BLAKE2B_80){
		hmac_BLAKE2b_80(&buffer[2], key, messageSize-4-macSize, key_size, &aux);
	}else if(alg == HMAC_BLAKE2S_80){
		hmac_BLAKE2s_80(&buffer[2], key, messageSize-4-macSize, key_size, &aux);
	}else if(alg == MAC_NONE){
		// Nothing to do ... but not an error
		printf("MAC Algorithm is None.\n");
		// What to do ? Valid, invalid ?
	}else{
		// Invalid data
		perror("Invalid MAC Algorithm byte");
	}

	printf("index_mac: %d\n",index_mac);

	printf("Calculated tag:\n  ");
    for(int i = 0; i < macSize; i++){
        printf("%02x", aux[i]);
    }
	printf("\n");

	printf("Expected tag:\n  ");
    for(int i = 0; i < macSize; i++){
        printf("%02x", buffer[index_mac+i]);
    }
	printf("\n");

	// MAC Tag comparison
	if(memcmp(aux, &buffer[index_mac], macSize) == 0){
		// MAC Tag is valid
		printf("Tag/R-GOOSE Message is Valid\n");
		return 1;
	}else{
		printf("Tag/R-GOOSE Message is Invalid\n");
		return 0;
	}
}

void r_gooseMessage_InsertGMAC(uint8_t* buffer, uint8_t* key, size_t key_size, int alg){
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

	if((tmp = (uint8_t*)realloc(buffer, new_size)) == NULL){
		// process error
		// new malloc ? call error ?
		printf("realloc error\n");

	}else{
		buffer = tmp;
	}

	int index = 16; 											// Aux variable to keep track of current pos in buffer

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
	index = new_size - macSize + 1; 
	buffer[index++] = macSize;

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

	printf("\nalg : %d\n",alg);

	uint8_t* aux = (uint8_t*)malloc(sizeof(uint8_t)*macSize);

	if(alg == GMAC_AES256_64){
		gmac_AES256_64(&buffer[2], key, iv, messageSize-4-macSize, iv_size, &aux);
	}else if(alg == GMAC_AES256_128){
		gmac_AES256_128(&buffer[2], key, iv, messageSize-4-macSize, iv_size, &aux);
	}else if(alg == GMAC_AES128_64){
		gmac_AES128_64(&buffer[2], key, iv, messageSize-4-macSize, iv_size, &aux);
	}else if(alg == GMAC_AES128_128){
		gmac_AES128_128(&buffer[2], key, iv, messageSize-4-macSize, iv_size, &aux);;
	}else if(alg == MAC_NONE){
		// Nothing to do ... but not an error
		printf("MAC Algorithm is None.\n");
		// What to do ? Valid, invalid ?
	}else{
		// Invalid data
		perror("Invalid MAC Algorithm byte");
	}

	printf("index_mac: %d\n",index_mac);

	printf("Calculated tag:\n  ");
    for(int i = 0; i < macSize; i++){
        printf("%02x", aux[i]);
    }
	printf("\n");

	printf("Expected tag:\n  ");
    for(int i = 0; i < macSize; i++){
        printf("%02x", buffer[index_mac+i]);
    }
	printf("\n");

	// MAC Tag comparison
	if(memcmp(aux, &buffer[index_mac], macSize) == 0){
		// MAC Tag is valid
		printf("Tag/R-GOOSE Message is Valid\n");
		return 1;
	}else{
		printf("Tag/R-GOOSE Message is Invalid\n");
		return 0;
	}
}

int r_gooseMessage_Encrypt(uint8_t* buffer, uint8_t* key, size_t key_size, int alg){

}

int r_gooseMessage_Decrypt(){

}


int decode_4bytesToInt(uint8_t* buffer, int index){
	return((buffer[index]<<24) + (buffer[index+1]<<16) + (buffer[index+2]<<8) + (buffer[index+3]));
}

void encodeInt2Bytes(uint8_t* buffer, uint16_t value, int index){
    buffer[index] 	= (uint8_t)((value & 0xFF00) >> 8 );
    buffer[index+1] = (uint8_t)((value & 0x00FF)      );
}

void encodeInt4Bytes(uint8_t* buffer, uint32_t value, int index){
    buffer[index] 	= (uint8_t)((value & 0xFF000000) >> 24);
    buffer[index+1] = (uint8_t)((value & 0x00FF0000) >> 16);
    buffer[index+2] = (uint8_t)((value & 0x0000FF00) >> 8 );
    buffer[index+3] = (uint8_t)((value & 0x000000FF)      );
}