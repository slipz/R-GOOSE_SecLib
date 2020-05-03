
#include "r_goose_security.h"


const int MAC_SIZES[] = {10, 16, 32, 10, 10, 8, 16, 8, 16};

/* Recebe apenas a mensagem r_goose, não o pacote inteiro 

	Packet: 
		Starts in: 	LI 						= 0x01
					TI						= 0x40
					Session Identifier 		= 1-byte
					...
					....
					...

		Ending:		GOOSE PDU
	
		To Add:		Signature TAG			= 0x85
					Signature Length		= 1-byte
					Authentication TAG		= Signature-length-bytes

*/		
void r_gooseMessage_InsertHMAC(uint8_t* buffer, uint8_t* key, size_t key_size, int alg){
	

	int macSize = MAC_SIZES[alg];

	int messageSize = decode_4bytesToInt(buffer,6) + 10;

	int new_size = messageSize + macSize;
	
	uint8_t* tmp;

	if((tmp = (uint8_t*)realloc(buffer, new_size)) == NULL){
		// process error
		// new malloc ? call error ?
		printf("deu erro no realloc\n");

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
	index = new_size - macSize + 1; // -1 ?
	buffer[index++] = macSize;

	// Generate Authentication Tag

	uint8_t* aux = (uint8_t*)malloc(sizeof(uint8_t)*macSize);

	if(alg == HMAC_SHA256_80){

		buffer[23] = 0x01;										// MAC Algorithm - 0x01 - HMAC-SHA256-80 as per IEC 62351-6:2020 draft
		
		hmac_SHA256_80(&buffer[2], key, messageSize-4, key_size, &aux);

		/*printf("Calculated tag:\n  ");
	    for(int i = 0; i < 10; i++){
	        printf("%02x", aux[i]);
	    }
		printf("\n");*/

	}else if(alg == HMAC_SHA256_128){

		buffer[23] = 0x02;										// MAC Algorithm - 0x01 - HMAC-SHA256-80 as per IEC 62351-6:2020 draft
		
		hmac_SHA256_128(&buffer[2], key, messageSize-4, key_size, &aux);

	}else if(alg == HMAC_SHA256_256){

		buffer[23] = 0x03;										// MAC Algorithm - 0x01 - HMAC-SHA256-80 as per IEC 62351-6:2020 draft
		
		hmac_SHA256_256(&buffer[2], key, messageSize-4, key_size, &aux);

	}else if(alg == HMAC_BLAKE2B_80){

		buffer[23] = 0x06;										// MAC Algorithm - 0x06 - Custom made
		
		hmac_BLAKE2b_80(&buffer[2], key, messageSize-4, key_size, &aux);

	}else if(alg == HMAC_BLAKE2S_80){

		buffer[23] = 0x07;										// MAC Algorithm - 0x07 - Custom made
		
		hmac_BLAKE2s_80(&buffer[2], key, messageSize-4, key_size, &aux);

	}
	
	// Append Authentication Tag to buffer
	memcpy(&buffer[new_size-macSize], aux, macSize);

}




void r_gooseMessage_InsertGMAC(uint8_t* buffer, uint8_t* key, size_t key_size, int alg){
	// Initiate IV - Can be changed
	uint8_t* iv = (uint8_t*)malloc(sizeof(uint8_t)*12);
	*(iv + 0) = 0x34;
	*(iv + 1) = 0xed;
	*(iv + 2) = 0xfa;
	*(iv + 3) = 0x46;
	*(iv + 4) = 0x2a;
	*(iv + 5) = 0x14;
	*(iv + 6) = 0xc6;
	*(iv + 7) = 0x96;
	*(iv + 8) = 0x9a;
	*(iv + 9) = 0x68;
	*(iv + 10) = 0x0e;
	*(iv + 11) = 0xc1;

	int iv_size = 12;

	int macSize = MAC_SIZES[alg];

	int messageSize = decode_4bytesToInt(buffer,6) + 10;

	int new_size = messageSize + macSize;
	
	uint8_t* tmp;

	if((tmp = (uint8_t*)realloc(buffer, new_size)) == NULL){
		// process error
		// new malloc ? call error ?
		printf("deu erro no realloc\n");

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
	index = new_size - macSize + 1; // -1 ?
	buffer[index++] = macSize;

	// Generate Authentication Tag

	uint8_t* aux = (uint8_t*)malloc(sizeof(uint8_t)*macSize);

	if(alg == GMAC_AES256_64){

		buffer[23] = 0x04;										// MAC Algorithm - 0x04 - GMAC_AES256_64 as per IEC 62351-6:2020 draft
		
		gmac_AES256_64(&buffer[2], key, iv, messageSize-4, iv_size, &aux);

		printf("Calculated tag:\n  ");
	    for(int i = 0; i < 10; i++){
	        printf("%02x", aux[i]);
	    }
		printf("\n");

	}else if(alg == GMAC_AES256_128){

		buffer[23] = 0x04;										// MAC Algorithm - 0x05 - GMAC_AES256_128 as per IEC 62351-6:2020 draft
		
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