#include "aux.h"

int decode_2bytesToInt(uint8_t* buffer, int index){
    return((buffer[index]<<8) + (buffer[index+1]));
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

uint8_t* hexStringToBytes(char hex[], size_t len){
    char* pos = hex;
    uint8_t* bytes = (uint8_t*)malloc(sizeof(char)*(len/2));

    /* verificação len ser impar */

    for(size_t count = 0; count < (len/2); count++){
        sscanf(pos, "%2hhx", &bytes[count]);
        pos += 2;
    }

    

    return bytes;
}
