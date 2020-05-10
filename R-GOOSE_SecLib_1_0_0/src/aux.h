#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

uint8_t* hexStringToBytes(char hex[], size_t len);
void encodeInt4Bytes(uint8_t* buffer, uint32_t value, int index);
void encodeInt2Bytes(uint8_t* buffer, uint16_t value, int index);
int decode_4bytesToInt(uint8_t* buffer, int index);