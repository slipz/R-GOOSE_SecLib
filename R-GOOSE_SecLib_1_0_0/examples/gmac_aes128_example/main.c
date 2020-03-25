/* 
	Example file: 
	
		GMAC-AES128-128 usage 

*/

#include "gmac_functions.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <time.h>

int64_t timespecDiff(struct timespec *timeA_p, struct timespec *timeB_p)
{
  return ((timeA_p->tv_sec * 1000000000) + timeA_p->tv_nsec) -
           ((timeB_p->tv_sec * 1000000000) + timeB_p->tv_nsec);
}

int main(int argc, char** argv){

	printf("--- GMAC Generation Example ---\n");

	uint8_t* dest = NULL;

	uint8_t* key = (uint8_t*)malloc(sizeof(uint8_t)*16);
	*(key + 0) = 0x6d;
	*(key + 1) = 0xfa;
	*(key + 2) = 0x1a;
	*(key + 3) = 0x07;
	*(key + 4) = 0xc1;
	*(key + 5) = 0x4f;
	*(key + 6) = 0x97;
	*(key + 7) = 0x80;
	*(key + 8) = 0x20;
	*(key + 9) = 0xac;
	*(key + 10) = 0xe4;
	*(key + 11) = 0x50;
	*(key + 12) = 0xad;
	*(key + 13) = 0x66;
	*(key + 14) = 0x3d;
	*(key + 15) = 0x18;

	uint8_t* data = (uint8_t*)malloc(sizeof(uint8_t)*16);
	*(data + 0) = 0x2a;
	*(data + 1) = 0x35;
	*(data + 2) = 0xc7;
	*(data + 3) = 0xf5;
	*(data + 4) = 0xf8;
	*(data + 5) = 0x57;
	*(data + 6) = 0x8e;
	*(data + 7) = 0x91;
	*(data + 8) = 0x9a;
	*(data + 9) = 0x58;
	*(data + 10) = 0x1c;
	*(data + 11) = 0x60;
	*(data + 12) = 0x50;
	*(data + 13) = 0x0c;
	*(data + 14) = 0x04;
	*(data + 15) = 0xf6;

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


	int data_size = 16, iv_size = 12;

	struct timespec start, end;
  	clock_gettime(CLOCK_MONOTONIC, &start);

	gmac_AES128_128(data, key, iv, data_size, iv_size, &dest);

	clock_gettime(CLOCK_MONOTONIC, &end);

	printf("Calculated tag:\n  ");
    for(int i = 0; i < 16; i++){
        printf("%02x", dest[i]);
    }
	printf("\n");

	uint64_t timeElapsed = timespecDiff(&end, &start);

  	long seconds = end.tv_sec - start.tv_sec;
  	long ns = end.tv_nsec - start.tv_nsec;

  	printf("total secs: %lf\n",(double)seconds + (double)ns/(double)1000000000);


}