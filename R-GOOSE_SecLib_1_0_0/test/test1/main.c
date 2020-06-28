/* 
	Example file: 

		HMAC-SHA256-80 usage with RFC4231 Test Vector Case 1

*/

#include "hmac_functions.h"

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

	uint8_t* dest = NULL;

	uint8_t* key = (uint8_t*)malloc(sizeof(uint8_t)*20);
	*(key + 0) = 0x0b;
	*(key + 1) = 0x0b;
	*(key + 2) = 0x0b;
	*(key + 3) = 0x0b;
	*(key + 4) = 0x0b;
	*(key + 5) = 0x0b;
	*(key + 6) = 0x0b;
	*(key + 7) = 0x0b;
	*(key + 8) = 0x0b;
	*(key + 9) = 0x0b;
	*(key + 10) = 0x0b;
	*(key + 11) = 0x0b;
	*(key + 12) = 0x0b;
	*(key + 13) = 0x0b;
	*(key + 14) = 0x0b;
	*(key + 15) = 0x0b;
	*(key + 16) = 0x0b;
	*(key + 17) = 0x0b;
	*(key + 18) = 0x0b;
	*(key + 19) = 0x0b;

	int data_size = 196, key_size = 20;

	uint8_t* data = (uint8_t*)malloc(sizeof(uint8_t)*data_size);
	memset(data, 0x23, data_size);
	


	for(int j = 0; j<500000; j++){

		struct timespec start, end;
	  	clock_gettime(CLOCK_MONOTONIC, &start);

		hmac_SHA256_128(data, key, data_size, key_size, &dest);

		clock_gettime(CLOCK_MONOTONIC, &end);

		/*printf("Calculated tag:\n  ");
	    for(int i = 0; i < 10; i++){
	        printf("%02x", dest[i]);
	    }
		printf("\n");*/

		uint64_t timeElapsed = timespecDiff(&end, &start);

	  	long seconds = end.tv_sec - start.tv_sec;
	  	long ns = end.tv_nsec - start.tv_nsec;

	  	

	}



}
