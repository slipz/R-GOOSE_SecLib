#include "hmac_functions.h"
#include "gmac_functions.h"


#include <stdio.h>
#include <string.h>

// Time measure
#include <stdint.h>
#include <time.h>

int64_t timespecDiff(struct timespec *timeA_p, struct timespec *timeB_p)
{
  return ((timeA_p->tv_sec * 1000000000) + timeA_p->tv_nsec) -
           ((timeB_p->tv_sec * 1000000000) + timeB_p->tv_nsec);
}


void main(){

	uint8_t* dest = malloc(sizeof(uint8_t)*16);

	uint8_t* data = (uint8_t*)malloc(sizeof(uint8_t)*16);
	*(data + 0) = 0x7a;
	*(data + 1) = 0x43;
	*(data + 2) = 0xec;
	*(data + 3) = 0x1d;
	*(data + 4) = 0x9c;
	*(data + 5) = 0x0a;
	*(data + 6) = 0x5a;
	*(data + 7) = 0x78;
	*(data + 8) = 0xa0;
	*(data + 9) = 0xb1;
	*(data + 10) = 0x65;
	*(data + 11) = 0x33;
	*(data + 12) = 0xa6;
	*(data + 13) = 0x21;
	*(data + 14) = 0x3c;
	*(data + 15) = 0xab;

	uint8_t* key = (uint8_t*)malloc(sizeof(uint8_t)*16);
	*(key + 0) = 0x77;
	*(key + 1) = 0xbe;
	*(key + 2) = 0x63;
	*(key + 3) = 0x70;
	*(key + 4) = 0x89;
	*(key + 5) = 0x71;
	*(key + 6) = 0xc4;
	*(key + 7) = 0xe2;
	*(key + 8) = 0x40;
	*(key + 9) = 0xd1;
	*(key + 10) = 0xcb;
	*(key + 11) = 0x79;
	*(key + 12) = 0xe8;
	*(key + 13) = 0xd7;
	*(key + 14) = 0x7f;
	*(key + 15) = 0xeb;

	uint8_t* iv = (uint8_t*)malloc(sizeof(uint8_t)*12);
	*(iv + 0) = 0xe0;
	*(iv + 1) = 0xe0;
	*(iv + 2) = 0x0f;
	*(iv + 3) = 0x19;
	*(iv + 4) = 0xfe;
	*(iv + 5) = 0xd7;
	*(iv + 6) = 0xba;
	*(iv + 7) = 0x01;
	*(iv + 8) = 0x36;
	*(iv + 9) = 0xa7;
	*(iv + 10) = 0x97;
	*(iv + 11) = 0xf3;

	struct timespec start, end;
  	clock_gettime(CLOCK_MONOTONIC, &start);




	//hmac_SHA256_80("what do ya want for nothing?","Jefe",sizeof("what do ya want for nothing?")-1, sizeof("Jefe")-1,dest);
  	//sleep(2);
	gmac_AES256_64(data, key, iv, 16, 12, dest);

	clock_gettime(CLOCK_MONOTONIC, &end);

	printf("Calculated tag:\n  ");
    for(int i = 0; i < 16; i++)
    {
        printf("%02x", dest[i]);
       
        if(i == 16 - 1) {
            printf("\n");
        }
    }
   
  	uint64_t timeElapsed = timespecDiff(&end, &start);

  	long seconds = end.tv_sec - start.tv_sec;
  	long ns = end.tv_nsec - start.tv_nsec;

  	printf("total secs: %lf\n",(double)seconds + (double)ns/(double)1000000000);


  	printf("time: %d\n",timeElapsed);

	for(int j = 0; j<16; j++){
		printf("%02x",dest[j]);
	}

	printf("\n");

}