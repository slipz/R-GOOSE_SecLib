/* 
	Example file: 

		R-GOOSE Message Authentication (HMAC) - Usage of function
			r_gooseMessage_InsertHMAC()

*/

#include "r_goose_security.h"

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

	FILE *fp;
	unsigned char *buffer;
	long filelen;

	char* filename = "packet";

	fp = fopen(filename, "rb");

	fseek(fp, 0, SEEK_END);

	filelen = ftell(fp);
	rewind(fp);

	buffer = (unsigned char*) malloc(filelen*sizeof(char));
	
	fread(buffer, filelen, 1, fp);
	fclose(fp);

	printf("%d\n",filelen);

	printf("buffer:\n  ");
    for(int i = 0; i < filelen; i++){
        printf("%02X ", buffer[i]);
    }
    printf("\n\n");

	int key_size = 20;

	struct timespec start, end;
  	clock_gettime(CLOCK_MONOTONIC, &start);

  	r_gooseMessage_InsertGMAC(buffer, key, key_size, GMAC_AES256_64);

	clock_gettime(CLOCK_MONOTONIC, &end);

	printf("buffer:\n  ");
    for(int i = 0; i < filelen+MAC_SIZES[GMAC_AES256_64]; i++){
        printf("%02X ", buffer[i]);
    }
	printf("\n");

	//buffer[INDEX_SPDU_LENGTH+20] = 0x99;

	r_gooseMessage_ValidateGMAC(buffer, key, key_size);


	uint64_t timeElapsed = timespecDiff(&end, &start);

  	long seconds = end.tv_sec - start.tv_sec;
  	long ns = end.tv_nsec - start.tv_nsec;

  	printf("total secs: %lf\n",(double)seconds + (double)ns/(double)1000000000);

}