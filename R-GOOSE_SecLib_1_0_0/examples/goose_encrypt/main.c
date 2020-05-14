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

	char keyHex[] = "219bcef0cd0f89a5e1297b99d956150f3128459f65312fdd71618f1177393e3f";
	uint8_t* key = hexStringToBytes(keyHex, 64);

	char ivHex[] = "75b66d3df73da95345c11a32";
	uint8_t* iv = hexStringToBytes(ivHex,24);

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

    r_goose_dissect(buffer);

	int key_size = 20, iv_size = 12;

	struct timespec start, end;
  	clock_gettime(CLOCK_MONOTONIC, &start);

  	//r_gooseMessage_InsertGMAC(buffer, key, key_size, GMAC_AES256_64);

  	r_gooseMessage_Encrypt(buffer, key, 1, 1, 1, 1, iv, iv_size);


	clock_gettime(CLOCK_MONOTONIC, &end);

	printf("buffer:\n  ");
    for(int i = 0; i < filelen; i++){
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