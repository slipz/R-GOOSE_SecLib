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

void test(){

	char keyHex[] = "11754cd72aec309bf52f7687212e8957";
	uint8_t* key = hexStringToBytes(keyHex, 32);

	FILE *fp;
	unsigned char *buffer;
	long filelen;

	char* filename = "../resources/valid_large.pkt";

	fp = fopen(filename, "rb");

	fseek(fp, 0, SEEK_END);

	filelen = ftell(fp);
	rewind(fp);

	buffer = (unsigned char*) malloc(filelen*sizeof(char));

	uint8_t* dest = NULL;
	
	fread(buffer, filelen, 1, fp);
	fclose(fp);

	int key_size = 16;

	//r_goose_dissect(buffer);

	struct timespec start, end;
  	

  	//int res1 = r_gooseMessage_InsertGMAC(buffer, key, key_size, GMAC_AES128_128, &dest);
  	int res1 = r_gooseMessage_InsertHMAC(buffer, key, key_size, HMAC_SHA256_80, &dest);

  	
  	if(res1 == 1){
  		free(buffer);
  		buffer = dest;
  	}

	
  	clock_gettime(CLOCK_MONOTONIC, &start);
  	int res;
	
	res = r_gooseMessage_ValidateHMAC(buffer, key, key_size);

	
	clock_gettime(CLOCK_MONOTONIC, &end);


	uint64_t timeElapsed = timespecDiff(&end, &start);

  	long seconds = end.tv_sec - start.tv_sec;
  	long ns = end.tv_nsec - start.tv_nsec;

  	printf("%lf\n",(double)seconds + (double)ns/(double)1000000000);


	free(key);
	free(buffer);
}


int main(int argc, char** argv){
	for(int i = 0; i<500; i++){
		test();
	}
	
}


//gcc -Wall -g main.c ../../../R-GOOSE_SecLib_1_0_0/src/hmac_functions.c ../../../R-GOOSE_SecLib_1_0_0/src/gmac_functions.c ../../../R-GOOSE_SecLib_1_0_0/src/r_goose_security.c ../../../R-GOOSE_SecLib_1_0_0/src/aux_funcs.c ../../../R-GOOSE_SecLib_1_0_0/src/aes_crypto.c -I../../../R-GOOSE_SecLib_1_0_0/src/ -lssl -lcrypto