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
	
	fread(buffer, filelen, 1, fp);
	fclose(fp);

	int key_size = 16;


	

  	//r_gooseMessage_InsertGMAC(buffer, key, key_size, GMAC_AES128_128);
  	r_gooseMessage_InsertHMAC(buffer, key, key_size, HMAC_SHA256_80);
	
	struct timespec start, end;
  	clock_gettime(CLOCK_MONOTONIC, &start);

  	int res;
	//r_gooseMessage_ValidateGMAC(buffer, key, key_size)
	if((res = r_gooseMessage_ValidateHMAC(buffer, key, key_size)) == 1){
		printf("Tag is valid.\n");
	}else if(res == 2){
		printf("Packet without Authentication Tag\n");
	}else{
		printf("Invalid Tag/Packet\n");
	}


	clock_gettime(CLOCK_MONOTONIC, &end);

	uint64_t timeElapsed = timespecDiff(&end, &start);

  	long seconds = end.tv_sec - start.tv_sec;
  	long ns = end.tv_nsec - start.tv_nsec;

  	double ola = ((double)seconds + (double)ns/(double)1000000000);

	printf("%lf\n",ola);

	//r_goose_dissect(buffer);

	free(buffer);


}


int main(int argc, char** argv){
	for(int i = 0; i<500; i++){
		test();
	}
	
}