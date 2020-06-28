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

	// Key and IV Set up
	char keyHex[] = "219bcef0cd0f89a5e1297b99d956150f3128459f65312fdd71618f1177393e3f";
	uint8_t* key = hexStringToBytes(keyHex, 64);

	char ivHex[] = "75b66d3df73da95345c11a32";
	uint8_t* iv = hexStringToBytes(ivHex,24);

	int iv_size = 12;


	// R-GOOSE Packet Set Up
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

//r_goose_dissect(buffer);
	// R-GOOSE Encrypt Usage

	struct timespec start, end;
  	clock_gettime(CLOCK_MONOTONIC, &start);

  	int res = r_gooseMessage_Encrypt(buffer, key, AES_128_GCM, 1, 1, 1, iv, iv_size);


	clock_gettime(CLOCK_MONOTONIC, &end);
	
	//r_goose_dissect(buffer);

  	long seconds = end.tv_sec - start.tv_sec;
  	long ns = end.tv_nsec - start.tv_nsec;

  	printf("%lf\n",(double)seconds + (double)ns/(double)1000000000);

  	free(key);
  	free(iv);
  	free(buffer);

}


int main(int argc, char** argv){

	for(int i=0; i<500000; i++){
		test();
	}

}
