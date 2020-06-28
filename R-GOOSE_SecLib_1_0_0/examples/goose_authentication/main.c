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

	// Key Set-up
	char keyHex[] = "11754cd72aec309bf52f7687212e8957";
	uint8_t* key = hexStringToBytes(keyHex, 32);
	int key_size = 16;

	// R-GOOSE Packet Set-up 		-- START --
	FILE *fp;
	unsigned char *buffer;
	long filelen;

	char* filename = "valid_small.pkt";

	fp = fopen(filename, "rb");

	fseek(fp, 0, SEEK_END);

	filelen = ftell(fp);
	rewind(fp);

	buffer = (unsigned char*) malloc(filelen*sizeof(char));

	uint8_t* dest = NULL;
	
	fread(buffer, filelen, 1, fp);
	fclose(fp);
	// R-GOOSE Packet Set-up 		-- END --

    r_goose_dissect(buffer);

	struct timespec start, end;
  	clock_gettime(CLOCK_MONOTONIC, &start);


  	// InsertHMAC USAGE 			-- START --

  	int res1 = r_gooseMessage_InsertHMAC(buffer, key, key_size, HMAC_SHA256_80, &dest);
  	//int res1 = r_gooseMessage_InsertHMAC(buffer, key, key_size, HMAC_SHA256_80, &dest);

  	// InsertHMAC USAGE 			-- END --
  	clock_gettime(CLOCK_MONOTONIC, &end);


  	// Clean Up 					-- IMPORTANT -- 
  	if(res1 == 1){
  		free(buffer);
  		buffer = dest;
  	}


	uint64_t timeElapsed = timespecDiff(&end, &start);

  	long seconds = end.tv_sec - start.tv_sec;
  	long ns = end.tv_nsec - start.tv_nsec;

  	printf("InsertHMAC total secs: %lf\n",(double)seconds + (double)ns/(double)1000000000);

	buffer[110] = 0x99;
	
	r_goose_dissect(buffer);


	int res;

	if((res = r_gooseMessage_ValidateHMAC(buffer, key, key_size)) == 1){
		printf("Tag is valid.\n");
	}else if(res == 2){
		printf("Packet without Authentication Tag\n");
	}else{
		printf("Invalid Tag/Packet\n");
	}

	/*if((res = r_gooseMessage_ValidateHMAC(buffer, key, key_size)) == 1){
		printf("Tag is valid.\n");
	}else if(res == 2){
		printf("Packet without Authentication Tag\n");
	}else{
		printf("Invalid Tag/Packet\n");
	}*/


	// Clean Up 					-- IMPORTANT -- 
	free(key);
	free(buffer);

}
