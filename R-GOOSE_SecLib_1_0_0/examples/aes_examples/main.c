/* 
	Example file: 
	
		GMAC-AES128-128 usage 

*/

#include "gmac_functions.h"
#include "aes_crypto.h"

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
	uint8_t* dest1 = NULL;

	char keyHex[] = "219bcef0cd0f89a5e1297b99d956150f3128459f65312fdd71618f1177393e3f";
	uint8_t* key = hexStringToBytes(keyHex, 64);

	char dataHex[] = "341841a174536a24866b0fd0bf03f3f1ecb247b3e8f5707ea244c85611adfdd26289e30be322a647d5f465e4aa145caa67ccec";
	uint8_t* data = hexStringToBytes(dataHex, 102);
  int data_size = 51;

  //char dataHex[] = "341841a174536a24866b0fd0bf03f3f1ecb247b3e8f5707ea244c85611adfdd26289e30be322a647d5f465e4aa145caa67ccec341841a174536a24866b0fd0bf03f3f1ecb247b3e8f5707ea244c85611adfdd26289e30be322a647d5f465e4aa145caa67ccec";
  //uint8_t* data = hexStringToBytes(dataHex, 204);
  //int data_size = 102;

  //char dataHex[] = "341841a174536a24866b0fd0bf03f3f1ecb247b3e8f5707ea244c85611adfdd26289e30be322a647d5f465e4aa145caa67ccec341841a174536a24866b0fd0bf03f3f1ecb247b3e8f5707ea244c85611adfdd26289e30be322a647d5f465e4aa145caa67ccec341841a174536a24866b0fd0bf03f3f1ecb247b3e8f5707ea244c85611adfdd26289e30be322a647d5f465e4aa145caa67ccec341841a174536a24866b0fd0bf03f3f1ecb247b3e8f5707ea244c85611adfdd26289e30be322a647d5f465e4aa145caa67ccec341841a174536a24866b0fd0bf03f3f1ecb247b3e8f5707ea244c85611adfdd26289e30be322a647d5f465e4aa145caa67ccec341841a174536a24866b0fd0bf03f3f1ecb247b3e8f5707ea244c85611adfdd26289e30be322a647d5f465e4aa145caa67ccec341841a174536a24866b0fd0bf03f3f1ecb247b3e8f5707ea244c85611adfdd26289e30be322a647d5f465e4aa145caa67ccec341841a174536a24866b0fd0bf03f3f1ecb247b3e8f5707ea244c85611adfdd26289e30be322a647d5f465e4aa145caa67ccec";
  //uint8_t* data = hexStringToBytes(dataHex, 816);
  //int data_size = 408;

	char ivHex[] = "75b66d3df73da95345c11a32";
	uint8_t* iv = hexStringToBytes(ivHex,24);

	int iv_size = 12;

	struct timespec start, end;
  	clock_gettime(CLOCK_MONOTONIC, &start);

	//gmac_AES128_128(data, key, iv, data_size, iv_size, &dest);

  	printf("Plaintext:\n  ");
    for(int i = 0; i < data_size; i++){
        printf("%02x", data[i]);
    }
    printf("\n");

  	int len = aes_256_gcm_encrypt(data, key, iv, data_size, iv_size, &dest);

  	printf("Plaintext:\n  ");
    for(int i = 0; i < data_size; i++){
        printf("%02x", dest[i]);
    }
    printf("\n");

  	int ret1 = aes_256_gcm_decrypt(dest, key, iv, data_size, iv_size, &dest1);

  	printf("Plaintext:\n  ");
    for(int i = 0; i < data_size; i++){
        printf("%02x", dest1[i]);
    }
    printf("\n");

	clock_gettime(CLOCK_MONOTONIC, &end);

	uint64_t timeElapsed = timespecDiff(&end, &start);

  	long seconds = end.tv_sec - start.tv_sec;
  	long ns = end.tv_nsec - start.tv_nsec;

  	printf("total secs: %lf\n",(double)seconds + (double)ns/(double)1000000000);



    free(key);
    free(data);
    free(iv);
    if(dest != NULL){
      free(dest);
    }
    if(dest1 != NULL){
      free(dest1);
    }
}