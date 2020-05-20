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

char *randstring(size_t length) {

    static char charset[] = "abcdef0123456789";        
    char *randomString = NULL;

    if (length) {
        randomString = malloc(sizeof(char) * (length +1));

        if (randomString) {            
            for (int n = 0;n < length;n++) {            
                int key = rand() % (int)(sizeof(charset) -1);
                randomString[n] = charset[key];
            }

            randomString[length] = '\0';
        }
    }

    return randomString;
}

int64_t timespecDiff(struct timespec *timeA_p, struct timespec *timeB_p)
{
  return ((timeA_p->tv_sec * 1000000000) + timeA_p->tv_nsec) -
           ((timeB_p->tv_sec * 1000000000) + timeB_p->tv_nsec);
}
void test(){

	uint8_t* dest = NULL;
	uint8_t* dest1 = NULL;

	char keyHex[] = "219bcef0cd0f89a5e1297b99d956150f3128459f65312fdd71618f1177393e3f";
	uint8_t* key = hexStringToBytes(keyHex, 64);

	/*char* dataHex = randstring(102);
	uint8_t* data = hexStringToBytes(dataHex, 102);
  int data_size = 51;*/

  char* dataHex = randstring(408);
  uint8_t* data = hexStringToBytes(dataHex, 408);
  int data_size = 204;

/*  char* dataHex = randstring(816);
  uint8_t* data = hexStringToBytes(dataHex, 816);
  int data_size = 408;
*/
	char ivHex[] = "75b66d3df73da95345c11a32";
	uint8_t* iv = hexStringToBytes(ivHex,24);

	int iv_size = 12;

	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);


	//int len = aes_256_gcm_encrypt(data, key, iv, data_size, iv_size, &dest);

	int ret1 = aes_128_gcm_decrypt(data, key, iv, data_size, iv_size, &dest1);

	clock_gettime(CLOCK_MONOTONIC, &end);

	if(ret1 == -1){
		printf("error\n");
	}

	uint64_t timeElapsed = timespecDiff(&end, &start);

	long seconds = end.tv_sec - start.tv_sec;
	long ns = end.tv_nsec - start.tv_nsec;

	printf("%lf\n",(double)seconds + (double)ns/(double)1000000000);



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


int main(int argc, char** argv){
  for(int i=0; i<1000; i++){
    test();
  }
}


