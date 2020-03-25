CC = gcc
CFLAGS = -Wall

sec: main.c ../../../R-GOOSE_SecLib_1_0_0/src/hmac_functions.c ../../../R-GOOSE_SecLib_1_0_0/src/gmac_functions.c
	$(CC) $(CFLAGS) -o a.out main.c ../../../R-GOOSE_SecLib_1_0_0/src/hmac_functions.c ../../../R-GOOSE_SecLib_1_0_0/src/gmac_functions.c -I../../../R-GOOSE_SecLib_1_0_0/src/ -lssl -lcrypto