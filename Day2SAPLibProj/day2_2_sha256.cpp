#include<stdio.h>
#include<malloc.h>
#include<stdlib.h>
#include<openssl/sha.h>
using namespace std;

#define INPUT_BLOCK_LENGTH 15 

int main() {
	FILE* inputFile = NULL;
	errno_t err;

	err = fopen_s(&inputFile, "input_SHA1.txt", "rb");
	if (err == 0) {
		SHA256_CTX ctx;
		SHA256_Init(&ctx);

		fseek(inputFile, 0, SEEK_END);
		unsigned int lenFile = ftell(inputFile);
		fseek(inputFile, 0, SEEK_SET);

		unsigned char* input = (unsigned char*)malloc(INPUT_BLOCK_LENGTH);

		unsigned char inputLength = lenFile; // total length of byteArray input
		unsigned char remainingLength = inputLength;

		printf("Original byte array to be encoded:\n\n");
		while (remainingLength > 0) {

			printf("\t");
			unsigned char hex_pair[2];
			if (remainingLength > INPUT_BLOCK_LENGTH * 2) //due to each txt hex value has 2 bytes, instead of 1
			{
				//sha1 update done for 15-byte input
				for (unsigned int i = 0; i < INPUT_BLOCK_LENGTH; i++) {
					fread(hex_pair, sizeof(unsigned char), 2 * sizeof(unsigned char), inputFile); //read 2 bytes from txt file coresponding to 1 single hex-pair
					input[i] = (unsigned char)strtol((const char*)hex_pair, NULL, 16);
					printf("%02X ", input[i]);
				}

				SHA256_Update(&ctx, input, INPUT_BLOCK_LENGTH);
				remainingLength -= (INPUT_BLOCK_LENGTH * 2);
			}
			else {
				//sha1 update done for less than 15 bytes
				for (unsigned int i = 0; i < (unsigned char)(remainingLength / 2); i++) {
					fread(hex_pair, sizeof(unsigned char), 2 * sizeof(unsigned char), inputFile); //read 2 bytes from txt file coresponding to 1 single hex-pair
					input[i] = (unsigned char)strtol((const char*)hex_pair, NULL, 16);
					printf("%02X ", input[i]);
				}
				SHA256_Update(&ctx, input, remainingLength / 2);
				remainingLength = 0; //instruction for exiting from the while
			}
			printf("\n");
		}

		unsigned char finalDigest[SHA256_DIGEST_LENGTH];
		SHA256_Final(finalDigest, &ctx); //this call also returns a int value for error codes

		printf("\n\nSHA1 = ");
		for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
			printf("%02X ", finalDigest[i]);
			printf(" ");
		}
		printf(" \n\n");

		FILE* outputFile = NULL;
		err = fopen_s(&outputFile, "outputFile.txt", "w+");
		if (err == 0) {
			fprintf(outputFile, "\nSHA1 = ");
			for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
				fprintf(outputFile, "%02X ", finalDigest[i]);
				fprintf(outputFile, " ");
			}
			fclose(outputFile);
		}

		fclose(inputFile);
	}
	return 0;
}