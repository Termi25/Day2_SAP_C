#include<stdio.h>
#include<string.h>
#include<malloc.h>
#include<openssl\aes.h>

int main() {
	printf("AES in CBC mode with 128bit key and Initialisation Vector:\n");
	printf("----------------------------------------------------------\n");
	unsigned char plaintext[] = { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
							  0x11,0x02,0x03,0x04,0x55,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
							  0x21,0x02,0x03,0x04,0x65,0x06,0x07,0x08,0x09,0xAA,0x0B,0x0C,0xDD,0x0E,0x0F,
							  0x01,0x02,0x03,0x04,0x75,0x06,0x07,0x08,0x09,0xBA,0x0B,0x0C,0xDD,0x0E };

	unsigned char key_128[] = { 0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x99,0x88,0x1a,0x2b,0x3c,0x4d,0x5e,0x6f,0x9a,0x8b };

	unsigned char IV[] = { 0xa1,0xb2,0xc3,0xd4,0xe5,0xf6,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff };

	unsigned char* ciphertext = NULL;
	unsigned int totalBlockSize = (unsigned int)(sizeof(plaintext) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
	if (sizeof(plaintext) % AES_BLOCK_SIZE != 0) {
		totalBlockSize += AES_BLOCK_SIZE;
	}
	ciphertext = (unsigned char*)malloc(totalBlockSize);

	printf("\nPlaintext = ");
	for (unsigned int i = 0;i < sizeof(plaintext);i++) {
		printf("%02X ", plaintext[i]);
	}
	printf("\n");

	printf("\nKey = ");
	for (unsigned int i = 0;i < sizeof(key_128);i++) {
		printf("%02X ", key_128[i]);
	}
	printf("\n");

	printf("\nIV = ");
	for (unsigned int i = 0;i < sizeof(IV);i++) {
		printf("%02X ", IV[i]);
	}
	printf("\n");

	printf("----------------------------------------------------------\n");

	AES_KEY aes_key;
	AES_set_encrypt_key(key_128, sizeof(key_128)*8, &aes_key);

	AES_cbc_encrypt(plaintext, ciphertext, sizeof(plaintext), &aes_key, IV, AES_ENCRYPT);

	printf("\nCiphertext = ");
	for (unsigned int i = 0;i < totalBlockSize;i++) {
		printf("%02X ", ciphertext[i]);
	}
	printf("\n");

	unsigned char* restoredtext = NULL;
	restoredtext = (unsigned char*)malloc(sizeof(plaintext));

	unsigned char IV2[] = {0xa1,0xb2,0xc3,0xd4,0xe5,0xf6,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff}; 
	//the original IV value is modified by the aes cbc encryption function, which invalidates the decryption

	AES_set_decrypt_key(key_128, sizeof(key_128) * 8, &aes_key);
	AES_cbc_encrypt(ciphertext, restoredtext, sizeof(plaintext), &aes_key, IV2, AES_DECRYPT);

	printf("\nRestoredtext = ");
	for (unsigned int i = 0;i < sizeof(plaintext);i++) {
		printf("%02X ", restoredtext[i]);
	}
	printf("\n");

	if(memcmp(plaintext, restoredtext, sizeof(plaintext))==0) {
		printf("\nEncryption and decryption work.\n");
	}
	else {
		printf("\nEncryption and decryption don't work.\n");
	}

	free(restoredtext);
	free(ciphertext);
	return 0;
}