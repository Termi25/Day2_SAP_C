#include<stdio.h>
#include<string.h>
#include<malloc.h>
#include<openssl\aes.h>

//TO-DO: switch to binary and text files for key, plaintext and ciphertext
//TO-DO: update implementation for key_192 and key_256
int main() {
	unsigned char plaintext[] = { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
							  0x11,0x02,0x03,0x04,0x55,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
							  0x21,0x02,0x03,0x04,0x65,0x06,0x07,0x08,0x09,0xAA,0x0B,0x0C,0xDD,0x0E,0x0F,
							  0x01,0x02,0x03,0x04,0x75,0x06,0x07,0x08,0x09,0xBA,0x0B,0x0C,0xDD,0x0E };

	printf("\nPlaintext= ");
	for (unsigned int i = 0;i < sizeof(plaintext);i++) {
		printf("%02X ", plaintext[i]);
	}
	printf("\n");

	unsigned char key_128[] = { 0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x99,0x88,0x1a,0x2b,0x3c,0x4d,0x5e,0x6f,0x9a,0x8b };

	unsigned char* ciphertext; //size of block aligned to AES data block (16 byte * 4 blocks from plaintext)
	unsigned int totalBlockSize =(unsigned int) (sizeof(plaintext) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
	if (sizeof(plaintext) % AES_BLOCK_SIZE != 0) {
		totalBlockSize += AES_BLOCK_SIZE;
	}
	ciphertext = (unsigned char*)malloc(totalBlockSize);
	
	AES_KEY aes_key;

	//AES ECB ENCRYPTION
	AES_set_encrypt_key(key_128, (sizeof(key_128)*8), &aes_key);

	for (unsigned int plain_block_offset = 0; plain_block_offset < sizeof(plaintext); plain_block_offset += AES_BLOCK_SIZE) {
		AES_encrypt(plaintext + plain_block_offset, (ciphertext + plain_block_offset), &aes_key);
	}
	
	printf("\nAES ciphertext= ");
	for (unsigned int i = 0;i < totalBlockSize;i++) {
		printf("%02X ",ciphertext[i]);
	}
	printf("\n");

	//AES_ECB_DECRYPTION
	unsigned char* decryptedtext; //size of block aligned to AES data block (16 byte * 4 blocks from plaintext)
	decryptedtext = (unsigned char*)malloc(sizeof(plaintext));

	AES_set_decrypt_key(key_128,(sizeof(key_128)*8),&aes_key);

	for (unsigned int plain_block_offset = 0; plain_block_offset < totalBlockSize-AES_BLOCK_SIZE; plain_block_offset += AES_BLOCK_SIZE) {
		AES_decrypt(ciphertext + plain_block_offset, (decryptedtext + plain_block_offset), &aes_key);
	}
	unsigned char buffer[AES_BLOCK_SIZE];
	AES_decrypt(ciphertext + totalBlockSize-AES_BLOCK_SIZE, buffer, &aes_key);
	for (int i = 0;i < sizeof(plaintext) - (totalBlockSize - AES_BLOCK_SIZE);i++) {
		decryptedtext[totalBlockSize - AES_BLOCK_SIZE + i] = buffer[i];
	}

	printf("\nRestoredtext= ");
	for (unsigned int i = 0;i < sizeof(plaintext);i++) {
		printf("%02X ", decryptedtext[i]);
	}
	printf("\n");

	printf("\n");
	if (memcmp(plaintext, decryptedtext, sizeof(plaintext))==0) {
		printf("Plaintext and Restoredtext are the same.");
	}
	else {
		printf("Plaintext and Restoredtext are different.");
	}
	printf("\n");

	free(decryptedtext);
	free(ciphertext);

	return 0;
}