#include<stdio.h>
#include<string.h>
#include<malloc.h>
#include<openssl\rsa.h>
#include<openssl\pem.h>
#include<openssl\applink.c>

int main() {

	RSA* rsa_keypair;

	unsigned char SHA1[] = { 0x2B, 0xA1, 0x7C, 0xE4, 0xAF, 0xD6, 0xCB, 0x94, 0xA2, 0xCD,
							0xC0, 0xDA, 0x23, 0x72, 0x97, 0x75, 0xBF, 0x5C, 0x2F, 0xD8 };
	//SHA1 = 2B  A1  7C  E4  AF  D6  CB  94  A2  CD  C0  DA  23  72  97  75  BF  5C  2F  D8  

	FILE* fPrivate = fopen("RSAPublicKey.pem", "r");
	rsa_keypair = PEM_read_RSAPublicKey(fPrivate, NULL, NULL, NULL);

	FILE* fSign = fopen("signature.sig", "rb");
	fseek(fSign, 0, SEEK_END);
	unsigned int sign_length = ftell(fSign);
	fseek(fSign, 0, SEEK_SET);
	
	unsigned char* rsa_signature = (unsigned char*)malloc(sign_length);
	fread(rsa_signature, sign_length, 1, fSign);

	unsigned char md_sha1[20];

	RSA_public_decrypt(sign_length, rsa_signature, md_sha1, rsa_keypair, RSA_PKCS1_PADDING);

	if (memcmp(SHA1, md_sha1, sizeof(md_sha1))==0) {
		printf("\n Message is valid.\n");
	}
	else {
		printf("\nInvalid signature!\n");
	}

	fclose(fSign);
	free(rsa_signature);
	RSA_free(rsa_keypair);
	fclose(fPrivate);

	return 0;
}