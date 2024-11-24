#include<stdio.h>
#include<malloc.h>
#include<openssl\rsa.h>
#include<openssl\pem.h>
#include<openssl\applink.c>

int main() {

	RSA* rsa_keypair;

	unsigned char SHA1[] = {0x2B, 0xA1, 0x7C, 0xE4, 0xAF, 0xD6, 0xCB, 0x94, 0xA2, 0xCD,
							0xC0, 0xDA, 0x23, 0x72, 0x97, 0x75, 0xBF, 0x5C, 0x2F, 0xD8};
	//SHA1 = 2B  A1  7C  E4  AF  D6  CB  94  A2  CD  C0  DA  23  72  97  75  BF  5C  2F  D8  

	FILE* fPrivate = fopen("RSAPrivateKey.pem", "r");
	//PEM_read_RSAPrivateKey(fPrivate,&rsa_keypair,NULL,NULL);
	rsa_keypair = PEM_read_RSAPrivateKey(fPrivate, NULL, NULL, NULL);

	int rsa_size = RSA_size(rsa_keypair);
	unsigned char* rsa_signature = (unsigned char*)malloc(rsa_size);
	// the signature is generated after the encryption in rsa_signature

	RSA_private_encrypt(sizeof(SHA1),SHA1,rsa_signature,rsa_keypair,RSA_PKCS1_PADDING);
	FILE* fSign = fopen("signature.sig","wb+");
	fwrite(rsa_signature, rsa_size, 1, fSign);


	fclose(fSign);
	free(rsa_signature);
	RSA_free(rsa_keypair);
	fclose(fPrivate);

	return 0;
}