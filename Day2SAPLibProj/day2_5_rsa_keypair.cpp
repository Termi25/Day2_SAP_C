#include<stdio.h>
#include<malloc.h>
#include<openssl\rsa.h>
#include<openssl\pem.h>
#include<openssl\applink.c>

int main() {

	RSA* rsa_keypair;
	rsa_keypair = RSA_generate_key(1024,65535,NULL,NULL);
	//don't forget to deallocate with "RSA_free(rsa_keypair);" before "return 0;"

	//RSA_check_key(rsa_keypair);

	//Generating private key file
	FILE* fprivate = fopen("RSAPrivateKey.pem", "wb");
	PEM_write_RSAPrivateKey(fprivate, rsa_keypair, NULL, NULL, 0, NULL, NULL);

	//Generating private key file
	FILE* fpublic = fopen("RSAPublicKey.pem", "wb");
	PEM_write_RSAPublicKey(fpublic, rsa_keypair);

	RSA_free(rsa_keypair);
	fclose(fprivate);
	fclose(fpublic);

	return 0;
}