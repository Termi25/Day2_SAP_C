#include<stdio.h>
#include<openssl/md5.h>

int main() {
	printf("%d", MD5_DIGEST_LENGTH);
	return 0;
}