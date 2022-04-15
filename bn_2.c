/* bn_2.c */
#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 256

void printBN(char *msg, BIGNUM * a)
{
   /* Use BN_bn2hex(a) for hex string
    * Use BN_bn2dec(a) for decimal string */
   char * number_str = BN_bn2hex(a);
   printf("%s %s\n", msg, number_str);
   OPENSSL_free(number_str);
}

int main ()
{	
	BN_CTX *ctx = BN_CTX_new();								
	BIGNUM *private_key = BN_new();
	BIGNUM *public_key = BN_new();
  	BIGNUM *encode = BN_new();
	BIGNUM *decode = BN_new();
	BIGNUM *mod = BN_new();
	BIGNUM *message = BN_new();

	BN_hex2bn(&private_key, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
	BN_hex2bn(&public_key, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	printBN("Public Key: ", public_key);
	BN_hex2bn(&mod, "010001");
	BN_hex2bn(&message, "4120746f702073656372657421");
	printBN("Message: ", message);

	BN_mod_exp(encode, message, mod, public_key, ctx);
	printBN("Encrypted Message: ", encode);
	BN_mod_exp(decode, encode, private_key, public_key, ctx);
	printBN("Decrypted Message: ", decode);

  return 0;
}
