/* bn_5.c */
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
	BIGNUM *mod = BN_new();
	BIGNUM *message = BN_new();
	BIGNUM *S = BN_new();
	BIGNUM *corrupt = BN_new();
	BIGNUM *decode1 = BN_new();
	BIGNUM *decode2 = BN_new();

	BN_hex2bn(&public_key, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
	BN_hex2bn(&mod, "010001");
	BN_hex2bn(&message, "4c61756e63682061206d697373696c652e");
	printBN("Original Message: ", message);
	BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
	BN_hex2bn(&corrupt, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
	
	BN_mod_exp(decode1, S, mod, public_key, ctx);
	printBN("From Alice's Signiture (S): ", decode1);	
	
	BN_mod_exp(decode2, corrupt, mod, public_key, ctx);
	printBN("From Corrupted Signiture: ", decode2);
  return 0;
}
