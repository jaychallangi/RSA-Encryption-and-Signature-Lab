/* bn_1.c */
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
	BIGNUM *p = BN_new();
	BIGNUM *q = BN_new();
	BIGNUM *e = BN_new();
	BIGNUM *temp_p = BN_new();
	BIGNUM *temp_q = BN_new();
	BIGNUM *one = BN_new();
	BIGNUM *trix = BN_new();
	
	BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
	BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
	BN_hex2bn(&e, "0D88C3");
	BN_dec2bn(&one, "1");
	
	BN_sub(temp_p, p, one);
	BN_sub(temp_q, q, one);
	BN_mul(trix, temp_p, temp_q, ctx);

	BIGNUM* res = BN_new();
	BN_mod_inverse(res, e, trix, ctx);
	BN_CTX_free(ctx);
	printBN("Private Key:", res);
  return 0;
}
