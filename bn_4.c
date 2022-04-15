/* bn_4.c */
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
  	BIGNUM *encode1 = BN_new();
	BIGNUM *encode2 = BN_new();
	BIGNUM *mod = BN_new();
	BIGNUM *message1 = BN_new();
	BIGNUM *message2 = BN_new();
	BIGNUM *decode1 = BN_new();
	BIGNUM *decode2 = BN_new();

	BN_hex2bn(&private_key, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
	BN_hex2bn(&public_key, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	BN_hex2bn(&mod, "010001");
	BN_hex2bn(&message1, "49206f776520796f752024323030302e");
	printBN("I owe you $2000.-Message: ", message1);
	BN_hex2bn(&message2, "49206f776520796f752024333030302e");
	printBN("I owe you $3000.-Message: ", message2);
	
	BN_mod_exp(encode1, message1, private_key, public_key, ctx);
	printBN("I owe you $2000.-Signature: ", encode1);
	BN_mod_exp(encode2, message2, private_key, public_key, ctx);
	printBN("I owe you $3000.-Signature: ", encode2);

	BN_mod_exp(decode1, encode1, mod, public_key, ctx);
	printBN("I owe you $2000.-Decrypted: ", decode1);
	BN_mod_exp(decode2, encode2, mod, public_key, ctx);
	printBN("I owe you $3000.-Decrypted: ", decode2);
	

  return 0;
}
