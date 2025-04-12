#ifndef RSA_CIPHER_H
#define RSA_CIPHER_H

#include <gmp.h>

void RSA_private_encrypt(mpz_t dest, mpz_t base, mpz_t priv_exp, mpz_t mod);
void RSA_public_decrypt(mpz_t dest, mpz_t base, mpz_t pub_exp, mpz_t mod);

#endif