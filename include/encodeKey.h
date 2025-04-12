#ifndef ENCODE_KEY_H
#define ENCODE_KEY_H

#include "config.h"


// WRITING AND READING KEYS IN PKCS#1
void write_privateKey_der(const char *filename, mpz_t modulus, mpz_t pub_exp, mpz_t priv_exp, mpz_t prime1, mpz_t prime2, mpz_t p_1, mpz_t q_1);
void write_privateKey_pem(const char *filename, mpz_t modulus, mpz_t pub_exp, mpz_t priv_exp, mpz_t prime1, mpz_t prime2, mpz_t p_1, mpz_t q_1);

PrivateKey *load_privateKey(const char *filename);
PublicKey *load_publicBytes(const char *filename);
PublicKey *extract_publicBytes(PrivateKey *privateKey);
void free_privateKey(PrivateKey *privateKey);
void free_publicKey(PublicKey *publicKey);

#endif