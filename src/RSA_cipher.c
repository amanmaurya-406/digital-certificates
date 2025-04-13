#include "RSA_cipher.h"

void RSA_private_encrypt(mpz_t signature, mpz_t hash, mpz_t priv_exp, mpz_t mod){  
    mpz_powm(signature, hash, priv_exp, mod);   
}

void RSA_public_decrypt(mpz_t hash, mpz_t signature, mpz_t pub_key, mpz_t mod){
    mpz_powm(hash, signature, pub_key, mod);
}