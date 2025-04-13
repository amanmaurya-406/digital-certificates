#include <stdio.h>
#include <gmp.h>
#include <time.h>
#include "utils.h"
#include "encodeKey.h"
#include "RSA_generateKey.h"


static void generate_prime(mpz_t prime, unsigned int bit_size, gmp_randstate_t state){
    mpz_t random_num;
    mpz_init(random_num);

    mpz_urandomb(random_num, state, bit_size);
    mpz_setbit(random_num, bit_size - 1);

    mpz_nextprime(prime, random_num);

    mpz_clear(random_num);
}

static void initialize_random_state(gmp_randstate_t state) {
    gmp_randinit_mt(state);
    unsigned long seed = time(NULL);
    gmp_randseed_ui(state, seed);
}

static void set_privateKey_components(PrivateKey *privKey, mpz_t n, mpz_t e, mpz_t d, mpz_t p, mpz_t q, mpz_t p_1, mpz_t q_1){

    mpz_set(privKey->n, n);
    mpz_set(privKey->e, e);
    mpz_set(privKey->d, d);
    mpz_set(privKey->p, p);
    mpz_set(privKey->q, q);
    mpz_mod(privKey->dmp1, d, p_1);
    mpz_mod(privKey->dmq1, d, q_1);
    mpz_invert(privKey->iqmp, q, p);

}

void extract_publicBytes(PublicKey *pubKey, PrivateKey *privKey){
    if(!privKey && !pubKey){ return; }

    mpz_set(pubKey->n, privKey->n);
    mpz_set(pubKey->e, privKey->e);
}


int generate_RSA_key(const char *filename){
    mpz_t n, e, d, p, q, p_1, q_1, phi, gcd;
    mpz_inits(n, e, d, p, q, p_1, q_1, phi, gcd, NULL);
    
    gmp_randstate_t state;
    initialize_random_state(state);

    unsigned int bit_size;
    printf("Enter the Size (<= 4096) of the key to be generated: ");
    scanf("%d", &bit_size);

    generate_prime(p, bit_size / 2, state);      // Generate prime number 1
    generate_prime(q, bit_size / 2, state);      // Generate prime number 2

    mpz_mul(n, p, q);                                   // n = p * q
    mpz_sub_ui(p_1, p, 1);                              // p_1 = p - 1
    mpz_sub_ui(q_1, q, 1);                              // q_1 = q - 1
    mpz_mul(phi, p_1, q_1);                             // phi = p_1 * q_1


    // public exponent
    mpz_set_str(e, "65537", 10);
    
    // private exponent
    int status = mpz_invert(d, e, phi) != 0;    // d * e mod phi = 1

    PrivateKey *privKey = init_privateKey();
    if(!privKey) status = 0;

    if(status){
        set_privateKey_components(privKey, n, e, d, p, q, p_1, q_1);
        i2d_RSAPrivateKey(filename, privKey);
    }
    else{
        gmp_printf("No modular inverse found. Public key %Zd and phi %Zd are not coprime.\n", e, phi);
    }
    
    mpz_clears(n, e, d, p, q, p_1, q_1, phi, gcd, NULL);
    free_privateKey(privKey);
    gmp_randclear(state);

    return status;
}
