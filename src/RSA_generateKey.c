#include <stdio.h>
#include <gmp.h>
#include <time.h>
#include "RSA_generateKey.h"
#include "encodeKey.h"


static void generate_prime(mpz_t prime, unsigned int bit_size, gmp_randstate_t state){
    mpz_t random_num;
    mpz_init(random_num);

    mpz_urandomb(random_num, state, bit_size);
    mpz_setbit(random_num, bit_size - 1);

    mpz_nextprime(prime, random_num);

    mpz_clear(random_num);
}

int generate_RSA_keys(const char *filename){
    mpz_t n, e, d, p, q, p_1, q_1, phi, gcd;
    mpz_inits(n, e, d, p, q, p_1, q_1, phi, gcd, NULL);
    
    gmp_randstate_t state;
    gmp_randinit_mt(state);

    unsigned long seed = time(NULL);
    gmp_randseed_ui(state, seed);

    unsigned int bit_size = 2048;
    // printf("Enter the Size (<= 4096) of the key to be generated: ");
    // scanf("%d", &bit_size);

    generate_prime(p, bit_size / 2, state);      // Generate prime number 1
    generate_prime(q, bit_size / 2, state);      // Generate prime number 2

    mpz_mul(n, p, q);                                   // n = p * q
    mpz_sub_ui(p_1, p, 1);                              // p_1 = p - 1
    mpz_sub_ui(q_1, q, 1);                              // q_1 = q - 1
    mpz_mul(phi, p_1, q_1);                             // phi = p_1 * q_1


    /* // Generate random Public Key (e)
    do{
        mpz_urandomb(e, state, 16);          // Generate a random 16-bit number for e
        mpz_gcd(gcd, e, phi);                // Ensure gcd(e, phi) = 1
    }while(mpz_cmp_ui(e, 1) <= 0 || mpz_cmp(e, phi) >= 0 || mpz_cmp_ui(gcd, 1) != 0); */
    mpz_set_str(e, "65537", 10);
    
    // Generate Private Key (d)
    if(mpz_invert(d, e, phi) != 0){         // d * e mod phi = 1
        // write_privateKey(filename, bit_size, pub_exp, priv_exp, modulus);
        write_privateKey_pem(filename, n, e, d, p, q, p_1, q_1);
    }
    else{
        gmp_printf("No modular inverse found. Public key %Zd and phi %Zd are not coprime.\n", e, phi);
    }
    
    /* gmp_printf("n=%Zd\n", n);
    gmp_printf("pub exp=%Zd\n", e);
    gmp_printf("priv exp=%Zd\n", d); */
    
    
    mpz_clears(n, e, d, p, q, p_1, q_1, phi, gcd, NULL);
    gmp_randclear(state);

    return (mpz_invert(d, e, phi) != 0);
}


/*  multiple leading 1's, strategic 0 placements; cause pattern matching easier, which is not good
    {
        mpz_rrandomb(prime, state, bit_size);
        mpz_setbit(prime, bit_size - 1);    // Ensure it's a large number
        mpz_setbit(prime, 0);               // Ensure it's odd

        while (!mpz_probab_prime_p(prime, 25))
            mpz_add_ui(prime, prime, 2);    // Keep trying the next odd number 
    }
*/
/*  p1 (Hex):   0xffffffffffffffffffffffffffffffffffffffffffffffff8
                0000000000000000000000000000000000000000000000000
                000000000000000000000000000000000000000000000000000
                000000000000000000000000000000000000000000000000000
                000000000000000000000000000000000000000000000000000
                20789     
    q1 (Hex):   0xffffffffffffffffffffffe
                000000000000000000000000000000000000000000000000000
                0000000000000000000000000000003fffc0000000000000000
                000000000000000000000000000000000000000000000000000
                000000000000000000000000000000000000000000000000000
                00010000000000000000000000065
 */