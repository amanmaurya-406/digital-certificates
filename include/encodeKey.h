#ifndef ENCODE_KEY_H
#define ENCODE_KEY_H

#include "config.h"


// WRITING AND READING KEYS IN PKCS#1
void write_privateKey_der(const char *filename, mpz_t modulus, mpz_t pub_exp, mpz_t priv_exp, mpz_t prime1, mpz_t prime2, mpz_t p_1, mpz_t q_1);
void write_privateKey_pem(const char *filename, mpz_t modulus, mpz_t pub_exp, mpz_t priv_exp, mpz_t prime1, mpz_t prime2, mpz_t p_1, mpz_t q_1);


/**
 * @brief Loads a private key from a file.
 * 
 * This function reads a private key from the specified file and returns a pointer
 * to a dynamically allocated PrivateKey structure containing the parsed key data.
 * 
 * @param filename The path to the file containing the private key (in PEM format).
 * @return PrivateKey* to the loaded PrivateKey structure on success, Must be freed after use.
 * or NULL on failure (e.g., file not found or invalid format).
 */
PrivateKey *load_privateKey(const char *filename);


/**
 * @brief Extarcts public key from private key.
 * 
 * @param filename The path to the file containing the private key (in PEM format).
 * @return PublicKey* on success, Must be freed after use.
 * or NULL on failure (e.g., file not found or invalid format).
 */
PublicKey *load_publicBytes(const char *filename);


/**
 * @brief Extracts a Public key from a Private key.
 * 
 * @param privateKey PrivateKey structure.
 * @return PublicKey* to the extracted PublicKey structure on success, Must be freed after use.
 * or NULL on failure (e.g., file not found or invalid format).
 */
PublicKey *extract_publicBytes(PrivateKey *privateKey);
void free_privateKey(PrivateKey *privateKey);
void free_publicKey(PublicKey *publicKey);

#endif