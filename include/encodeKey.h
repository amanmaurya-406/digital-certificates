#ifndef ENCODE_KEY_H
#define ENCODE_KEY_H

#include "config.h"


// WRITING AND READING KEYS IN PKCS#1
void i2d_RSAPrivateKey(const char *filename, PrivateKey *privKey);

/**
 * @brief Loads a private key from a file.
 * 
 * This function reads a private key from the specified file and returns a pointer
 * to a dynamically allocated PrivateKey structure containing the parsed key data.
 * 
 * @param filename The path to the file containing the private key (in der format).
 * @return PrivateKey* to the loaded PrivateKey structure on success, Must be freed after use.
 * or NULL on failure (e.g., file not found or invalid format).
 */
PrivateKey *d2i_RSAPrivateKey(const char *filename);

/**
 * @brief Extarcts public key from private key.
 * 
 * @param filename The path to the file containing the private key (in der format).
 * @return PublicKey* on success, Must be freed after use.
 * or NULL on failure (e.g., file not found or invalid format).
 */
PublicKey *d2i_RSAPublicKey(const char *filename);


#endif