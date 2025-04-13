#ifndef RSA_GENERATE_KEY_H
#define RSA_GENERATE_KEY_H

#include "config.h"

int generate_RSA_key(const char *filename);

/**
 * @brief Extracts a Public key from a Private key.
 * 
 * @param pubKey Pointer to PublicKey structure.
 * @param privateKey Pointer to PrivateKey structure.
 */
void extract_publicBytes(PublicKey *pubKey, PrivateKey *privKey);

#endif