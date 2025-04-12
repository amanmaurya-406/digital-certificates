#ifndef CONFIG_H
#define CONFIG_H

#include <gmp.h>

/**
 * @struct Private Key
 * @brief Represents a Private Key structure.
 */
typedef struct {
    mpz_t modulus;      // n
    mpz_t pub_exp;      // e
    mpz_t priv_exp;     // d
    mpz_t p;
    mpz_t q;
    mpz_t dmp1;
    mpz_t dmq1;
    mpz_t iqmp;
} PrivateKey ;

/**
 * @struct Public Key
 * @brief Represents the Public Key information.
 */
typedef struct {
    char algorithmIdentifier[50];
    int keyBit;
    mpz_t exponent;
    mpz_t modulus;
} PublicKey ;

/**
 * @struct Signature
 * @brief Represents Signature of a Certificate Signing Request (CSR).
 */
typedef struct {
    char algorithmIdentifier[50];
    mpz_t value;
} Signature ;

/**
 * @struct Info
 * @brief Represents the information of a Certificate Owner.
 */
typedef struct {
    char country[3];
    char state[50];
    char locality[50];
    char organization[50];
    // char organisationUnit[50];
    char common_name[50];          /** Common name (e.g., domain name). */
} Info ;


/**
 * @struct CSR
 * @brief Represents a Certificate Signing Request (CSR).
 */
typedef struct {
    int version;
    Info subject_info;
    PublicKey *publicKey;
    Signature *signature;
} CSR ;


/**
 * @struct Time
 */
typedef struct {
    int year, month, day;
    int hour, minute, second;
} Time ;

/**
 * @struct Certificate
 * @brief Represents the structure of an X.509 v3 digital certificate.
 * 
 * The structure of an X.509 v3 digital certificate includes several fields necessary
 * for identification, validation, and authentication of entities.
 *
 * @param version             The version of the certificate (e.g., X.509 v3).
 * @param serialNumber        The serial number of the certificate, used to uniquely identify it.
 * @param subSignAlgorithm    The signature algorithm intended for use with the Subject's public key.
 * @param issuer              The name of the entity issuing the certificate (e.g., CA).
 * @param validFrom           The start of the certificate's validity period (Not Before).
 * @param validTo             The end of the certificate's validity period (Not After).
 * @param subject             The name of the entity to which the certificate is issued.
 * @param subPubKey           The subject's public key information.
 * @param signature           The digital signature.
 */
typedef struct {
    int version;
    mpz_t serialNumber;
    char subject_signAlgorithm[50];
    Info issuer;
    Time validFrom;
    Time validTo;
    Info subject_name;
    PublicKey *subject_pubKey;
    // Extensions extensions;                  // Optional certificate extensions  
    Signature *signature;
} Certificate ;


#endif