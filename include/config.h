#ifndef CONFIG_H
#define CONFIG_H

#include <gmp.h>

/**
 * @struct Private Key
 * @brief Represents a Private Key structure.
 */
typedef struct privkey_st {
    int version;
    mpz_t n;
    mpz_t e;
    mpz_t d;
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
typedef struct pubkey_st {
    mpz_t n;
    mpz_t e;
} PublicKey ;


/**
 * @struct Info
 * @brief Represents the information of a Certificate Owner.
 */
typedef struct dname_st {
    char country[4];
    char state[50];
    char city[50];
    char org[50];
    char unit[50];
    char name[50];
} DName ;

typedef struct pubKeyInfo_st {
    char *pubKeyAlgo;
    PublicKey *pubKey;
} PKeyInfo ;

typedef struct csrInfo_st {
    int version;
    DName *subject;
    PKeyInfo *pKeyInfo;
} CSRInfo ;


/**
 * @struct CSR
 * @brief Represents a Certificate Signing Request (CSR).
 */
typedef struct csr_st {
    CSRInfo *csrInfo;
    char *signatureAlgo;
    mpz_t signature;
} CSR ;


/**
 * @struct Time
 */
typedef struct time_st {
    int year, month, day;
    int hour, minute, second;
} Time ;

typedef struct validity_st {
    Time *validFrom;
    Time *validTo;
} Validity ;

typedef struct tbsCert_st {
    int version;
    mpz_t serialNumber;
    char *signatureAlgo;
    DName *issuer;
    Validity *validity;
    DName *subject;
    PKeyInfo *pKeyInfo;
} TBSCertificate ;

typedef struct cert_st {
    TBSCertificate *tbsCert;
    char *signatureAlgo;
    mpz_t signature;
} Certificate ;


#endif