#include "common.h"
#include "verifyCSR.h"
#include "utils.h"
#include "RSA_generateKey.h"
#include "serialize.h"
#include "sha512.h"
#include "encodeKey.h"
#include "RSA_cipher.h"
#include "cer2txt.h"
#include "generateCertificate.h"


static void generate_uniqueSerialNumber(mpz_t serialNumber){
    gmp_randstate_t state;
    gmp_randinit_mt(state); 
    gmp_randseed_ui(state, time(NULL));

    // Generate a random number with a maximum bit size of 256
    mpz_init(serialNumber);
    mpz_urandomb(serialNumber, state, 160);      // 160(20 * 8) for 20 byte serial number

    gmp_randclear(state);
}

static void get_currentTime(Time *validFrom){
    time_t now = time(NULL);
    struct tm *local = localtime(&now);

    validFrom->year = local->tm_year + 1900;     // tm_year is years since 1900, so we add 1900.
    validFrom->month = local->tm_mon + 1;        // tm_mon is zero-indexed (0 = January), so we add 1.
    validFrom->day = local->tm_mday;
    validFrom->hour = local->tm_hour;
    validFrom->minute = local->tm_min;
    validFrom->second = local->tm_sec;
}

static void addDays(Validity *validity, int extendUpTo){
    validity->validTo->year = validity->validFrom->year + extendUpTo;
    validity->validTo->month = validity->validFrom->month;
    validity->validTo->day = validity->validFrom->day;
    validity->validTo->hour = validity->validFrom->hour;
    validity->validTo->minute = validity->validFrom->minute;
    validity->validTo->second = validity->validFrom->second;
}

static void get_certificateDetails(TBSCertificate *tbsCert, DName *issuer, int val_period, DName *subject){
    tbsCert->version = 3;
    generate_uniqueSerialNumber(tbsCert->serialNumber);

    tbsCert->signatureAlgo = malloc(strlen("sha512WithRSAEncryption") + 1);
    strcpy(tbsCert->signatureAlgo, "sha512WithRSAEncryption");
    
    copy_dName(tbsCert->issuer, issuer);
    get_currentTime(tbsCert->validity->validFrom);
    addDays(tbsCert->validity, val_period);
    copy_dName(tbsCert->subject, subject);
}

static void get_pKeyInfo(PKeyInfo *certPKeyInfo, PKeyInfo *subPKeyInfo){

    certPKeyInfo->pubKeyAlgo = malloc(strlen(subPKeyInfo->pubKeyAlgo) + 1);
    strcpy(certPKeyInfo->pubKeyAlgo, subPKeyInfo->pubKeyAlgo);
    
    mpz_set(certPKeyInfo->pubKey->n, subPKeyInfo->pubKey->n);
    mpz_set(certPKeyInfo->pubKey->e, subPKeyInfo->pubKey->e);

}

static uint8_t *serializeAndSignCertificate(size_t *outputSize, Certificate *cert, PrivateKey *priv_key){
    size_t tbsCert_size;
    uint8_t *tbsCert_s = serialize_tbsCertificate(cert->tbsCert, &tbsCert_size);
    uint8_t *tbsCertHash = SHA512(tbsCert_s, tbsCert_size);
    
    mpz_t tbsCertHash_m;
    mpz_init(tbsCertHash_m);
    mpz_import(tbsCertHash_m, SHA512_DIGEST_LENGTH, 1, 1, 0, 0, tbsCertHash);
    
    cert->signatureAlgo = malloc(strlen("sha512WithRSAEncryption") + 1);
    strcpy(cert->signatureAlgo, "sha512WithRSAEncryption");
    
    size_t signatureAlgo_size;
    uint8_t *signatureAlgo_s = serialize_signAlgo(cert->signatureAlgo, &signatureAlgo_size);

    RSA_private_encrypt(cert->signature, tbsCertHash_m, priv_key->d, priv_key->n);
    
    size_t signature_size;
    uint8_t *signature_s = serialize_signature(cert->signature, &signature_size);

    size_t buffer_size = tbsCert_size + signatureAlgo_size + signature_size;
    uint8_t *buffer = malloc(buffer_size);
    if(!buffer){
        perror("Error serializing TBSCertificate");
        *outputSize = 0;
        return NULL;
    }

    int index = 0;
    #define COLLECT_INDIVIDUAL(val_s, val_size)             \
        memcpy(buffer + index, val_s, val_size);         \
        index += val_size;

        COLLECT_INDIVIDUAL(tbsCert_s, tbsCert_size);
        COLLECT_INDIVIDUAL(signatureAlgo_s, signatureAlgo_size);
        COLLECT_INDIVIDUAL(signature_s, signature_size);

    #undef COLLECT_INDIVIDUAL

    uint8_t *certificate_s = serialize_sequence(outputSize, buffer_size, buffer);

    free(tbsCert_s);
    free(tbsCertHash);
    mpz_clear(tbsCertHash_m);
    free(signatureAlgo_s);
    free(signature_s);
    free(buffer);

    return certificate_s;
}


Certificate *generate_certificate(CSR *csr, DName *caInfo, PrivateKey *ca_privKey){
     
    Certificate *cert = init_certificate();
    if(!cert){ return NULL; }
    
    if(verify_CSRSignature(csr) && verify_RSAPublicKey(csr->csrInfo->pKeyInfo->pubKey)){
        
        int val_period = 1;
        get_certificateDetails(cert->tbsCert, caInfo, val_period, csr->csrInfo->subject);
        get_pKeyInfo(cert->tbsCert->pKeyInfo, csr->csrInfo->pKeyInfo);
        
        size_t certificate_size;
        uint8_t *certificate_s = serializeAndSignCertificate(&certificate_size, cert, ca_privKey);
        
        if(write_cer_file(DATA_DIR "/issued_certificate.cer", certificate_size, certificate_s))
            printf("Certificate generated and saved as 'issued_certificate.cer'\n");
        else{
            printf("Certificate generation failed.\n");
            free_certificate(cert);
            free(certificate_s);
            return NULL;
        }
            
        free(certificate_s);
    }
    else{
        perror("Invalid CSR signature or Invalid Public Key");
    }
    
    return cert;
}

Certificate *generate_self_signed_certificate(DName *caInfo, PrivateKey *ca_privKey){
    
    Certificate *ca_cert = init_certificate();
    if(!ca_cert){ return NULL; }
    
    int val_period = 10;
    get_certificateDetails(ca_cert->tbsCert, caInfo, val_period, caInfo);
    
    ca_cert->tbsCert->pKeyInfo->pubKeyAlgo = malloc(strlen("rsaEncryption") + 1);
    strcpy(ca_cert->tbsCert->pKeyInfo->pubKeyAlgo, "rsaEncryption");
    extract_publicBytes(ca_cert->tbsCert->pKeyInfo->pubKey, ca_privKey);

    size_t certificate_size;
    uint8_t *certificate_s = serializeAndSignCertificate(&certificate_size, ca_cert, ca_privKey);

    if(write_cer_file(DATA_DIR "/ca_certificate.cer", certificate_size, certificate_s))
        printf("CA certificate generated and saved as 'ca_certificate.cer'\n");
    else{
        printf("CA certificate generation failed.\n");
        free_certificate(ca_cert);
        free(certificate_s);
        return NULL;
    }

    free(certificate_s);
    return ca_cert;
}


