#include "common.h"
#include "verifyCSR.h"
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

static Time get_currentTime(){
    time_t now = time(NULL);
    struct tm *local = localtime(&now);

    Time validFrom; 
    validFrom.year = local->tm_year + 1900;     // tm_year is years since 1900, so we add 1900.
    validFrom.month = local->tm_mon + 1;        // tm_mon is zero-indexed (0 = January), so we add 1.
    validFrom.day = local->tm_mday;
    validFrom.hour = local->tm_hour;
    validFrom.minute = local->tm_min;
    validFrom.second = local->tm_sec;

    return validFrom;
}

static Time addDays(Time validFrom, int extendUpTo){
    validFrom.year += extendUpTo;
    Time validTo = validFrom;

    return validTo;
}

static void get_certificateDetails(Certificate *certificate, Info issuer, int val_period, Info subject){
    certificate->version = 3;
    generate_uniqueSerialNumber(certificate->serialNumber);
    strcpy(certificate->subject_signAlgorithm, "sha512WithRSAEncryption"), certificate->subject_signAlgorithm[24] = '\0';
    certificate->issuer = issuer;
    certificate->validFrom = get_currentTime();
    certificate->validTo = addDays(certificate->validFrom, val_period);
    certificate->subject = subject;
}

static int get_publicKey(Certificate *cert, PublicKey *publicKey){

    cert->subject_pubKey = (PublicKey *)malloc(sizeof(PublicKey));
    if(!cert->subject_pubKey){
        perror("Memory allocation failed");
        return 0;
    }

    strcpy(cert->subject_pubKey->algorithmIdentifier,  publicKey->algorithmIdentifier);
    cert->subject_pubKey->algorithmIdentifier[strlen(publicKey->algorithmIdentifier)] = '\0';
    
    cert->subject_pubKey->keyBit = publicKey->keyBit;
    
    mpz_inits(cert->subject_pubKey->modulus, cert->subject_pubKey->exponent, NULL);
    mpz_set(cert->subject_pubKey->modulus, publicKey->modulus);
    mpz_set(cert->subject_pubKey->exponent, publicKey->exponent);

    return 1;
}

static uint8_t *serializeAndSignCertificate(size_t *outputSize, Certificate *certificate, PrivateKey *priv_key){
    size_t certData_size;
    uint8_t *certData_s = serialize_certificate(certificate, &certData_size);
    uint8_t *hash = SHA512(certData_s, certData_size);
    
    mpz_t hash_m;
    mpz_init(hash_m);
    mpz_import(hash_m, SHA512_DIGEST_LENGTH, 1, 1, 0, 0, hash);
    
    certificate->signature = (Signature *)malloc(sizeof(Signature));
    strcpy(certificate->signature->algorithmIdentifier, "sha512WithRSAEncryption"), certificate->signature->algorithmIdentifier[24] = '\0';
    RSA_private_encrypt(certificate->signature->value, hash_m, priv_key->priv_exp, priv_key->modulus);
    
    size_t signature_size;
    uint8_t *signature_s = serialize_signature(*(certificate->signature), &signature_size);

    size_t buffer_size = certData_size + signature_size;
    uint8_t *buffer = (uint8_t *)malloc(buffer_size);
    if(!buffer){
        *outputSize = 0;
        perror("Memory allocation failed");
        return NULL;
    }

    memcpy(buffer, certData_s, certData_size);
    memcpy(buffer + certData_size, signature_s, signature_size);

    uint8_t *certificate_s = serialize_sequence(outputSize, buffer_size, buffer);

    free(certData_s);
    free(hash);
    free(signature_s);
    free(buffer);
    mpz_clear(hash_m);

    return certificate_s;
}


Certificate *generate_certificate(CSR *csr, Info caInfo, PrivateKey *ca_privKey){
     
    Certificate *cert = (Certificate *)malloc(sizeof(Certificate));
    if(!cert){
        perror("Memory allocation failed");
        return NULL;
    }
    
    if(verify_CSRSignature(*csr) && verify_rsaPublicKey(csr->publicKey)){
        
        get_certificateDetails(cert, caInfo, 1, csr->subject);

        if(!get_publicKey(cert, csr->publicKey)){
            return NULL;
        }
        
        size_t certificate_size;
        uint8_t *certificate_s = serializeAndSignCertificate(&certificate_size, cert, ca_privKey);
        
        if(write_cer_file(DATA_DIR "/issued_certificate.cer", certificate_size, certificate_s))

            printf("Certificate generated and saved as 'issued_certificate.cer'\n");
        else
            printf("Certificate generation failed.\n");
            
        free(certificate_s);
    }
    else{
        perror("Invalid CSR signature or Invalid Public Key");
    }
    
    return cert;
}

Certificate *generate_self_signed_certificate(Info caInfo, PrivateKey *ca_privKey){

    Certificate *ca_cert = (Certificate *)malloc(sizeof(Certificate));
    if(!ca_cert){
        perror("Memory allocation failed");
        return NULL;
    }
    get_certificateDetails(ca_cert, caInfo, 10, caInfo);

    ca_cert->subject_pubKey = extract_publicBytes(ca_privKey);
    strcpy(ca_cert->subject_pubKey->algorithmIdentifier, "rsaEncryption"), ca_cert->subject_pubKey->algorithmIdentifier[14] = '\0';
    ca_cert->subject_pubKey->keyBit = 2048;

    size_t certificate_size;
    uint8_t *certificate_s = serializeAndSignCertificate(&certificate_size, ca_cert, ca_privKey);
    
    if(write_cer_file(DATA_DIR "/ca_certificate.cer", certificate_size, certificate_s))
        printf("CA certificate generated and saved as 'ca_certificate.cer'\n");
    else
        printf("CA certificate generation failed.\n");
    
    free(certificate_s);

    return ca_cert;
}

void free_certificate(Certificate *cert){
    mpz_clears(cert->serialNumber, cert->subject_pubKey->exponent, NULL);
    mpz_clears(cert->subject_pubKey->modulus, cert->signature->value, NULL);
    free(cert->subject_pubKey);
    free(cert->signature);
    free(cert);
}
