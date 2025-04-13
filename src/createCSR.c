#include "common.h"
#include "utils.h"
#include "RSA_generateKey.h"
#include "serialize.h"
#include "sha512.h"
#include "RSA_cipher.h"
#include "cer2txt.h"

static void get_csrInfo(CSRInfo *csrInfo, DName *subject, PrivateKey *privKey){
    csrInfo->version = 0x00;  // v1
    copy_dName(csrInfo->subject, subject);
    
    csrInfo->pKeyInfo->pubKeyAlgo = malloc(strlen("rsaEncryption") + 1);
    strcpy(csrInfo->pKeyInfo->pubKeyAlgo, "rsaEncryption");
    
    extract_publicBytes(csrInfo->pKeyInfo->pubKey, privKey);
}

static uint8_t *serializeAndSignCSR(size_t *output_size, CSR *csr, PrivateKey *privKey){
    size_t csrInfo_size;
    uint8_t *csrInfo_s = serialize_CSRInfo(csr->csrInfo, &csrInfo_size);
    uint8_t *csrInfoHash = SHA512(csrInfo_s, csrInfo_size);
    
    mpz_t csrInfoHash_m;
    mpz_init(csrInfoHash_m);
    mpz_import(csrInfoHash_m, SHA512_DIGEST_LENGTH, 1, 1, 0, 0, csrInfoHash);
    
    csr->signatureAlgo = malloc(strlen("sha512WithRSAEncryption") + 1);
    strcpy(csr->signatureAlgo, "sha512WithRSAEncryption");
    
    size_t signatureAlgo_size;
    uint8_t *signatureAlgo_s = serialize_signAlgo(csr->signatureAlgo, &signatureAlgo_size);

    RSA_private_encrypt(csr->signature, csrInfoHash_m, privKey->d, privKey->n);
    
    size_t signature_size;
    uint8_t *signature_s = serialize_signature(csr->signature, &signature_size);
    
    size_t certRequest_size = csrInfo_size + signatureAlgo_size + signature_size;
    uint8_t *certRequest_s = malloc(certRequest_size);
    if(!certRequest_s){
        perror("Error serializing CSR");
        return NULL;
    }
    
    int index = 0;
    #define COLLECT_INDIVIDUAL(val_s, val_size)             \
        memcpy(certRequest_s + index, val_s, val_size);     \
        index += val_size;

        COLLECT_INDIVIDUAL(csrInfo_s, csrInfo_size);
        COLLECT_INDIVIDUAL(signatureAlgo_s, signatureAlgo_size);
        COLLECT_INDIVIDUAL(signature_s, signature_size);

    #undef COLLECT_INDIVIDUAL

    uint8_t *buffer = serialize_sequence(output_size, certRequest_size, certRequest_s);

    free(csrInfo_s);
    free(csrInfoHash);
    mpz_clear(csrInfoHash_m);
    free(signatureAlgo_s);
    free(signature_s);
    free(certRequest_s);

    return buffer;
}

CSR *createCSR(PrivateKey *privKey, DName *subject){
    
    CSR *csr = init_csr();
    if(!csr){ return NULL; }

    get_csrInfo(csr->csrInfo, subject, privKey);
    
    size_t certRequest_size;
    uint8_t *certRequest_s = serializeAndSignCSR(&certRequest_size, csr, privKey);

    if(write_cer_file(DATA_DIR "/csr.cer", certRequest_size, certRequest_s))
        printf("CSR generated and saved as 'csr.cer'\n");
    else{
        printf("CSR generation failed.\n");
        free_csr(csr);
        free(certRequest_s);
        return NULL;
    }
    
    free(certRequest_s);
    return csr;
}
