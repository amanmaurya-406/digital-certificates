#include "common.h"
#include "serialize.h"
#include "encodeKey.h"
#include "sha512.h"
#include "RSA_cipher.h"
#include "cer2txt.h"


CSR *createCSR(PrivateKey *privateKey, Info subject){
    
    CSR *csr = (CSR *)malloc(sizeof(CSR));

    csr->version = 0x00;  // v1
    csr->subject = subject;
    
    csr->publicKey = extract_publicBytes(privateKey);
    strcpy(csr->publicKey->algorithmIdentifier, "rsaEncryption"), csr->publicKey->algorithmIdentifier[14] = '\0';
    csr->publicKey->keyBit = 2048;
    
    /* gmp_printf("modulus=%Zx\n", csr->publicKey->modulus);
    gmp_printf("pub exp=%Zx\n", csr->publicKey->exponent);
    gmp_printf("priv exp=%Zx\n", privateKey->priv_exp); */

    size_t csr_size;
    uint8_t *csr_s = serialize_CSR(*csr, &csr_size);
    uint8_t *csrHash = SHA512(csr_s, csr_size);
    
    mpz_t csrHash_m;
    mpz_init(csrHash_m);
    mpz_import(csrHash_m, SHA512_DIGEST_LENGTH, 1, 1, 0, 0, csrHash);
    
    csr->signature = (Signature *)malloc(sizeof(Signature));
    strcpy(csr->signature->algorithmIdentifier, "sha512WithRSAEncryption");
    csr->signature->algorithmIdentifier[24] = '\0';
    
    RSA_private_encrypt(csr->signature->value, csrHash_m, privateKey->priv_exp, privateKey->modulus);
    
    size_t signature_size;
    uint8_t *signature_s = serialize_signature(*csr->signature, &signature_size);
    
    size_t certRequest_size = csr_size + signature_size;
    uint8_t *certRequest_s = (uint8_t *)malloc(certRequest_size);
    if(certRequest_s){
        int index = 0;

        memcpy(certRequest_s + index, csr_s, csr_size);
        index += csr_size;

        memcpy(certRequest_s + index, signature_s, signature_size);
        index += signature_size;

        size_t buffer_size;
        uint8_t *buffer = serialize_sequence(&buffer_size, certRequest_size, certRequest_s);
        
        if(write_cer_file(DATA_DIR "/csr.cer", certRequest_size, certRequest_s))
            printf("CSR generated and saved as 'csr.cer'\n");
        else
            printf("CSR generation failed.\n");
        
        free(buffer);
    }
    else{
        perror("Memory allocation failed");
    }
    
    free(csr_s);
    free(csrHash);
    free(signature_s);
    mpz_clear(csrHash_m);
    
    return csr;
}
