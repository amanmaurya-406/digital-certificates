#include <stdio.h>
#include <error.h>
#include "serialize.h"
#include "sha512.h"
#include "RSA_cipher.h"
#include "verifyCSR.h"

#define SHA512_DIGEST_LENGTH 64

// Signature Verification
bool verify_CSRSignature(CSR *csr){

    size_t csrInfo_size;
    uint8_t *csrInfo_s = serialize_CSRInfo(csr->csrInfo, &csrInfo_size);
    uint8_t *csrInfoHash = SHA512(csrInfo_s, csrInfo_size);
    
    mpz_t computed_signature, received_signature;
    mpz_inits(computed_signature, received_signature, NULL);
    mpz_import(computed_signature, SHA512_DIGEST_LENGTH, 1, 1, 0, 0, csrInfoHash);
    
    RSA_public_decrypt(received_signature, csr->signature, csr->csrInfo->pKeyInfo->pubKey->e, csr->csrInfo->pKeyInfo->pubKey->n);
    bool comparison_result = !mpz_cmp(computed_signature, received_signature);
    
    mpz_clears(computed_signature, received_signature, NULL);

    return comparison_result;
}

// Public Key Verification
bool verify_RSAPublicKey(PublicKey *publicKey){
    if(mpz_sizeinbase(publicKey->n, 256) < 2048 / 8){ // 2048 bits
        printf("RSA key size is too small, choose atleast 2048 bits\n");
        // errno = ERROR_BAD_LENGTH;
        return 0;
    }

    if(!(mpz_sizeinbase(publicKey->e, 256) == 3 && !mpz_cmp_ui(publicKey->e, 65537)) && \
       !(mpz_sizeinbase(publicKey->e, 256) == 1 && !mpz_cmp_ui(publicKey->e, 3))){
            printf("Unusual exponent\n");
            return 0;
    }

    return 1;
}

// Subject Name Validation
// bool verifyCSRSubjectInfo(Info sub_Info){ }

