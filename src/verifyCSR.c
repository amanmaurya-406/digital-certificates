#include <stdio.h>
#include "serialize.h"
#include "sha512.h"
#include "RSA_cipher.h"
#include "verifyCSR.h"


// 1. Signature Verification
bool verify_CSRSignature(CSR csr){

    size_t csrDataLen;
    uint8_t *csrData = serialize_CSR(csr, &csrDataLen);
    uint8_t *hash = SHA512(csrData, csrDataLen);
    
    mpz_t computed_signature, received_signature;
    mpz_init(computed_signature);
    mpz_import(computed_signature, SHA512_DIGEST_LENGTH, 1, 1, 0, 0, hash);
    
    RSA_public_decrypt(received_signature, csr.signature->value, csr.publicKey->exponent, csr.publicKey->modulus);
    bool comparison_result = !mpz_cmp(computed_signature, received_signature);
    
    mpz_clears(computed_signature, received_signature, NULL);

    return comparison_result;
}

// 2. Public Key Verification
bool verify_rsaPublicKey(PublicKey subPubKey){
    if(mpz_sizeinbase(subPubKey.modulus, 256) < 2048 / 8){ // 2048 bits
        printf("Modulus size is too small\n");
        return 0;
    }

    if(!(mpz_sizeinbase(subPubKey.exponent, 256) == 3 && !mpz_cmp_ui(subPubKey.exponent, 65537)) && \
       !(mpz_sizeinbase(subPubKey.exponent, 256) == 1 && !mpz_cmp_ui(subPubKey.exponent, 3))){
            printf("Unusual exponent\n");
            return 0;
    }

    // Public Key Valid.
    return 1;
}

// 3. Subject Name Validation
// bool verifyCSRSubjectInfo(Info sub_Info){ }

