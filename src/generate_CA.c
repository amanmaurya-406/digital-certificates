#include <stdio.h>
#include "RSA_generateKey.h"
#include "encodeKey.h"
#include "generateCertificate.h"
#include "utils.h"

Certificate *generateCA(DName *caInfo){

    if(generate_RSA_key(DATA_DIR "/ca_private.key"))
        printf("Key generated and stored as '%s'\n", "ca_private.key");
    else{
        printf("Key generation failed\n");
        return NULL;
    }

    PrivateKey *ca_privKey = d2i_RSAPrivateKey(DATA_DIR "/ca_private.key");
    Certificate *ca_cert = generate_self_signed_certificate(caInfo, ca_privKey);
    
    free_privateKey(ca_privKey);
    return ca_cert;
}