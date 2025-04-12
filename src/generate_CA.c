#include <stdio.h>
#include "RSA_generateKey.h"
#include "encodeKey.h"
#include "generateCertificate.h"

Certificate *generateCA(Info caInfo){

    if(generate_RSA_keys(DATA_DIR "/ca_private.key"))
        printf("Key generated and stored as '%s'\n", "ca_private.key");
    else{
        printf("Key generation failed\n");
        return NULL;
    }

    PrivateKey *ca_privKey = load_privateKey(DATA_DIR "/ca_private.key");
    Certificate *ca_cert = generate_self_signed_certificate(caInfo, ca_privKey);

    free_privateKey(ca_privKey);
    return ca_cert;
}