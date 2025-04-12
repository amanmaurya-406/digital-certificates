#include "common.h"
#include "asn1.h"
#include "serialize.h"



uint8_t *serialize_version(int version, size_t *outputSize){
    return serialize_integer(outputSize, version);
}

uint8_t *serialize_serialNumber(mpz_t serialNumber, size_t *outputSize){
    return serialize_mpz(outputSize, serialNumber);
}

uint8_t *serialize_issuerInfo(Info caInfo, size_t *outputSize){
    
    size_t country_size, org_size;
    
    uint8_t *country_s = serialize_string(&country_size, MY_ASN1_PRINTABLESTRING, caInfo.country);
    uint8_t *organization_s = serialize_string(&org_size, MY_ASN1_UTF8STRING, caInfo.organization);

    size_t issuerInfo_size = country_size + org_size;
    uint8_t *issuerInfo_s = (uint8_t *)malloc(issuerInfo_size);
    if(!issuerInfo_s){
        perror("Memory allocation failed\n");
        *outputSize = 0;
        return NULL;
    }

    int index = 0;
    memcpy(issuerInfo_s + index, country_s, country_size);
    index += country_size;

    memcpy(issuerInfo_s + index, organization_s, org_size);
    index += org_size;

    uint8_t *buffer = serialize_sequence(outputSize, issuerInfo_size, issuerInfo_s);
    
    free(country_s);
    free(organization_s);
    free(issuerInfo_s);
    return buffer;
}

uint8_t *serialize_validity(Time time, size_t *outputSize){

    size_t year_size, month_size, day_size, hour_size, minute_size, second_size;

    uint8_t *year_s = serialize_integer(&year_size, time.year);
    uint8_t *month_s = serialize_integer(&month_size, time.month);
    uint8_t *day_s = serialize_integer(&day_size, time.day);
    uint8_t *hour_s = serialize_integer(&hour_size, time.hour);
    uint8_t *minute_s = serialize_integer(&minute_size, time.minute);
    uint8_t *second_s = serialize_integer(&second_size, time.second);

    size_t time_size = year_size + month_size + day_size + hour_size + minute_size + second_size;
    uint8_t *time_s = (uint8_t *)malloc(time_size);
    if(!time_s){ 
        perror("Memory allocation failed\n");
        *outputSize = 0;
        return NULL; 
    }

    int index = 0;

    #define COLLECT_INDIVIDUAL(individual, individual_size)          \
        memcpy(time_s + index, individual, individual_size);      \
        index += individual_size;

        COLLECT_INDIVIDUAL(year_s, year_size);
        COLLECT_INDIVIDUAL(month_s, month_size);
        COLLECT_INDIVIDUAL(day_s, day_size);
        COLLECT_INDIVIDUAL(hour_s, hour_size);
        COLLECT_INDIVIDUAL(minute_s, minute_size);
        COLLECT_INDIVIDUAL(second_s, second_size);

    #undef COLLECT_INDIVIDUAL

    uint8_t *buffer = serialize_sequence(outputSize, time_size, time_s);

    free(year_s);
    free(month_s);
    free(day_s);
    free(hour_s);
    free(minute_s);
    free(second_s);
    free(time_s);
    return buffer;
}

uint8_t *serialize_subInfo(Info subInfo, size_t *outputSize){

    size_t country_size, state_size, locality_size, organization_size, commonName_size;
    
    uint8_t *country_s = serialize_string(&country_size, MY_ASN1_PRINTABLESTRING, subInfo.country);
    uint8_t *state_s = serialize_string(&state_size, MY_ASN1_UTF8STRING, subInfo.state);
    uint8_t *locality_s = serialize_string(&locality_size, MY_ASN1_UTF8STRING, subInfo.locality);
    uint8_t *organization_s = serialize_string(&organization_size, MY_ASN1_UTF8STRING, subInfo.organization);
    uint8_t *commonName_s = serialize_string(&commonName_size, MY_ASN1_UTF8STRING, subInfo.common_name);

    size_t subInfo_size = country_size + state_size + locality_size + organization_size + commonName_size;
    uint8_t *subInfo_s = (uint8_t *)malloc(subInfo_size);
    if(!subInfo_s){
        perror("Memory allocation failed");
        *outputSize = 0;
        return NULL;
    }
    
    int index = 0;

    #define COLLECT_INDIVIDUAL(individual, individual_size)         \
        memcpy(subInfo_s + index, individual, individual_size);             \
        index += individual_size;

        COLLECT_INDIVIDUAL(country_s, country_size);
        COLLECT_INDIVIDUAL(state_s, state_size);
        COLLECT_INDIVIDUAL(locality_s, locality_size);
        COLLECT_INDIVIDUAL(organization_s, organization_size);
        COLLECT_INDIVIDUAL(commonName_s, commonName_size);

    #undef COLLECT_INDIVIDUAL

    uint8_t *buffer = serialize_sequence(outputSize, subInfo_size, subInfo_s);
    
    free(country_s);
    free(state_s);
    free(locality_s);
    free(organization_s);
    free(commonName_s);
    free(subInfo_s);

    return buffer;
}

uint8_t *serialize_subPubKeyInfo(PublicKey publicKey, size_t *outputSize){

    // 1. Serialize AlgorithmIdentifier
    size_t pubKeyAlgoIdentifier_size;
    uint8_t *pubKeyAlgoIdentifier_s = serialize_string(&pubKeyAlgoIdentifier_size, MY_ASN1_UTF8STRING, publicKey.algorithmIdentifier);

    // 2. Serialize Public keyBit
    size_t keyBit_size;;
    uint8_t *keyBit_s = serialize_integer(&keyBit_size, publicKey.keyBit);
    
    // 3. Serialize Public key modulus
    size_t mod_size;
    uint8_t *mod_s = serialize_mpz(&mod_size, publicKey.modulus);

    // 4. Serialize Public key exponent
    size_t exp_size;
    uint8_t *exp_s = serialize_mpz(&exp_size, publicKey.exponent);

    // 5. Serialize all key components in sequence
    size_t publicKey_size = keyBit_size + exp_size + mod_size;
    uint8_t *publicKey_s = malloc(publicKey_size);
    if(!publicKey_s){
        perror("Memory alloaction failed");
        *outputSize = 0;
        return NULL;
    }

    int index = 0;

    #define COLLECT_INDIVIDUAL(rop, individual, individual_size)          \
        memcpy(rop + index, individual, individual_size);                 \
        index += individual_size;

        COLLECT_INDIVIDUAL(publicKey_s, keyBit_s, keyBit_size);
        COLLECT_INDIVIDUAL(publicKey_s, mod_s, mod_size);
        COLLECT_INDIVIDUAL(publicKey_s, exp_s, exp_size);

        size_t xxx_size;
        uint8_t *xxx_s = serialize_sequence(&xxx_size, publicKey_size, publicKey_s);

        // 6. sequence of AlgorithmIdentifier + Public key
        size_t publicKeyInfo_size = pubKeyAlgoIdentifier_size + xxx_size;
        uint8_t *publicKeyInfo_s = (uint8_t *)malloc(publicKeyInfo_size);
        if(!publicKeyInfo_s){
            perror("Memory alloaction failed");
            *outputSize = 0;
            return NULL;
        }

        index = 0;
        COLLECT_INDIVIDUAL(publicKeyInfo_s, pubKeyAlgoIdentifier_s, pubKeyAlgoIdentifier_size);
        COLLECT_INDIVIDUAL(publicKeyInfo_s, xxx_s, xxx_size);

    #undef COLLECT_INDIVIDUAL

    uint8_t *buffer = serialize_sequence(outputSize, publicKeyInfo_size, publicKeyInfo_s);

    free(pubKeyAlgoIdentifier_s);
    free(keyBit_s);
    free(mod_s);
    free(exp_s);
    free(publicKey_s);
    free(xxx_s);
    free(publicKeyInfo_s);
    return buffer;
}

uint8_t *serialize_CSR(CSR csr, size_t *outputSize){
    
    size_t ver_size, subInfo_size, PKeyInfo_size;
    
    uint8_t *version_s = serialize_version(csr.version, &ver_size);
    uint8_t *subInfo_s = serialize_subInfo(csr.subject, &subInfo_size);
    uint8_t *PKeyInfo_s = serialize_subPubKeyInfo(*csr.publicKey, &PKeyInfo_size);
    
    size_t csr_size = ver_size + subInfo_size + PKeyInfo_size;
    uint8_t *csr_s = (uint8_t *)malloc(csr_size);
    if(!csr_s){
        perror("Memory allocation failed");
        *outputSize = 0;
        return NULL; 
    }

    int index = 0;

    #define COLLECT_INDIVIDUAL(individual, individual_size)         \
        memcpy(csr_s + index, individual, individual_size);         \
        index += individual_size;

        COLLECT_INDIVIDUAL(version_s, ver_size);
        COLLECT_INDIVIDUAL(subInfo_s, subInfo_size);
        COLLECT_INDIVIDUAL(PKeyInfo_s, PKeyInfo_size);

    #undef COLLECT_INDIVIDUAL
    
    uint8_t *buffer = serialize_sequence(outputSize, csr_size, csr_s);
    
    free(version_s);
    free(subInfo_s);
    free(PKeyInfo_s);
    free(csr_s);
    
    return buffer;
}

uint8_t *serialize_certificate(Certificate *cert, size_t *outputSize){

    size_t ver_size, ser_size, subSignAlgo_size, issuerInfo_size, validFrom_size, validTo_size, subInfo_size, subPubKey_size;
    
    uint8_t *version_s = serialize_version(cert->version, &ver_size);
    uint8_t *serialNumber_s = serialize_serialNumber(cert->serialNumber, &ser_size);
    uint8_t *subSignAlgo_s = serialize_subSignAlgo(cert->subject_signAlgorithm, &subSignAlgo_size);
    uint8_t *issuerInfo_s = serialize_issuerInfo(cert->issuer, &issuerInfo_size);
    uint8_t *validFrom_s = serialize_validity(cert->validFrom, &validFrom_size);
    uint8_t *validTo_s = serialize_validity(cert->validTo, &validTo_size);
    uint8_t *subInfo_s = serialize_subInfo(cert->subject, &subInfo_size);
    uint8_t *subPubKey_s = serialize_subPubKeyInfo(*cert->subject_pubKey, &subPubKey_size);

    size_t cert_size = ver_size + ser_size + subSignAlgo_size + issuerInfo_size + validFrom_size + validTo_size + subInfo_size + subPubKey_size;
    uint8_t *certificate_s = (uint8_t *)malloc(cert_size);
    if(!certificate_s){
        perror("Memory allocation failed");
        *outputSize = 0;
        return NULL;
    }

    int index = 0;

    #define COLLECT_INDIVIDUAL(individual, individual_size)          \
        memcpy(certificate_s + index, individual, individual_size);      \
        index += individual_size;

        COLLECT_INDIVIDUAL(version_s, ver_size);
        COLLECT_INDIVIDUAL(serialNumber_s, ser_size);
        COLLECT_INDIVIDUAL(subSignAlgo_s, subSignAlgo_size);
        COLLECT_INDIVIDUAL(issuerInfo_s, issuerInfo_size);
        COLLECT_INDIVIDUAL(validFrom_s, validFrom_size);
        COLLECT_INDIVIDUAL(validTo_s, validTo_size);
        COLLECT_INDIVIDUAL(subInfo_s, subInfo_size);
        COLLECT_INDIVIDUAL(subPubKey_s, subPubKey_size);

    #undef COLLECT_INDIVIDUAL

    uint8_t *buffer = serialize_sequence(outputSize, cert_size, certificate_s);
    
    free(version_s);
    free(serialNumber_s);
    free(subSignAlgo_s);
    free(issuerInfo_s);
    free(validFrom_s);
    free(validTo_s);
    free(subInfo_s);
    free(subPubKey_s);
    free(certificate_s);

    return buffer;
}

uint8_t *serialize_subSignAlgo(const char *algorithm, size_t *outputSize){
    return serialize_string(outputSize, MY_ASN1_UTF8STRING, algorithm);
}

uint8_t *serialize_signature(Signature signature, size_t *outputSize){

    size_t signAlgoIdentifier_size, signValue_size;
    
    uint8_t *signAlgoIdentifier_s = serialize_string(&signAlgoIdentifier_size, MY_ASN1_UTF8STRING, signature.algorithmIdentifier);
    uint8_t *signValue_s = serialize_mpz(&signValue_size, signature.value);

    *outputSize = signAlgoIdentifier_size + signValue_size;
    uint8_t *buffer = (uint8_t *)malloc(*outputSize);
    if(!buffer){
        perror("Memory allocation failed");
        *outputSize = 0;
        return NULL;
    }

    int index = 0;
    memcpy(buffer + index, signAlgoIdentifier_s, signAlgoIdentifier_size);
    index += signAlgoIdentifier_size;

    memcpy(buffer + index, signValue_s, signValue_size);
    index += signValue_size;

    free(signAlgoIdentifier_s);
    free(signValue_s);
    return buffer;
}


