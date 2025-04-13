#include "common.h"
#include "asn1.h"
#include "serialize.h"



uint8_t *serialize_version(int version, size_t *outputSize){
    return serialize_integer(outputSize, version);
}

uint8_t *serialize_serialNumber(mpz_t serialNumber, size_t *outputSize){
    return serialize_mpz(outputSize, serialNumber);
}

uint8_t *serialize_issuerInfo(DName *issuer, size_t *outputSize){
    
    size_t country_size, org_size;
    
    uint8_t *country_s = serialize_string(&country_size, MY_ASN1_PRINTABLESTRING, issuer->country);
    uint8_t *org_s = serialize_string(&org_size, MY_ASN1_UTF8STRING, issuer->org);

    size_t issuerInfo_size = country_size + org_size;
    uint8_t *issuerInfo_s = malloc(issuerInfo_size);
    if(!issuerInfo_s){
        perror("Error serializing Issuer Info");
        *outputSize = 0;
        return NULL;
    }

    memcpy(issuerInfo_s, country_s, country_size);
    memcpy(issuerInfo_s + country_size, org_s, org_size);

    uint8_t *buffer = serialize_sequence(outputSize, issuerInfo_size, issuerInfo_s);
    
    free(country_s);
    free(org_s);
    free(issuerInfo_s);
    return buffer;
}

uint8_t *serialize_time(Time *t, size_t *outputSize){

    size_t year_size, month_size, day_size, hour_size, minute_size, second_size;

    uint8_t *year_s = serialize_integer(&year_size, t->year);
    uint8_t *month_s = serialize_integer(&month_size, t->month);
    uint8_t *day_s = serialize_integer(&day_size, t->day);
    uint8_t *hour_s = serialize_integer(&hour_size, t->hour);
    uint8_t *minute_s = serialize_integer(&minute_size, t->minute);
    uint8_t *second_s = serialize_integer(&second_size, t->second);

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

uint8_t *serialize_subInfo(DName *subject, size_t *outputSize){

    size_t country_size, state_size, city_size, org_size, unit_size, name_size;
    
    uint8_t *country_s = serialize_string(&country_size, MY_ASN1_PRINTABLESTRING, subject->country);
    uint8_t *state_s = serialize_string(&state_size, MY_ASN1_UTF8STRING, subject->state);
    uint8_t *city_s = serialize_string(&city_size, MY_ASN1_UTF8STRING, subject->city);
    uint8_t *org_s = serialize_string(&org_size, MY_ASN1_UTF8STRING, subject->org);
    uint8_t *unit_s = serialize_string(&unit_size, MY_ASN1_UTF8STRING, subject->org);
    uint8_t *name_s = serialize_string(&name_size, MY_ASN1_UTF8STRING, subject->name);

    size_t subInfo_size = country_size + state_size + city_size + org_size + unit_size + name_size;
    uint8_t *subInfo_s = (uint8_t *)malloc(subInfo_size);
    if(!subInfo_s){
        perror("Error seriliazing DName");
        *outputSize = 0;
        return NULL;
    }
    
    int index = 0;

    #define COLLECT_INDIVIDUAL(individual, individual_size)         \
        memcpy(subInfo_s + index, individual, individual_size);             \
        index += individual_size;

        COLLECT_INDIVIDUAL(country_s, country_size);
        COLLECT_INDIVIDUAL(state_s, state_size);
        COLLECT_INDIVIDUAL(city_s, city_size);
        COLLECT_INDIVIDUAL(org_s, org_size);
        COLLECT_INDIVIDUAL(unit_s, unit_size);
        COLLECT_INDIVIDUAL(name_s, name_size);

    #undef COLLECT_INDIVIDUAL

    uint8_t *buffer = serialize_sequence(outputSize, subInfo_size, subInfo_s);
    
    free(country_s);
    free(state_s);
    free(city_s);
    free(org_s);
    free(unit_s);
    free(name_s);
    free(subInfo_s);

    return buffer;
}

uint8_t *serialize_pKeyInfo(PKeyInfo *pKeyInfo, size_t *outputSize){

    // Serialize algorithm
    size_t pubKeyAlgo_size;
    uint8_t *pubKeyAlgo_s = serialize_string(&pubKeyAlgo_size, MY_ASN1_UTF8STRING, pKeyInfo->pubKeyAlgo);
    
    // Serialize modulus
    size_t mod_size;
    uint8_t *mod_s = serialize_mpz(&mod_size, pKeyInfo->pubKey->n);

    // Serialize Public exponent
    size_t exp_size;
    uint8_t *exp_s = serialize_mpz(&exp_size, pKeyInfo->pubKey->e);

    // wrapping key components in sequence
    size_t pubKey_size = mod_size + exp_size;
    uint8_t *pubKey_s = malloc(pubKey_size);
    if(!pubKey_s){
        perror("Error serializing public key");
        *outputSize = 0;
        return NULL;
    }

    memcpy(pubKey_s, mod_s, mod_size);
    memcpy(pubKey_s + mod_size, exp_s, exp_size);

    size_t xxx_size;
    uint8_t *xxx_s = serialize_sequence(&xxx_size, pubKey_size, pubKey_s);

    // wrapping algorithm and public key
    size_t pubKeyInfo_size = pubKeyAlgo_size + xxx_size;
    uint8_t *pubKeyInfo_s = (uint8_t *)malloc(pubKeyInfo_size);
    if(!pubKeyInfo_s){
        perror("Error serializing PKeyInfo");
        *outputSize = 0;
        return NULL;
    }

    memcpy(pubKeyInfo_s, pubKeyAlgo_s, pubKeyAlgo_size);
    memcpy(pubKeyInfo_s + pubKeyAlgo_size, xxx_s, xxx_size);


    uint8_t *buffer = serialize_sequence(outputSize, pubKeyInfo_size, pubKeyInfo_s);

    free(pubKeyAlgo_s);
    free(mod_s);
    free(exp_s);
    free(pubKey_s);
    free(xxx_s);
    free(pubKeyInfo_s);
    
    return buffer;
}

uint8_t *serialize_CSRInfo(CSRInfo *csrInfo, size_t *outputSize){
    
    size_t ver_size, subInfo_size, pKeyInfo_size;
    
    uint8_t *version_s = serialize_version(csrInfo->version, &ver_size);
    uint8_t *subInfo_s = serialize_subInfo(csrInfo->subject, &subInfo_size);
    uint8_t *pKeyInfo_s = serialize_pKeyInfo(csrInfo->pKeyInfo, &pKeyInfo_size);
    
    size_t csr_size = ver_size + subInfo_size + pKeyInfo_size;
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
        COLLECT_INDIVIDUAL(pKeyInfo_s, pKeyInfo_size);

    #undef COLLECT_INDIVIDUAL
    
    uint8_t *buffer = serialize_sequence(outputSize, csr_size, csr_s);
    
    free(version_s);
    free(subInfo_s);
    free(pKeyInfo_s);
    free(csr_s);
    
    return buffer;
}

uint8_t *serialize_tbsCertificate(TBSCertificate *tbsCert, size_t *outputSize){

    size_t ver_size, ser_size, signatureAlgo_size, issuerInfo_size, validFrom_size, validTo_size, subInfo_size, pKeyInfo_size;
    
    uint8_t *version_s = serialize_version(tbsCert->version, &ver_size);
    uint8_t *serialNumber_s = serialize_serialNumber(tbsCert->serialNumber, &ser_size);
    uint8_t *signatureAlgo_s = serialize_signAlgo(tbsCert->signatureAlgo, &signatureAlgo_size);
    uint8_t *issuerInfo_s = serialize_issuerInfo(tbsCert->issuer, &issuerInfo_size);
    uint8_t *validFrom_s = serialize_time(tbsCert->validity->validFrom, &validFrom_size);
    uint8_t *validTo_s = serialize_time(tbsCert->validity->validTo, &validTo_size);
    uint8_t *subInfo_s = serialize_subInfo(tbsCert->subject, &subInfo_size);
    uint8_t *pKeyInfo_s = serialize_pKeyInfo(tbsCert->pKeyInfo, &pKeyInfo_size);

    size_t tbsCert_size = ver_size + ser_size + signatureAlgo_size + issuerInfo_size + validFrom_size + validTo_size + subInfo_size + pKeyInfo_size;
    uint8_t *tbsCert_s = (uint8_t *)malloc(tbsCert_size);
    if(!tbsCert_s){
        perror("Memory allocation failed");
        *outputSize = 0;
        return NULL;
    }

    int index = 0;

    #define COLLECT_INDIVIDUAL(val_s, val_size)          \
        memcpy(tbsCert_s + index, val_s, val_size);      \
        index += val_size;

        COLLECT_INDIVIDUAL(version_s, ver_size);
        COLLECT_INDIVIDUAL(serialNumber_s, ser_size);
        COLLECT_INDIVIDUAL(signatureAlgo_s, signatureAlgo_size);
        COLLECT_INDIVIDUAL(issuerInfo_s, issuerInfo_size);
        COLLECT_INDIVIDUAL(validFrom_s, validFrom_size);
        COLLECT_INDIVIDUAL(validTo_s, validTo_size);
        COLLECT_INDIVIDUAL(subInfo_s, subInfo_size);
        COLLECT_INDIVIDUAL(pKeyInfo_s, pKeyInfo_size);

    #undef COLLECT_INDIVIDUAL

    uint8_t *buffer = serialize_sequence(outputSize, tbsCert_size, tbsCert_s);
    
    free(version_s);
    free(serialNumber_s);
    free(signatureAlgo_s);
    free(issuerInfo_s);
    free(validFrom_s);
    free(validTo_s);
    free(subInfo_s);
    free(pKeyInfo_s);
    free(tbsCert_s);

    return buffer;
}

uint8_t *serialize_signAlgo(const char *algorithm, size_t *outputSize){
    return serialize_string(outputSize, MY_ASN1_UTF8STRING, algorithm);
}

uint8_t *serialize_signature(mpz_t signature, size_t *outputSize){
    return serialize_mpz(outputSize, signature);
}


