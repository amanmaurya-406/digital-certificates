#include "common.h"
#include "asn1.h"
#include "serialize.h"



/**
 * @brief Serializes the CSR version in ASN.1 DER format.
 *
 * @param version Version string (e.g., 0 for v1).
 * @param outputsize Pointer to store the size of the serialized version.
 * @return uint8_t* Pointer to the serialized version buffer. Must be freed after use.
 */
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

/**
 * @brief Serializes the subject information into ASN.1 DER format.
 *
 * @param subInfo SubjectInfo structure containing subject data.
 * @param outputSize Pointer to store the size of the serialized subject info.
 * @return uint8_t* Pointer to the serialized subject info buffer. Must be freed after use.
 */
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


/**
 * @brief Serializes the public key information in ASN.1 DER format.
 *
 * This function encapsulates the RSA public key along with the algorithm identifier,
 * producing a sequence suitable for inclusion in a CSR.
 *
 * @param publicKey SubjectPublicKey structure containing subject's public key data.
 * @param outputSize Pointer to store the size of the serialized public key information.
 * @return uint8_t* Pointer to the serialized public key information buffer. Must be freed after use.
 */
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


/**
 * @brief Serializes the entire CSR structure into ASN.1 DER format.
 *
 * Combines the version, subject information, public key, and signature into a
 * complete Certificate Signing Request (CSR) in DER format.
 *
 * @param csr The CSR structure containing all the required fields.
 * @param outputSize Pointer to store the length of the serialized CSR.
 * @return uint8_t* Pointer to the serialized CSR buffer. Must be freed after use.
 */
uint8_t *serialize_CSR(CSR csr, size_t *outputSize){
    
    size_t ver_size, subInfo_size, PKeyInfo_size;
    
    uint8_t *version_s = serialize_version(csr.version, &ver_size);
    uint8_t *subInfo_s = serialize_subInfo(csr.subject_info, &subInfo_size);
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

uint8_t *serialize_certificate(Certificate cert, size_t *outputSize){

    size_t ver_size, ser_size, subSignAlgo_size, issuerInfo_size, validFrom_size, validTo_size, subInfo_size, subPubKey_size;
    
    uint8_t *version_s = serialize_version(cert.version, &ver_size);
    uint8_t *serialNumber_s = serialize_serialNumber(cert.serialNumber, &ser_size);
    uint8_t *subSignAlgo_s = serialize_subSignAlgo(cert.subject_signAlgorithm, &subSignAlgo_size);
    uint8_t *issuerInfo_s = serialize_issuerInfo(cert.issuer, &issuerInfo_size);
    uint8_t *validFrom_s = serialize_validity(cert.validFrom, &validFrom_size);
    uint8_t *validTo_s = serialize_validity(cert.validTo, &validTo_size);
    uint8_t *subInfo_s = serialize_subInfo(cert.subject_name, &subInfo_size);
    uint8_t *subPubKey_s = serialize_subPubKeyInfo(*cert.subject_pubKey, &subPubKey_size);

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

/**
 * @brief Serializes the signature into ASN.1 DER format.
 *
 * Converts the RSA signature represented by an mpz_t to a DER-encoded INTEGER.
 *
 * @param signature The signature to be serialized.
 * @param outputSize Pointer to store the size of the serialized signature.
 * @return uint8_t* Pointer to the serialized signature buffer. Must be freed after use.
 */
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


// CSR
/* 
CertificationRequest ::= SEQUENCE {
    certificationRequestInfo SEQUENCE {
        version INTEGER (0),
        subject Name ::= SEQUENCE {
            SET {
                SEQUENCE {
                    OBJECT IDENTIFIER countryName (2.5.4.6),
                    PrintableString "US"
                }
            },
            SET {
                SEQUENCE {
                    OBJECT IDENTIFIER stateOrProvinceName (2.5.4.8),
                    UTF8String "asdfgj"
                }
            },
            SET {
                SEQUENCE {
                    OBJECT IDENTIFIER localityName (2.5.4.7),
                    UTF8String "gfdsa"
                }
            },
            SET {
                SEQUENCE {
                    OBJECT IDENTIFIER organizationName (2.5.4.10),
                    UTF8String "oiuytrew"
                }
            },
            SET {
                SEQUENCE {
                    OBJECT IDENTIFIER organizationalUnitName (2.5.4.11),
                    UTF8String "okmnbgf"
                }
            },
            SET {
                SEQUENCE {
                    OBJECT IDENTIFIER commonName (2.5.4.3),
                    UTF8String "kjbvcxsfg.com"
                }
            }
        },
        subjectPublicKeyInfo SubjectPublicKeyInfo ::= SEQUENCE {
            algorithm AlgorithmIdentifier ::= SEQUENCE {
                OBJECT IDENTIFIER rsaEncryption (1.2.840.113549.1.1.1),
                NULL
            },
            subjectPublicKey BIT STRING (a wrapper around modulus + public bytes with initial 0x00)
        },
        attributes [0] IMPLICIT SET OF Attribute
    },
    signatureAlgorithm AlgorithmIdentifier ::= SEQUENCE {
        OBJECT IDENTIFIER sha256WithRSAEncryption (1.2.840.113549.1.1.11),
        NULL
    },
    signature BIT STRING
}
*/
/**
 * @brief Encodeing objects
 * 
 * Let's say the OID is: 1.2.840.113549.1.1.1
 * ✅ Step 1: The First Byte
 * First two components are encoded as:
 * (first_number * 40) + second_number
 * (1 * 40) + 2 = 42 → 0x2A
 * 
 * ✅ Step 2: Encode Remaining Components in Base-128 (7-bit chunks)
 * Each component is encoded as:
 * Split into 7-bit chunks
 * Set MSB = 1 for all chunks except the last one
 * Combine bytes
 * 
 * Example:
 * 840 in binary = 1101001000 → 7-bit chunks: 0000100 1010000
 * add MSB: 10000100 01010000 → encoded as: 0x86 0x48
 * 113549 → encoded as: 0x86 0xF7 0x0D
 * 1 → 0x01
 * 1 → 0x01
 * 1 → 0x01
 * 
 */
// Exapmle
/*
0x30 <totalLen>                  ; SEQUENCE (CSR)
|
├── 0x30 <csrInfoLen>            ; SEQUENCE (CertificationRequestInfo)
|   |
|   ├── 0x02 0x01 0x00           ; INTEGER version (0)
|   |
|   ├── 0x30 <subjectLen>        ; SEQUENCE (subject - Name)
|   |   ├── 0x31                 ; SET (RDN - countryName)
|   |   |   └── 0x30             ; SEQUENCE (AttributeTypeAndValue)
|   |   |       ├── 0x06         ; OBJECT IDENTIFIER
|   |   |       └── 0x13 0x02 IN ; PrintableString (countryName = "IN")
|   |   |
|   |   ├── 0x31                 ; SET (RDN - stateOrProvinceName)
|   |   |   └── 0x30             ; SEQUENCE (AttributeTypeAndValue)
|   |   |       ├── 0x06         ; OBJECT IDENTIFIER
|   |   |       └── 0x0C 0x02 IN ; PrintableString (countryName = "WEST BENGAL")
|   |   |
|   |   ├── 0x31 ...             ; SET (localityName = "HOWRAH")
|   |   ├── 0x31 ...             ; SET (organizationName = "IIEST SHIBPUR")
|   |   ├── 0x31 ...             ; SET (organizationalUnitName = "CST")
|   |   └── 0x31 ...             ; SET (commonName = "example.com")
|   |
|   └── 0x30 <subjectPKInfoLen>  ; SEQUENCE (SubjectPublicKeyInfo)
|       |
|       ├── 0x30 ...             ; SEQUENCE (AlgorithmIdentifier)
|       |   ├── 0x06 ...         ; OBJECT (rsaEncryption)
|       |   └── 0x05 0x00        ; NULL
|       |
|       └── 0x03 LEN             ; BIT STRING (public key)
|           ├── 0x00
|           └── 0x30 82 01 0A       ; <DER encoded RSAPublicKey>
|               ├── 0x02 82 01 00   ; INTEGER, length 256 (modulus)
|               ├── <modulus bytes>
|               ├── 0x02 03         ; INTEGER, length 3 (public exponent)
|               └── 01 00 01
|   
├── [0]                          ; context-specific tag (attributes - usually omitted in simple CSRs)
|
├── 0x30 <sigAlgLen>             ; SEQUENCE (Signature Algorithm)
|   ├── 0x06 ...                 ; OBJECT (sha256WithRSAEncryption)
|   └── 0x05 0x00                ; NULL
|
└── 0x03 LEN                     ; BIT STRING (Signature)
    ├── 0x00
    └── 0x30 82 01 0A            ; <DER encoded Signature>
        ├── 0x02 82 01 00        ; INTEGER, length (signature)
        └── <modulus bytes>

*/

// Certificate
/*
    1. Certificate
        Certificate ::= SEQUENCE {
            version             IA5String(0x16) - x509_v3
            serialNumber        INTEGER(0x02)
            subSignAlgorithm    IA5String(0x16) - sha512WithRSAEncryption
            issuer              IssuerInfo
            validity            Validity
            subject             SubjectInfo
            subjectPKInfo       SubjectPublicKeyInfo
        }
            
        IssuerInfo ::= SEQUENCE {
            IA5String(0x16)     IN
            IA5String(0x16)     Private CA
        }

        Validity ::= SEQUENCE {
            notBefore           NotBefore
            notAfter            NotAfter
        }

        NotBefore, NotAfter ::= SEQUENCE {
            INTEGER(0x02)       month
            INTEGER(0x02)       day
            INTEGER(0x02)       hour
            INTEGER(0x02)       minute
            INTEGER(0x02)       second
            INTEGER(0x02)       year
        }

        SubjectInfo ::= SEQUENCE {
            IA5String(0x16)     IN
            IA5String(0x16)     WEST BENGAL
            IA5String(0x16)     HOWRAH
            IA5String(0x16)     IIEST SHIBPUR
            IA5String(0x16)     example.com
        }
            
        SubjectPublicKeyInfo ::= SEQUENCE {
            IA5String(0x16)     rsaEncryption
            subjectPublicKey    publicKey => BIT STRING ::= 2048-bit RSA Key (Modulus + Exponent)
        }
        
        PublicKey ::= SEQUENCE {
            INTEGER             Public Key Size
            INTEGER             Modulus 
            INTEGER             Public Exponent
        }
                
    2. SignatureAlgorithm:
            IA5String(0x16)	        sha512WithRSAEncryption

    3. Signature Value:
            INTEGER(0x02)           Signature
*/
// Exapmle
/*
    0x30 totalLen
        0x16 len version
        0x02 len serialNumber
        0x16 len subSignAlgorithm - sha512WithRSAEncryption
        0x30 issuerInfolen (Issuer Information)
            0x16 len IN
            0x16 len Private CA
        0x30 validityLen
            0x30 notBeforeLen
                0x02 len month
                0x02 len day
                0x02 len hour
                0x02 len minute
                0x02 len second
                0x02 len year
            0x30 notAfterLen
                0x02 len month
                0x02 len day
                0x02 len hour
                0x02 len minute
                0x02 len second
                0x02 len year
        0x30 subjectInfoLen (Subject Information)
            0x16 len IN
            0x16 len WEST BENGAL
            0x16 len HOWRAH
            0x16 len IIEST SHIBPUR
            0x16 len example.com
        0x30 subjectPKInfoLen (Public Key Information)
            0x16 len pubKeyAlgorithm - rsaEncryption
            0x30 keyLen(modulus + exponent)
                0x02 pubKeyLen pubKeySize
                0x02 modLen modData
                0x02 keylen keyData
    0x16 len certificateSignAlgorithm - sha512WithRSAEncryption
    0x02 len signature
*/




