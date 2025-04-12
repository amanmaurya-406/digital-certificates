#include "common.h"
#include "config.h"
#include "asn1.h"
#include "encodeKey.h"
#include <math.h>

static void write_pem(const char *filename, const char *header, const char *base64_data){
    FILE *file = fopen(filename, "w");
    if(!file){
        perror("Error opening output file");
        return;
    }
    
    fprintf(file, "-----BEGIN %s-----\n", header);
    
    int len = strlen(base64_data);
    for (int i = 0; i < len; i += 64) {
        fprintf(file, "%.64s\n", base64_data + i);
    }
    
    fprintf(file, "-----END %s-----", header); 
    fclose(file);
}

static char* read_pem(const char *filename){
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Error opening input file");
        return NULL;
    }
    
    unsigned char buffer[65];
    char *base64_data = NULL;
    size_t current_length = 0;
    
    while(fgets((char *)buffer, sizeof(buffer), file)){
        // Skip header and footer lines
        if(strstr((char *)buffer, "-----") != NULL){
            continue;
        }
        
        // Remove the trailing newline
        size_t buffer_len = strlen((char *)buffer);
        if(buffer[buffer_len - 1] == '\n'){
            buffer[buffer_len - 1] = '\0';
            buffer_len -= 1;
        }
        
        // Reallocate memory for concatenating the new line
        base64_data = realloc(base64_data, current_length + buffer_len + 1);
        if(!base64_data){
            perror("Memory allocation failed");
            fclose(file);
            return NULL;
        }
        
        strcpy((char *)base64_data + current_length, (char *)buffer);
        current_length += buffer_len;
    }
    
    fclose(file);
    
    return base64_data;
}

#include <openssl/evp.h>

static char* encode_base64(const unsigned char* input, size_t input_length){
    
    size_t b64_length = 4 * ceil((input_length + 2)/ 3.0);
    char* b64 = malloc(b64_length + 1);
    if(!b64){
        perror("Memory allocation failed");
        return NULL;
    }

    int len = EVP_EncodeBlock((unsigned char*)b64, input, input_length);
    b64[len] = '\0';

    return b64;
}

static char* decode_base64(const char* b64){

    size_t b64_length = strlen(b64);
    size_t der_length = 3 * b64_length / 4;

    uint8_t *der = malloc(der_length + 1);
    if(!der){
        perror("Memory allocation failed");
        return NULL; 
    }

    EVP_DecodeBlock(der, (const unsigned char*)b64, b64_length);
    return der;
}




static uint8_t *encode_privateKey_der(size_t *countp, mpz_t modulus, mpz_t pub_exp, 
        mpz_t priv_exp, mpz_t prime1, mpz_t prime2, mpz_t p_1, mpz_t q_1){

    uint8_t version_s[] = { 0x02, 0x01, 0x00 };     // Serilaizing version
    size_t version_size = sizeof(version_s);

    size_t modulus_size, pubExp_size, privExp_size, prime1_size, prime2_size, \
        exponent1_size, exponent2_size, coefficient_size;
    
    mpz_t exponent1, exponent2, coefficient;
    mpz_inits(exponent1, exponent2, coefficient, NULL);

    mpz_mod(exponent1, priv_exp, p_1);
    mpz_mod(exponent2, priv_exp, q_1);
    mpz_invert(coefficient, prime2, prime1);

    uint8_t *modulus_s = serialize_mpz(&modulus_size, modulus); 
    uint8_t *pubExp_s = serialize_mpz(&pubExp_size, pub_exp);
    uint8_t *privExp_s = serialize_mpz(&privExp_size, priv_exp);
    uint8_t *prime1_s = serialize_mpz(&prime1_size, prime1);
    uint8_t *prime2_s = serialize_mpz(&prime2_size, prime2);
    uint8_t *exponent1_s = serialize_mpz(&exponent1_size, exponent1);
    uint8_t *exponent2_s = serialize_mpz(&exponent2_size, exponent2);
    uint8_t *coefficient_s = serialize_mpz(&coefficient_size, coefficient);

    size_t total_size = version_size + modulus_size + pubExp_size + privExp_size + \
        prime1_size + prime2_size + exponent1_size + exponent2_size + coefficient_size;
    uint8_t *total_s = (uint8_t *)malloc(total_size);
    if(!total_s){
        perror("Memory allocation failed\n");
        *countp = 0;
        return NULL;
    }

    int index = 0;

    #define COLLECT_INDIVIDUAL(val_s, val_size)     \
        memcpy(total_s + index, val_s, val_size);       \
        index += val_size;

        COLLECT_INDIVIDUAL(version_s, version_size);
        COLLECT_INDIVIDUAL(modulus_s, modulus_size);
        COLLECT_INDIVIDUAL(pubExp_s, pubExp_size);
        COLLECT_INDIVIDUAL(privExp_s, privExp_size);
        COLLECT_INDIVIDUAL(prime1_s, prime1_size);
        COLLECT_INDIVIDUAL(prime2_s, prime2_size);
        COLLECT_INDIVIDUAL(exponent1_s, exponent1_size);
        COLLECT_INDIVIDUAL(exponent2_s, exponent2_size);
        COLLECT_INDIVIDUAL(coefficient_s, coefficient_size);

    #undef COLLECT_INDIVIDUAL

    uint8_t *buffer = serialize_sequence(countp, total_size, total_s);

    free(modulus_s);
    free(pubExp_s);
    free(privExp_s);
    free(prime1_s);
    free(prime2_s);
    free(exponent1_s);
    free(exponent2_s);
    free(coefficient_s);
    free(total_s);
    mpz_clears(exponent1, exponent2, coefficient, NULL);
    
    return buffer;
}

void write_privateKey_der(const char *filename, mpz_t modulus, mpz_t pub_exp, 
    mpz_t priv_exp, mpz_t prime1, mpz_t prime2, mpz_t p_1, mpz_t q_1){

    size_t der_size;
    uint8_t *der = encode_privateKey_der(&der_size, modulus, pub_exp, priv_exp, prime1, prime2, p_1, q_1);
    if(!der){ return; }

    FILE *fptr = fopen(filename, "wb");
    if(!fptr){
        perror("Error opening file\n");
        return;
    }

    size_t bytesWritten = fwrite(der, 1, der_size, fptr);
    if(bytesWritten != der_size){
        perror("Full data is not written");
    }

    free(der);
    fclose(fptr);
}

void write_privateKey_pem(const char *filename, mpz_t modulus, mpz_t pub_exp, 
    mpz_t priv_exp, mpz_t prime1, mpz_t prime2, mpz_t p_1, mpz_t q_1){

    size_t der_size;
    uint8_t *der = encode_privateKey_der(&der_size, modulus, pub_exp, priv_exp, prime1, prime2, p_1, q_1);
    if(!der){ return; }

    uint8_t *b64 = encode_base64(der, der_size);
    if(!b64){ return; }

    write_pem(filename, "RSA PRIVATE KEY", b64);

    free(der);
    free(b64);
}



PrivateKey *load_privateKey(const char *filename){

    char *b64 = read_pem(filename);
    if(!b64){ return NULL; }

    char *der = decode_base64(b64);
    free(b64);
    if(!der){ return NULL; };

    int idx = 0;
    /* printf("Sequence tag = [0x%02x]\n", */ idx++;
    read_asn1_length(der, &idx);
    
    int version;
    idx += deserialize_integer(&version, der + idx);
    
    PrivateKey *privateKey = (PrivateKey *)malloc(sizeof(PrivateKey));
    if(!privateKey){
        perror("Memory allocation failed");
        return NULL;
    }

    mpz_inits(privateKey->modulus, privateKey->pub_exp, privateKey->priv_exp, 
              privateKey->p, privateKey->q, privateKey->dmp1, 
              privateKey->dmq1, privateKey->iqmp, NULL);
    
    idx += deserialize_mpz(privateKey->modulus, der + idx);
    idx += deserialize_mpz(privateKey->pub_exp, der + idx);
    idx += deserialize_mpz(privateKey->priv_exp, der + idx);
    idx += deserialize_mpz(privateKey->p, der + idx);
    idx += deserialize_mpz(privateKey->q, der + idx);
    idx += deserialize_mpz(privateKey->dmp1, der + idx);
    idx += deserialize_mpz(privateKey->dmq1, der + idx);
    idx += deserialize_mpz(privateKey->iqmp, der + idx);

    return privateKey;
}

PublicKey *load_publicBytes(const char *filename){
    char *b64 = read_pem(filename);
    if(!b64){ return NULL; }

    char *der = decode_base64(b64);
    free(b64);
    if(!der){ return NULL; };

    int idx = 0;
    /* printf("Sequence tag = [0x%02x]\n", */ idx++;
    read_asn1_length(der, &idx);

    int version;
    idx += deserialize_integer(&version, der + idx);

    PublicKey *publicKey = (PublicKey *)malloc(sizeof(PublicKey));
    if(!publicKey){
        perror("Memory allocation failed");
        return NULL;
    }

    mpz_inits(publicKey->modulus, publicKey->exponent, NULL);

    idx += deserialize_mpz(publicKey->modulus, der + idx);
    idx += deserialize_mpz(publicKey->exponent, der + idx);

    free(der);
    return publicKey;
}

PublicKey *extract_publicBytes(PrivateKey *privateKey){

    PublicKey *publicKey = (PublicKey *)malloc(sizeof(PublicKey));
    if(!publicKey){
        perror("Memory allocation failed");
        return NULL;
    }
    
    mpz_inits(publicKey->modulus, publicKey->exponent, NULL);
    
    mpz_set(publicKey->modulus, privateKey->modulus);
    mpz_set(publicKey->exponent, privateKey->pub_exp);
    
    return publicKey;
}

void free_publicKey(PublicKey *publicKey){
    mpz_clears(publicKey->modulus, publicKey->exponent, NULL);
    
    free(publicKey);
}

void free_privateKey(PrivateKey *privateKey){
    mpz_clears(privateKey->modulus, privateKey->pub_exp, privateKey->priv_exp, NULL);
    mpz_clears(privateKey->p, privateKey->q, privateKey->dmp1, NULL);
    mpz_clears(privateKey->dmq1, privateKey->iqmp, NULL);

    free(privateKey);
}
