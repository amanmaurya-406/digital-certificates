#include "common.h"
#include "config.h"
#include "asn1.h"
#include "encodeKey.h"
#include "utils.h"
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




static uint8_t *encode_privateKey_der(size_t *countp, PrivateKey *privKey){

    uint8_t version_s[] = { 0x02, 0x01, privKey->version };     // Serilaizing version
    size_t version_size = sizeof(version_s);

    size_t n_size, e_size, d_size, p_size, q_size, dmp1_size, dmq1_size, iqmp_size;

    uint8_t *n_s    = serialize_mpz(&n_size, privKey->n); 
    uint8_t *e_s    = serialize_mpz(&e_size, privKey->e);
    uint8_t *d_s    = serialize_mpz(&d_size, privKey->d);
    uint8_t *p_s    = serialize_mpz(&p_size, privKey->p);
    uint8_t *q_s    = serialize_mpz(&q_size, privKey->q);
    uint8_t *dmp1_s  = serialize_mpz(&dmp1_size, privKey->dmp1);
    uint8_t *dmq1_s  = serialize_mpz(&dmq1_size, privKey->dmq1);
    uint8_t *iqmp_s = serialize_mpz(&iqmp_size, privKey->iqmp);

    size_t total_size = version_size + n_size + e_size + d_size + \
        p_size + q_size + dmp1_size + dmq1_size + iqmp_size;
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
        COLLECT_INDIVIDUAL(n_s, n_size);
        COLLECT_INDIVIDUAL(e_s, e_size);
        COLLECT_INDIVIDUAL(d_s, d_size);
        COLLECT_INDIVIDUAL(p_s, p_size);
        COLLECT_INDIVIDUAL(q_s, q_size);
        COLLECT_INDIVIDUAL(dmp1_s, dmp1_size);
        COLLECT_INDIVIDUAL(dmq1_s, dmq1_size);
        COLLECT_INDIVIDUAL(iqmp_s, iqmp_size);

    #undef COLLECT_INDIVIDUAL

    uint8_t *der = serialize_sequence(countp, total_size, total_s);

    free(n_s);
    free(e_s);
    free(d_s);
    free(p_s);
    free(q_s);
    free(dmp1_s);
    free(dmq1_s);
    free(iqmp_s);
    free(total_s);
    
    return der;
}

void i2d_RSAPrivateKey(const char *filename, PrivateKey *privKey){

    size_t der_size;
    uint8_t *der = encode_privateKey_der(&der_size, privKey);
    if(!der){ 
        printf("DER encoding failed.\n");
        return; 
    }

    FILE *fptr = fopen(filename, "wb");
    if(!fptr){
        perror("Error opening file\n");
        free(der);
        return;
    }

    size_t bytesWritten = fwrite(der, 1, der_size, fptr);
    if(bytesWritten != der_size){
        perror("Full data is not written");
    }

    free(der);
    fclose(fptr);
}

void i2pem_RSAPrivateKey(const char *filename, PrivateKey *privKey){

    size_t der_size;
    uint8_t *der = encode_privateKey_der(&der_size, privKey);
    if(!der){ return; }

    uint8_t *b64 = encode_base64(der, der_size);
    if(!b64){ return; }

    write_pem(filename, "RSA PRIVATE KEY", b64);

    free(der);
    free(b64);
}


static size_t read_asn1_len(FILE *fptr){

    size_t length = 0;
    
    uint8_t first_byte;
    fread(&first_byte, 1, 1, fptr);

    if(first_byte & 0x80){
        uint8_t len_size = first_byte & 0x7F;

        for(uint8_t j = 0; j < len_size; j++){
            uint8_t temp;
            fread(&temp, 1, 1, fptr);
            length = (length << 8) | temp;
        }
    }
    else{
        length = first_byte;
    }

    return length;
}

static int deserialize_int(uint8_t *buffer, int len){
    int value = 0;
    for(int i = 0; i < len; i++){
        value = (value << 8) | buffer[i];
    }
    return value;
}

# define ASN1_SEQUENCE (MY_ASN1_SEQUENCE | 0x20)

int handle_privateKey_components(PrivateKey *privKey, mpz_t **fields, int con, FILE *fptr, size_t len){

    uint8_t buffer[len];
    if(fread(buffer, 1, len, fptr) != len)
        return 0;

    if(con == 0){
        privKey->version = deserialize_int(buffer, len);
    }
    else if(con >= 1 && con <= 8){
        mpz_import(*fields[con - 1], len, 1, 1, 0, 0, buffer);
    }

    return 1;
}

PrivateKey *d2i_RSAPrivateKey(const char *filename){
    FILE *fptr = fopen(filename, "rb");
    if(!fptr){
        perror("Error opening Key file");
        return NULL;
    }
    
    PrivateKey *privKey = init_privateKey();
    if(!privKey){ return NULL; }
 
    mpz_t *fields[] = {
        &privKey->n,
        &privKey->e,
        &privKey->d,
        &privKey->p,
        &privKey->q,
        &privKey->dmp1,
        &privKey->dmq1,
        &privKey->iqmp
    };

    int con = 0;
    while(!feof(fptr)){
        uint8_t ASN1_TAG;
        if(fread(&ASN1_TAG, 1, 1, fptr) != 1)
            break;

        size_t len = read_asn1_len(fptr);
        
        if(ASN1_TAG != ASN1_SEQUENCE)         
            handle_privateKey_components(privKey, fields, con++, fptr, len);
    }

    return privKey;
}

PrivateKey *pem2txt_RSAPrivateKey(const char *filename){

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
    
    PrivateKey *privKey = init_privateKey();
    if(!privKey){ return NULL; }
    
    idx += deserialize_mpz(privKey->n, der + idx);
    idx += deserialize_mpz(privKey->e, der + idx);
    idx += deserialize_mpz(privKey->d, der + idx);
    idx += deserialize_mpz(privKey->p, der + idx);
    idx += deserialize_mpz(privKey->q, der + idx);
    idx += deserialize_mpz(privKey->dmp1, der + idx);
    idx += deserialize_mpz(privKey->dmq1, der + idx);
    idx += deserialize_mpz(privKey->iqmp, der + idx);

    return privKey;
}

static void handle_components(PublicKey *pubKey, uint8_t *buffer, size_t len, int sec){
    switch(sec){
        case 2 : {
            int version = deserialize_int(buffer, len);
            break;
        }

        case 3 : {
            mpz_import(pubKey->n, len, 1, 1, 0, 0, buffer);
            break;
        }

        case 4 : {
            mpz_import(pubKey->e, len, 1, 1, 0, 0, buffer);
            break;
        }
    }
}

PublicKey *d2i_RSAPublicKey(const char *filename){
    FILE *fptr = fopen(filename, "rb");
    if(!fptr){
        perror("Error opening input file");
        return NULL;
    }

    PublicKey *pubKey = init_publicKey();
    if(!pubKey){ return NULL; }

    int sec = 0;
    while(sec++ < 4){
        uint8_t tag;
        fread(&tag, 1, 1, fptr);
        size_t len = read_asn1_len(fptr);

        if(tag == ASN1_SEQUENCE){ continue; }

        uint8_t buffer[len];
        fread(buffer, 1, len, fptr);
        handle_components(pubKey, buffer, len, sec);
    }
    
    fclose(fptr);
    return pubKey;
}

