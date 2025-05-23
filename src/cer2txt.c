#include "common.h"
#include "cer2txt.h"
#include "utils.h"

#define ASN1_SEQUENCE   0x30


bool write_cer_file(const char *filename, size_t data_size, uint8_t *data){

    FILE *fptr = fopen(filename, "wb");
    if(fptr == NULL){
        perror("Error opening file");
        return 0;
    }

    size_t bytesWritten = fwrite(data, 1, data_size, fptr);
    if(bytesWritten != data_size){
        perror("Full data is not written");
        return 0;
    }

    fclose(fptr);
    return 1;
}

uint8_t *read_cer_file(const char *filename){
    FILE *fptr = fopen(filename, "rb");
    if(!fptr){
        perror("Error opening file");
        return NULL;
    }

    size_t size = 0;
    fseek(fptr, 0, SEEK_END);
    size = ftell(fptr);
    rewind(fptr);

    uint8_t *buffer = (uint8_t *)malloc(sizeof(uint8_t) * size);

    size_t bytesRead = fread((void *)buffer, 1, size, fptr);
    fclose(fptr);
    
    if(bytesRead != size){
        perror("Warning: Could not read the entire file.\n");
        free(buffer);
        return NULL;
    }

    return buffer;
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

static void handle_csrInfo(CSR *csr, uint8_t con, uint8_t *temp, size_t len){
    switch(con){
        case 0 :
            csr->csrInfo->version = deserialize_int(temp, len);
            break;

        // Subject fields
        case 1: case 2: case 3: case 4: case 5: case 6: {
            char *fields[] = {
                csr->csrInfo->subject->country,
                csr->csrInfo->subject->state,
                csr->csrInfo->subject->city,
                csr->csrInfo->subject->org,
                csr->csrInfo->subject->unit,
                csr->csrInfo->subject->name
            };
            memcpy(fields[con - 1], temp, len);
            fields[con - 1][len] = '\0';
            break;
        } 

        // Subject Public key
        case 7 :
            csr->csrInfo->pKeyInfo->pubKeyAlgo = malloc(len + 1);
            memcpy(csr->csrInfo->pKeyInfo->pubKeyAlgo, temp, len);
            csr->csrInfo->pKeyInfo->pubKeyAlgo[len] = '\0';
            break;
        case 8 :
            mpz_import(csr->csrInfo->pKeyInfo->pubKey->n, len, 1, 1, 0, 0, temp);
            break;
        case 9 :
            mpz_import(csr->csrInfo->pKeyInfo->pubKey->e, len, 1, 1, 0, 0, temp);
            break;

        // Signature
        case 10 :
            csr->signatureAlgo = malloc(len + 1);
            memcpy(csr->signatureAlgo, temp, len);
            csr->signatureAlgo[len] = '\0';
            break;
        case 11 :
            mpz_import(csr->signature, len, 1, 1, 0, 0, temp);
            break;
    }
}

CSR *load_csr(const char *filename){

    FILE *fptr = fopen(filename, "rb");
    if(!fptr){
        perror("Error opening file");
        return NULL;
    }

    CSR *csr = init_csr();
    if(!csr){ 
        fclose(fptr);
        return NULL;
    }

    int con = 0;
    while(!feof(fptr)){
        uint8_t ASN1_TAG;
        fread(&ASN1_TAG, 1, 1, fptr);
        size_t len = read_asn1_len(fptr);

        if(ASN1_TAG != (ASN1_SEQUENCE)){
            uint8_t temp[len];
            fread(temp, 1, len, fptr);
            
            handle_csrInfo(csr, con, temp, len);
            con++;
        }
    }

    fclose(fptr);
    return csr;
}


static void handle_certInfo(Certificate *cert, uint8_t con, uint8_t *temp, size_t len){
    switch(con){
        case 0:
            cert->tbsCert->version = deserialize_int(temp, len);
            break;
        
        case 1:
            mpz_import(cert->tbsCert->serialNumber, len, 1, 1, 0, 0, temp);
            break;

        case 2:
            cert->tbsCert->signatureAlgo = malloc(len + 1);
            memcpy(cert->tbsCert->signatureAlgo, temp, len);
            cert->tbsCert->signatureAlgo[len] = '\0';
            break;

        // Issuer fields
        case 3: case 4: {
            char *fields[] = {
                cert->tbsCert->issuer->country,
                cert->tbsCert->issuer->org
            };
            memcpy(fields[con - 3], temp, len);
            fields[con - 3][len] = '\0';
            break;
        }

        // Valid From
        case 5:  cert->tbsCert->validity->validFrom->year   = deserialize_int(temp, len); break;
        case 6:  cert->tbsCert->validity->validFrom->month  = deserialize_int(temp, len); break;
        case 7:  cert->tbsCert->validity->validFrom->day    = deserialize_int(temp, len); break;
        case 8:  cert->tbsCert->validity->validFrom->hour   = deserialize_int(temp, len); break;
        case 9:  cert->tbsCert->validity->validFrom->minute = deserialize_int(temp, len); break;
        case 10: cert->tbsCert->validity->validFrom->second = deserialize_int(temp, len); break;

        // Valid To
        case 11: cert->tbsCert->validity->validTo->year     = deserialize_int(temp, len); break;
        case 12: cert->tbsCert->validity->validTo->month    = deserialize_int(temp, len); break;
        case 13: cert->tbsCert->validity->validTo->day      = deserialize_int(temp, len); break;
        case 14: cert->tbsCert->validity->validTo->hour     = deserialize_int(temp, len); break;
        case 15: cert->tbsCert->validity->validTo->minute   = deserialize_int(temp, len); break;
        case 16: cert->tbsCert->validity->validTo->second   = deserialize_int(temp, len); break;

        // Subject fields
        case 17: case 18: case 19: case 20: case 21: case 22: {
            char *fields[] = {
                cert->tbsCert->subject->country,
                cert->tbsCert->subject->state,
                cert->tbsCert->subject->city,
                cert->tbsCert->subject->org,
                cert->tbsCert->subject->unit,
                cert->tbsCert->subject->name
            };
            memcpy(fields[con - 17], temp, len);
            fields[con - 17][len] = '\0';
            break;
        }

        // Subject Public Key
        case 23:
            cert->tbsCert->pKeyInfo->pubKeyAlgo = malloc(len + 1);
            memcpy(cert->tbsCert->pKeyInfo->pubKeyAlgo, temp, len);
            cert->tbsCert->pKeyInfo->pubKeyAlgo[len] = '\0';
            break;
        case 24:
            mpz_import(cert->tbsCert->pKeyInfo->pubKey->n, len, 1, 1, 0, 0, temp);
            break;
        case 25:
            mpz_import(cert->tbsCert->pKeyInfo->pubKey->e, len, 1, 1, 0, 0, temp);
            break;

        // Signature
        case 26:
            cert->signatureAlgo = malloc(len + 1);
            memcpy(cert->signatureAlgo, temp, len);
            cert->signatureAlgo[len] = '\0';
            break;

        case 27:
            mpz_import(cert->signature, len, 1, 1, 0, 0, temp);
            break;

    }
}

Certificate *load_certificate(const char *filename){
    FILE *fptr = fopen(filename, "rb");
    if(!fptr){
        perror("Error opening file");
        return NULL;
    }
    
    Certificate *cert = init_certificate();
    if(!cert){
        fclose(fptr);
        return NULL;
    }
    
    int con = 0;
    while(!feof(fptr)){
        uint8_t ASN1_TAG;
        if(fread(&ASN1_TAG, 1, 1, fptr) != 1)
            break;

        size_t len = read_asn1_len(fptr);
        
        if(ASN1_TAG != ASN1_SEQUENCE){
            uint8_t temp[len];
            if(fread(temp, 1, len, fptr) != len){
                perror("Failed to read expected bytes");
                fclose(fptr);
                free(cert);
                return NULL;
            }            
            handle_certInfo(cert, con, temp, len);
            con++;
        }
    }

    fclose(fptr);
    return cert;
}


void csr_cer2txt(const char *filename){
    FILE *input = fopen(filename, "rb");
    if(!input){
        perror("Error opening input file");
        return;
    }

    FILE *output = fopen(DATA_DIR "/csr.txt", "w");
    if(!output){
        perror("Error opening output file");
        fclose(input);
        return;
    }

    const char *headers[] = {
        "Certificate Request:\n",
        "\tData:\n",
        "\t\tVersion: ",
        "\t\tSubject: ",
        "\t\tSubject Public Key Info:\n",
        "\t\t\tPublic Key Algorithm: ",
        "\t\t\t\tPublic-Key: ",
        "\t\t\t\tModulus:\n\t\t\t\t\t",
        "\t\t\t\tExponent: ",
        "\tSignature Algorithm: ",
        "\tSignature Value:\n\t\t"
    };
    const char *labels[] = {"C=", "ST=", "L=", "O=", "OU=", "CN="};    // Labels for subject info


    fprintf(output, "%s%s", headers[0], headers[1]);

    int section = 0;

    while(!feof(input)){
        uint8_t tag;
        if(fread(&tag, 1, 1, input) != 1)
            break;

        size_t len = read_asn1_len(input);

        if(tag == (ASN1_SEQUENCE)){
            // Container SEQUENCE: handled recursively elsewhere or skipped
            continue;
        }

        uint8_t *buffer = (uint8_t *)malloc(len + 1);
        if(!buffer){
            perror("Memory allocation failed");
            break;
        }

        if(fread(buffer, 1, len, input) != len){
            perror("Error reading ASN.1 element");
            free(buffer);
            break;
        }

        buffer[len] = '\0'; // Safe for printable strings

        switch(section){
            case 0: { // Version
                int version = deserialize_int(buffer, len);
                fprintf(output, "%s%d (0x%02x)\n", headers[2], version + 1, buffer[0]);
                break;
            }

            case 1:   // Subject - Country
                fprintf(output, "%s" , headers[3]);
                /* fall through */
            case 2:   // Subject - State
            case 3:   // Subject - Locality
            case 4:   // Subject - Organization
            case 5:   // Subject - Organization Unit
            case 6: { // Subject - Common Name
                fprintf(output, "%s%s%s", labels[section - 1], buffer, (section == 6) ? "\n" : ", ");
                break;
            }

            case 7: { // Public Key Algorithm
                fprintf(output, "%s%s%s\n", headers[4], headers[5], buffer);
                break;
            }
            case 8: { // Key Size
                int bits = ((buffer[0] == 0x00) ? len - 1 : len) * 8;
                fprintf(output, "%s(%d bit)\n", headers[6], bits);
                
                // Modulus
                fprintf(output, "%s", headers[7]);
                for(size_t i = 0; i < len; ++i){
                    fprintf(output, "%02x", buffer[i]);
                    if(i < len - 1) fprintf(output, ":");
                    if(i % 15 == 14) fprintf(output, "\n\t\t\t\t\t");
                }
                fprintf(output, "\n");
                break;
            }
            case 9: { // Exponent
                unsigned int exponent = deserialize_int(buffer, len);
                fprintf(output, "%s%u (0x", headers[8], exponent);
                for(size_t i = 0; i < len; ++i)
                    fprintf(output, "%02x", buffer[i]);
                fprintf(output, ")\n");
                break;
            }

            case 10: { // Signature Algorithm
                fprintf(output, "%s%s\n", headers[9], buffer);
                break;
            }
            case 11: { // Signature Value
                fprintf(output, "%s", headers[10]);
                for(size_t i = 0; i < len; ++i){
                    fprintf(output, "%02x", buffer[i]);
                    if(i < len - 1) fprintf(output, ":");
                    if(i % 18 == 17) fprintf(output, "\n\t\t");
                }
                fprintf(output, "\n");
                break;
            }

            default:
                break;
        }

        free(buffer);
        section++;
    }

    fclose(input);
    fclose(output);
}


void cert_cer2txt(const char *input_file, const char *output_file){

    FILE *input = fopen(input_file, "rb");
    if(!input){
        perror("Error opening input file");
        return;
    }

    FILE *output = fopen(output_file, "w");
    if(!output){
        perror("Error opening output file");
        fclose(input);
        return;
    }

    const char *headers[] = {
        "Certificate:\n",
        "\tData:\n",
        "\t\tVersion: ",
        "\t\tSerial Number:\n\t\t\t",
        "\t\tSignature Algorithm: ",
        "\t\tIssuer: ",
        "\t\tValidity\n",
        "\t\t\tNot Before: ",
        "\t\t\tNot After : ",
        "\t\tSubject: ",
        "\t\tSubject Public Key Info:\n",
        "\t\t\tPublic Key Algorithm: ",
        "\t\t\t\tPublic-Key: ",
        "\t\t\t\tModulus:\n\t\t\t\t\t",
        "\t\t\t\tExponent: ",
        "\tSignature Algorithm: ",
        "\tSignature Value:\n\t\t"
    };
    const char *label1[] = {"C=", "O="};
    const char *label2[] = {"C=", "ST=", "L=", "O=", "OU=", "CN="};

    fprintf(output, "%s%s", headers[0], headers[1]);

    int section = 0;

    while(!feof(input)){  
        uint8_t tag;
        if(fread(&tag, 1, 1, input) != 1) break;
        size_t len = read_asn1_len(input);

        if(tag == (ASN1_SEQUENCE)) continue;

        uint8_t *buffer = malloc(len + 1);
        if(!buffer){
            perror("Memory allocation failed");
            break;
        }

        if(fread(buffer, 1, len, input) != len){
            perror("Error reading ASN.1 element");
            free(buffer);
            break;
        }

        buffer[len] = '\0';

        switch(section){
            case 0: { // Version
                int version = deserialize_int(buffer, len);
                fprintf(output, "%s%d (0x%02x)\n", headers[2], version, buffer[0]);
                break;
            }

            case 1: {
                fprintf(output, "%s", headers[3]);
                for(size_t i = 0; i < len; ++i){
                    fprintf(output, "%02x", buffer[i]);
                    if(i < len - 1) fprintf(output, ":");
                }
                fprintf(output, "\n");
                break;
            }

            case 2: { // Signature Algorithm
                fprintf(output, "%s%s\n", headers[4], buffer);
                break;
            }

            case 3:   // Subject - Country
                fprintf(output, "%s" , headers[5]);
                /* fall through */
            case 4: { // Subject - Organization
                fprintf(output, "%s%s%s", label1[section - 3], buffer, (section == 4) ? "\n" : ", ");
                break;
            }

            case 5:
                fprintf(output, "%s%s", headers[6], headers[7]);
            case 6:
            case 7: {
                int val = deserialize_int(buffer, len);
                fprintf(output, "%d ", val);
                break;
            }
            case 8:
            case 9:
            case 10: {
                int val = deserialize_int(buffer, len);
                fprintf(output, "%d%s", val, (section == 10) ? " GMT\n" : ":");
                break;
            }

            case 11:
                fprintf(output, "%s" , headers[8]);
            case 12:
            case 13: {
                int val = deserialize_int(buffer, len);
                fprintf(output, "%d ", val);
                break;
            }
            case 14:
            case 15:
            case 16: {
                int val = deserialize_int(buffer, len);
                fprintf(output, "%d%s", val, (section == 16) ? " GMT\n" : ":");
                break;
            }
            
            case 17:   // Subject - Country
                fprintf(output, "%s" , headers[9]);
                /* fall through */
            case 18:   // Subject - State
            case 19:   // Subject - Locality
            case 20:   // Subject - Organization
            case 21:   // Subject - Organization Unit
            case 22: { // Subject - Common Name
                fprintf(output, "%s%s%s", label2[section - 17], buffer, (section == 22) ? "\n" : ", ");
                break;
            }

            case 23: { // Public Key Algorithm
                fprintf(output, "%s%s%s\n", headers[10], headers[11], buffer);
                break;
            }
            case 24: { // Key Size
                int bits = ((buffer[0] == 0x00) ? len - 1 : len) * 8;
                fprintf(output, "%s(%d bit)\n", headers[12], bits);
                
                // Modulus
                fprintf(output, "%s", headers[13]);
                for(size_t i = 0; i < len; ++i){
                    fprintf(output, "%02x", buffer[i]);
                    if(i < len - 1) fprintf(output, ":");
                    if(i % 15 == 14) fprintf(output, "\n\t\t\t\t\t");
                }
                fprintf(output, "\n");
                break;
            }
            case 25: { // Exponent
                unsigned int exponent = deserialize_int(buffer, len);
                fprintf(output, "%s%u (0x", headers[14], exponent);
                for(size_t i = 0; i < len; ++i)
                    fprintf(output, "%02x", buffer[i]);
                fprintf(output, ")\n");
                break;
            }

            case 26: { // Signature Algorithm
                fprintf(output, "%s%s\n", headers[15], buffer);
                break;
            }
            case 27: { // Signature Value
                fprintf(output, "%s", headers[16]);
                for(size_t i = 0; i < len; ++i){
                    fprintf(output, "%02x", buffer[i]);
                    if(i < len - 1) fprintf(output, ":");
                    if(i % 18 == 17) fprintf(output, "\n\t\t");
                }
                fprintf(output, "\n");
                break;
            }
        }

        free(buffer);
        section++;
    }
    
    fclose(input);
    fclose(output);
}


