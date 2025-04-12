#include "common.h"
#include "asn1.h"


static size_t find_length(size_t srcLen){
    return (srcLen > 127) ? ((srcLen > 255) ? 3 : 2) : 1;
}

static uint8_t *encode(size_t *countp, int MY_ASN1_TAG, size_t srcLen, uint8_t *src){
    
    int index = 0;
    size_t srcLenSize = find_length(srcLen);

    *countp = 1 + ((srcLenSize > 1) + srcLenSize) + srcLen;
    uint8_t *buffer = (uint8_t *)malloc(*countp);
    if(!buffer){
        perror("Memory allocation failed\n");
        return NULL;
    }

    buffer[index++] = MY_ASN1_TAG;
    if(srcLenSize == 1){
        buffer[index++] = srcLen;
    }
    else{
        buffer[index++] = LENGTH_DESCRIPTOR | srcLenSize;
        for(int j = srcLenSize - 1; j >= 0; j--){
            buffer[index++] = (srcLen >> (j * 8)) & 0xFF;
        }
    }

    memcpy(buffer + index, src, srcLen);
    return buffer;
}

uint8_t *serialize_string(size_t *countp, int MY_ASN1_TAG, const char *src){
    size_t srcLen = strlen(src);
    return encode(countp, MY_ASN1_TAG, srcLen, (uint8_t *)src);
}

uint8_t *serialize_integer(size_t *countp, int value){

    uint8_t *buffer = (uint8_t *)malloc(5);     // value upto 2 bytes

    buffer[0] = MY_ASN1_INTEGER;

    if(value <= 0x7F){
        buffer[1] = 0x01;
        buffer[2] = (uint8_t)value;
        *countp = 3;
    }
    else if(value <= 0xFF){
        buffer[1] = 0x02;
        buffer[2] = 0x00;
        buffer[3] = (uint8_t)value;
        *countp = 4;
    }
    else if(value <= 0x7FFF){
        buffer[1] = 0x02;
        buffer[2] = (uint8_t)(value >> 8);
        buffer[3] = (uint8_t)(value & 0xFF);
        *countp = 4;
    }
    else if(value <= 0xFFFF){
        buffer[1] = 0x03;
        buffer[2] = 0x00;
        buffer[3] = (uint8_t)(value >> 8);
        buffer[4] = (uint8_t)(value & 0xFF);
        *countp = 5;
    }
    return buffer;
}

uint8_t *serialize_mpz(size_t *countp, mpz_t src){
    
    size_t srcLen = (mpz_sizeinbase(src, 2) + 7) / 8;
    uint8_t *raw = (uint8_t *)malloc(srcLen + 1); // +1 for potential 0x00
    mpz_export(raw + 1, &srcLen, 1, 1, 1, 0, src);

    uint8_t *buffer = NULL;
    if(raw[1] & 0x80){
        // First byte of integer has MSB = 1, prefix 0x00
        raw[0] = 0x00;
        srcLen += 1;
        buffer = encode(countp, MY_ASN1_INTEGER, srcLen, raw);
    }
    else{
        // No prefix needed
        buffer = encode(countp, MY_ASN1_INTEGER, srcLen, raw + 1);
    }

    free(raw);
    return buffer;
}

uint8_t *serialize_sequence(size_t *countp, size_t srcLen, uint8_t *src){
    return encode(countp, MY_ASN1_SEQUENCE | 0x20, srcLen, src);
}

/* uint8_t *serialize_set(size_t *countp, size_t srcLen, uint8_t *src){
    
} */





size_t read_asn1_length(char *decoded, int *i){
    size_t length = 0;
    
    uint8_t firstByte = decoded[(*i)++];

    if(firstByte & 0x80){
        size_t numBytesInLen = firstByte & 0x7F;
        
        for(size_t j = 0; j < numBytesInLen; j++){
            uint8_t temp = decoded[(*i)++]; 
            length = (length << 8) | temp;
        }
    }
    else
        length = firstByte;
    
    return length;
}

static size_t decode(size_t *out_len, uint8_t **dest, char *buffer){
    
    int index = 0;
    index++;
    *out_len = read_asn1_length(buffer, &index);
    
    *dest = (uint8_t *)malloc(*out_len);
    if(!(*dest)){
        perror("Memory allocation failed\n");
        return 0;
    }
    
    memcpy(*dest, buffer + index, *out_len);
    index += *out_len;
    
    return index;
}

size_t deserialize_integer(int *value, char *buffer){
    uint8_t *str;
    size_t len;
    
    size_t tlv_len = decode(&len, &str, buffer);
    *value = 0;
    for(int i = 0; i < len; i++){
        *value = (*value << 8) | str[i];
    }

    free(str);
    return tlv_len;
}

size_t deserialize_mpz(mpz_t value, char *buffer){   
    uint8_t *str;
    size_t len;

    size_t tlv_len = decode(&len, &str, buffer);
    mpz_import(value, len, 1, 1, 1, 0, str);
    
    free(str);
    return tlv_len;
}