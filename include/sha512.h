#ifndef SHA512_H
#define SHA512_h

#include <stdint.h>
#define SHA512_DIGEST_LENGTH 64

uint8_t* SHA512(uint8_t *input, int input_len);

#endif