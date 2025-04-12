#ifndef ASN1_H
#define ASN1_H

#include <gmp.h>
#include <stdint.h>

/* ASN.1 tag values */
#define MY_ASN1_INTEGER               0X02 /* primitive */
#define MY_ASN1_BITSTRING             0x03 /* primitive */
#define MY_ASN1_NULL                  0x05 /* primitive */
#define MY_ASN1_OBJECT                0x06 /* primitive */
#define MY_ASN1_UTF8STRING            0x0C /* primitive */
#define MY_ASN1_SEQUENCE              0x10 /* constructed, final 0x10 | 0x20 => 0x30 */
#define MY_ASN1_SET                   0x11 /* constructed, final 0x11 | 0x20 => 0x31 */
#define MY_ASN1_PRINTABLESTRING       0x13 /* primitive */

/* Base value for long-form lengths */
#define LENGTH_DESCRIPTOR             0x80


uint8_t *serialize_string(size_t *countp, int MY_ASN1_TAG, const char *src);
uint8_t *serialize_mpz(size_t *countp, mpz_t src);
uint8_t *serialize_integer(size_t *countp, int value);
uint8_t *serialize_sequence(size_t *countp, size_t srcLen, uint8_t *src);

size_t read_asn1_length(char *decoded, int *i);
size_t deserialize_integer(int *value, char *buffer);
size_t deserialize_mpz(mpz_t value, char *buffer);


#endif