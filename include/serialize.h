#ifndef SERIALIZE_H
#define SERIALIZE_H

#include "config.h"
#include <stdint.h>

uint8_t *serialize_version(int version, size_t *outputSize);
uint8_t *serialize_serialNumber(mpz_t serialNumber, size_t *outputSize);
uint8_t *serialize_issuerInfo(Info caInfo, size_t *outputSize);
uint8_t *serialize_validity(Time time, size_t *outputSize);
uint8_t *serialize_subInfo(Info subInfo, size_t *outputSize);
uint8_t *serialize_subPubKeyInfo(PublicKey publicKey, size_t *outputSize);
uint8_t *serialize_CSR(CSR request, size_t *outputLen);
uint8_t *serialize_certificate(Certificate cert, size_t *outputSize);
uint8_t *serialize_subSignAlgo(const char *algorithm, size_t *outputSize);
uint8_t *serialize_signature(Signature signature, size_t *signLen);

uint8_t *serialize_sequence(size_t *countp, size_t srcLen, uint8_t *src);

#endif