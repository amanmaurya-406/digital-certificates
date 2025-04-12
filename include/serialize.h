#ifndef SERIALIZE_H
#define SERIALIZE_H

#include "config.h"
#include <stdint.h>


/**
 * @file serialize.h
 * @brief Provides serialization utilities for certificate structures using ASN.1 DER encoding.
 */


/**
 * @brief Serializes the version in ASN.1 DER format.
 *
 * @param version integer value (e.g., 0 for v1).
 * @param outputsize Pointer to store the size of the serialized version.
 * @return uint8_t* Pointer to the serialized version buffer. Must be freed after use.
 */
uint8_t *serialize_version(int version, size_t *outputSize);


/**
 * @brief Serializes the certificate serial number in ASN.1 DER format.
 * 
 * @param serialNumber Serial number as an mpz_t.
 * @param outputSize Pointer to store the size of the serialized data.
 * @return uint8_t* Pointer to the serialized buffer (must be freed by the caller).
 */
uint8_t *serialize_serialNumber(mpz_t serialNumber, size_t *outputSize);


/**
 * @brief Serializes issuer information into ASN.1 DER format.
 * 
 * @param caInfo The issuer information structure.
 * @param outputSize Pointer to store the size of the serialized data.
 * @return uint8_t* Pointer to the serialized buffer (must be freed by the caller).
 */
uint8_t *serialize_issuerInfo(Info caInfo, size_t *outputSize);


/**
 * @brief Serializes the certificate validity period in ASN.1 DER format.
 * 
 * @param time Validity structure (e.g., notBefore and notAfter).
 * @param outputSize Pointer to store the size of the serialized data.
 * @return uint8_t* Pointer to the serialized buffer (must be freed by the caller).
 */
uint8_t *serialize_validity(Time time, size_t *outputSize);


/**
 * @brief Serializes the subject information into ASN.1 DER format.
 *
 * @param subInfo SubjectInfo structure containing subject data.
 * @param outputSize Pointer to store the size of the serialized subject info.
 * @return uint8_t* Pointer to the serialized subject info buffer. Must be freed after use.
 */
uint8_t *serialize_subInfo(Info subInfo, size_t *outputSize);


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
uint8_t *serialize_subPubKeyInfo(PublicKey publicKey, size_t *outputSize);


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
uint8_t *serialize_CSR(CSR request, size_t *outputLen);


/**
 * @brief Serializes the complete X.509 certificate.
 * 
 * @param cert Pointer to certificate structure with all components populated.
 * @param outputSize Pointer to store the length of the serialized certificate.
 * @return uint8_t* Pointer to the serialized buffer (must be freed by the caller).
 */
uint8_t *serialize_certificate(Certificate *cert, size_t *outputSize);


/**
 * @brief Serializes the signature algorithm identifier.
 * 
 * @param algorithm Name of the algorithm (e.g., "sha512WithRSAEncryption").
 * @param outputSize Pointer to store the size of the serialized algorithm identifier.
 * @return uint8_t* Pointer to the serialized buffer (must be freed by the caller).
 */
uint8_t *serialize_subSignAlgo(const char *algorithm, size_t *outputSize);


/**
 * @brief Serializes the signature into ASN.1 DER format.
 *
 * Converts the RSA signature represented by an mpz_t to a DER-encoded INTEGER.
 *
 * @param signature The signature to be serialized.
 * @param outputSize Pointer to store the size of the serialized signature.
 * @return uint8_t* Pointer to the serialized signature buffer. Must be freed after use.
 */
uint8_t *serialize_signature(Signature signature, size_t *signLen);


/**
 * @brief Wraps raw encoded data in an ASN.1 SEQUENCE.
 * 
 * @param countp Pointer to the current encoded item count (optional).
 * @param srcLen Length of the source data.
 * @param src Pointer to the raw encoded data.
 * @return uint8_t* Pointer to the SEQUENCE-wrapped buffer (must be freed by the caller).
 */
uint8_t *serialize_sequence(size_t *countp, size_t srcLen, uint8_t *src);

#endif