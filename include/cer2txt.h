#ifndef CER_TO_TXT_H
#define CER_TO_TXT_H

#include <stdint.h>
#include <stdbool.h>
#include "config.h"

bool write_cer_file(const char *filename, size_t data_size, uint8_t *data);
uint8_t *read_cer_file(const char *filename);


/**
 * @brief Parses a Certificate Signing Request (CSR) in DER format
 *        and stores it in CSR structure.
 * 
 * @param filename Path to the DER-encoded CSR file. 
 * @return CSR* -- Pointer to CSR structure. Must be freed after use.
 */
CSR *load_csr(const char *filename);


/**
 * @brief Frees the CSR structure
 * 
 * @param csr pointer to the CSR structure
 */
void free_csr(CSR *csr);


/**
 * @brief Parses a Certificate in DER format
 *        and stores it in Certificate structure.
 * 
 * @param filename Path to the DER-encoded Certificate file. 
 * @return Certificate* -- Pointer to Certificate structure. Must be freed after use.
 */
Certificate *load_certificate(const char *filename);


/**
 * @brief Parses a Certificate Signing Request (CSR) in DER format
 *        and outputs a human-readable text representation.
 *
 * @param filename Path to the DER-encoded CSR file.
 */
void csr_cer2txt(const char *filename);


/**
 * @brief Parses a Certificate in DER format and outputs 
 *        a human-readable text representation.
 *
 * @param filename Path to the DER-encoded Certificate file.
 */
void cert_cer2txt(const char *input_file, const char *output_file);

#endif