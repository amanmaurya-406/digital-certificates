#ifndef CER_TO_TXT_H
#define CER_TO_TXT_H

#include <stdint.h>
#include <stdbool.h>
#include "config.h"

bool write_cer_file(const char *filename, size_t data_size, uint8_t *data);
uint8_t *read_cer_file(const char *filename);

CSR *load_csr(const char *filename);
Certificate *load_certificate(const char *filename);
void csr_cer2txt(const char *filename);
void cert_cer2txt(const char *input_file, const char *output_file);

#endif