#ifndef CREATE_CSR_H
#define CREATE_CSR_H

#include "config.h"
#include "serialize.h"

CSR *createCSR(PrivateKey *privateKey, DName *subject_info);

#endif