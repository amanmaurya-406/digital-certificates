#ifndef VERIFY_CSR_H
#define VERIFY_CSR_H

#include <stdbool.h>
#include "config.h"

bool verify_CSRSignature(CSR *csr);
bool verify_RSAPublicKey(PublicKey *publicKey);
// bool verifyCSRSubjectInfo(Info sub_Info);

#endif