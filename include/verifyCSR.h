#ifndef VERIFY_CSR_H
#define VERIFY_CSR_H

#include <stdbool.h>
#include "config.h"

#define SHA512_DIGEST_LENGTH 64

bool verify_CSRSignature(CSR csr);
bool verify_rsaPublicKey(PublicKey subPubKey);
// bool verifyCSRSubjectInfo(Info sub_Info);

#endif