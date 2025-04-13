#ifndef GENERATE_CERTIFICATE_H
#define GENERATE_CERTIFICATE_H

#include "config.h"

Certificate *generate_certificate(CSR *csr, DName *caInfo, PrivateKey *ca_privKey);
Certificate *generate_self_signed_certificate(DName *caInfo, PrivateKey *ca_privKey);
void free_certificate(Certificate *cert);

#endif