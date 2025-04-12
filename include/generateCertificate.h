#ifndef GENERATE_CERTIFICATE_H
#define GENERATE_CERTIFICATE_H

#include "config.h"

Certificate generate_certificate(CSR csr, Info caInfo, PrivateKey *ca_privKey);
Certificate generate_self_signed_certificate(Info caInfo, PrivateKey *ca_privKey);

#endif