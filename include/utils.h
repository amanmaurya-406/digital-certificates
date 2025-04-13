#ifndef INIT_TYPES_H
#define INIT_TYPES_H

#include "config.h"

PrivateKey *init_privateKey();
PublicKey *init_publicKey();
DName *init_dname();
void copy_dName(DName *dn1, DName *dn2);
PKeyInfo *init_pKeyInfo();
CSRInfo *init_csrInfo();
CSR *init_csr();
Time *init_time();
Validity *init_validity();
TBSCertificate *init_tbsCertificate();
Certificate *init_certificate();


void free_privateKey(PrivateKey *privKey);
void free_publicKey(PublicKey *pubKey);
void free_dname(DName *dName);
void free_pKeyInfo(PKeyInfo *pKeyInfo);
void free_csrInfo(CSRInfo *csrInfo);
void free_csr(CSR *csr);
void free_time(Time *t);
void free_validity(Validity *validity);
void free_tbsCertificate(TBSCertificate *tbsCert);
void free_certificate(Certificate *cert);


#endif