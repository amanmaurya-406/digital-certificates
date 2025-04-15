#include "common.h"
#include "utils.h"


PrivateKey *init_privateKey(){
    PrivateKey *privKey = malloc(sizeof(PrivateKey));
    if(!privKey){
        perror("Error Initializing Private Key");
        return NULL;
    }

    privKey->version = 0;
    mpz_inits(privKey->n, privKey->e, privKey->d, NULL);
    mpz_inits(privKey->p, privKey->q, privKey->dmp1, NULL);
    mpz_inits(privKey->dmq1, privKey->iqmp, NULL);

    return privKey;
}

PublicKey *init_publicKey(){
    PublicKey *pubKey = malloc(sizeof(PublicKey));
    if(!pubKey){
        perror("Error Initializing Public Key");
        return NULL;
    }
    
    mpz_inits(pubKey->n, pubKey->e, NULL);

    return pubKey;
}

DName *init_dname(){
    DName *dName = malloc(sizeof(DName));
    if(!dName){
        perror("Error Initializing DName");
        return NULL;
    }
    return dName;
}

void copy_dName(DName *dn1, DName *dn2){
    strcpy(dn1->country, dn2->country);
    strcpy(dn1->state, dn2->state);
    strcpy(dn1->city, dn2->city);
    strcpy(dn1->org, dn2->org);
    strcpy(dn1->unit, dn2->unit);
    strcpy(dn1->name, dn2->name);
}

PKeyInfo *init_pKeyInfo(){
    PKeyInfo *pKeyInfo = malloc(sizeof(PKeyInfo));
    if(!pKeyInfo){
        perror("Error Initializing PKeyinfo");
        return NULL;
    }

    pKeyInfo->pubKeyAlgo = NULL;
    pKeyInfo->pubKey = init_publicKey();
    if(!pKeyInfo->pubKey){
        free(pKeyInfo);
        return NULL;
    }

    return pKeyInfo;
}

CSRInfo *init_csrInfo(){
    CSRInfo *csrInfo = malloc(sizeof(CSRInfo));
    if(!csrInfo){
        perror("Error Initializing CSRInfo");
        return NULL;
    }

    csrInfo->version = 0;
    csrInfo->subject = init_dname();
    if(!csrInfo->subject){
        free(csrInfo);
        return NULL;
    }

    csrInfo->pKeyInfo = init_pKeyInfo();
    if(!csrInfo->pKeyInfo){
        free_dname(csrInfo->subject);
        free(csrInfo);
        return NULL;
    }

    return csrInfo;
}

CSR *init_csr(){

    CSR *csr = malloc(sizeof(CSR));
    if(!csr){
        perror("Error Initializing CSR");
        return NULL;
    }

    csr->csrInfo = init_csrInfo();
    if(!csr->csrInfo){
        free(csr);
        return NULL;
    }

    csr->signatureAlgo = NULL;
    mpz_init(csr->signature);

    return csr;
}

Time *init_time(){
    Time *t = malloc(sizeof(Time));
    if(!t){
        perror("Error Initializing Time");
        return NULL;
    }

    return t;
}

Validity *init_validity(){
    Validity *validity = malloc(sizeof(Validity));
    if(!validity){
        perror("Error Initilaizing Validity");
        return NULL;
    }

    validity->validFrom = init_time();
    if(!validity->validFrom){
        free(validity);
        return NULL;
    }

    validity->validTo = init_time();
    if(!validity->validTo){
        free_time(validity->validFrom);
        free(validity);
        return NULL;
    }

    return validity;
}

TBSCertificate *init_tbsCertificate(){
    TBSCertificate *tbsCert = malloc(sizeof(TBSCertificate));
    if(!tbsCert){
        perror("Error Initializing TBSCertificate");
        return NULL;
    }

    mpz_init(tbsCert->serialNumber);
    tbsCert->signatureAlgo = NULL;

    tbsCert->issuer = init_dname();
    if(!tbsCert->issuer){
        mpz_clear(tbsCert->serialNumber);
        free(tbsCert);
        return NULL;
    }

    tbsCert->validity = init_validity();
    if(!tbsCert->validity){
        mpz_clear(tbsCert->serialNumber);
        free_dname(tbsCert->issuer);
        free(tbsCert);
        return NULL;
    }

    tbsCert->subject = init_dname();
    if(!tbsCert->subject){
        mpz_clear(tbsCert->serialNumber);
        free_dname(tbsCert->issuer);
        free_validity(tbsCert->validity);
        free(tbsCert);
        return NULL;
    }

    tbsCert->pKeyInfo = init_pKeyInfo();
    if(!tbsCert->pKeyInfo){
        mpz_clear(tbsCert->serialNumber);
        free_dname(tbsCert->issuer);
        free_validity(tbsCert->validity);
        free_dname(tbsCert->subject);
        free(tbsCert);
        return NULL;
    }

    return tbsCert;
}

Certificate *init_certificate(){

    Certificate *cert = malloc(sizeof(Certificate));
    if(!cert){
        perror("Error Initializing Certificate");
        return NULL;
    }

    cert->tbsCert = init_tbsCertificate();
    if(!cert->tbsCert){
        free(cert);
        return NULL;
    }

    cert->signatureAlgo = NULL;
    mpz_init(cert->signature);

    return cert;
}



void free_privateKey(PrivateKey *privKey){
    if(!privKey){ return; }

    mpz_clears(privKey->n, privKey->e, privKey->d, NULL);
    mpz_clears(privKey->p, privKey->q, privKey->dmp1, NULL);
    mpz_clears(privKey->dmq1, privKey->iqmp, NULL);

    free(privKey);
}

void free_publicKey(PublicKey *pubKey){
    if(!pubKey){ return; }

    mpz_clears(pubKey->n, pubKey->e, NULL);
    
    free(pubKey);
}

void free_dname(DName *dName){
    if(!dName){ return; }

    free(dName);
}

void free_pKeyInfo(PKeyInfo *pKeyInfo){
    if(!pKeyInfo){ return; }

    free_publicKey(pKeyInfo->pubKey);
    free(pKeyInfo);
}

void free_csrInfo(CSRInfo *csrInfo){
    if(!csrInfo){ return; }

    free_dname(csrInfo->subject);
    free_pKeyInfo(csrInfo->pKeyInfo);
    free(csrInfo);
}

void free_csr(CSR *csr){
    if(!csr){ return; }

    free_csrInfo(csr->csrInfo);
    mpz_clear(csr->signature);
    free(csr);
}

void free_time(Time *t){
    if(!t){ return; }
    free(t);
}

void free_validity(Validity *validity){
    if(!validity){ return; }

    free_time(validity->validFrom);
    free_time(validity->validTo);
    free(validity);
}

void free_tbsCertificate(TBSCertificate *tbsCert){
    if(!tbsCert){ return; }

    mpz_clear(tbsCert->serialNumber);
    free_dname(tbsCert->issuer);
    free_validity(tbsCert->validity);
    free_dname(tbsCert->subject);
    free_pKeyInfo(tbsCert->pKeyInfo);
    free(tbsCert);
}

void free_certificate(Certificate *cert){
    if(!cert){ return; }

    free_tbsCertificate(cert->tbsCert);
    mpz_clear(cert->signature);
    free(cert);
}

