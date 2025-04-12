## Digital Certificates

A lightweight cryptographic framework that builds core elements of a Public Key Infrastructure (PKI) from scratch. This project implements SHA-512, RSA key generation, CSRs, and X.509-style certificate creation using manual ASN.1 and DER encoding — without relying on high-level crypto libraries.


### Features

- **SHA-512 Hashing**  
  Fully custom SHA-512 implementation for secure hashing.

- **RSA Key Generation**  
  Manual creation of RSA key pairs, encoded according to PKCS#1 standards.

- **CSR (Certificate Signing Request)**  
  Constructs and encodes CSRs using ASN.1 and DER, ready for signing.

- **Self-Signed Certificate Authority (CA)**  
  Generates a self-signed root certificate that can be used to issue other certificates.

- **Certificate Generation**  
  Verifies CSRs and generates X.509-style certificates with manual field construction and ASN.1 serialization.

- **ASN.1 and DER Encoding**  
  Custom encoding logic for RSA keys, CSRs, and certificates following DER encoding rules.

- **CER to Text Conversion**  
  Decodes binary `.cer` files and prints a human-readable structure.


### Build & Run

#### Prerequisites
- CMake
- GMP library

#### Build Instructions

```bash
    mkdir build
    cd build
    cmake ..
    cmake --build .
```


### Standards (Partially Implemented)
- PKCS#1 – for RSA key encoding
- X.509 v3-style – basic certificate fields and structure
- ASN.1 (DER) – for binary encoding of all structures
- PEM/CER – support for .cer and .txt conversion

