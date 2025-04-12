## PKCS#1 (Public-Key Cryptography Standards #1) is the standard for RSA cryptography, defining key formats, encryption, signatures, and padding schemes. The main components of PKCS#1 include:

### 1. **RSA Key Representations**
   - **ASN.1 Structures**: Defines how RSA keys are represented.
   - **BER/DER Encoding**: Uses Distinguished Encoding Rules (DER) for key storage.

   **Key structures:**
   - **RSA Private Key (RSAPrivateKey)**
     > The private key in PKCS#1 is represented using the ASN.1 structure `RSAPrivateKey`. It includes the following components: <br>
       The private key can be encoded in PEM or DER format for storage and transmission.
        + **version**: Version number, typically 0.
        + **modulus (n)**: The modulus n.
        + **publicExponent (e)**: The public exponent e.
        + **privateExponent (d)**: The private exponent d.
        + **prime1 (p)**: The first prime factor p.
        + **prime2 (q)**: The second prime factor q.
        + **exponent1 (d mod (p-1))**: The exponent d mod (p-1).
        + **exponent2 (d mod (q-1))**: The exponent d mod (q-1).
        + **coefficient ((inverse of q) mod p)**: The coefficient (inverse of q) mod p.

   - **RSA Public Key (RSAPublicKey)**
     > The public key in PKCS#1 is represented using the ASN.1 structure `RSAPublicKey`. It includes the following components: <br>
        + **modulus (n)**: The modulus n.
        + **publicExponent (e)**: The public exponent e.

   - **RSA Public Key in SubjectPublicKeyInfo (X.509 format)**


### 2. **Encryption Schemes**
   Defines padding schemes used for secure RSA encryption.
   - **RSAES-PKCS1-v1_5** (Older, less secure)
   - **RSAES-OAEP (Optimal Asymmetric Encryption Padding)** (Recommended)

### 3. **Signature Schemes**
   Defines padding and hashing for digital signatures.
   - **RSASSA-PKCS1-v1_5** (Legacy signature scheme)
   - **RSASSA-PSS (Probabilistic Signature Scheme)** (More secure)

### 4. **Hashing Algorithms for Signatures**
   Commonly used hash functions in PKCS#1:
   - SHA-256, SHA-384, SHA-512, etc.
   - MD5 and SHA-1 (deprecated due to security risks)

### 5. **Encoding and Formatting**
   - **PEM (Privacy-Enhanced Mail) Format**:
     - Base64-encoded key representations with headers like:
       ```
       -----BEGIN RSA PRIVATE KEY-----
       ... (Base64 Data) ...
       -----END RSA PRIVATE KEY-----
       ```
   - **DER (Distinguished Encoding Rules) Format**:
     - Binary format of the same ASN.1 structures.
