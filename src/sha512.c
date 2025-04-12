#include <stdlib.h>
#include <string.h>
#include "sha512.h"


#define ROTR(x,n) (((x) >> (n)) | ((x) << (64 - (n))))
#define SHR(x,n) ((x) >> (n))
#define CH(e,f,g) (((e) & (f)) ^ (~(e) & (g)))
#define MAJ(a,b,c) (((a) & (b)) ^ ((a) & (c)) ^ ((b) & (c)))
#define EP0(a) (ROTR(a,28) ^ ROTR(a,34) ^ ROTR(a,39))
#define EP1(e) (ROTR(e,14) ^ ROTR(e,18) ^ ROTR(e,41))
#define SIG0(x) (ROTR(x,1) ^ ROTR(x,8) ^ SHR(x,7))
#define SIG1(x) (ROTR(x,19) ^ ROTR(x,61) ^ SHR(x,6))

// Pre-defined constants
static const uint64_t k[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

// State initialization
static void sha512_initialize(uint64_t *state){
    state[0] = 0x6a09e667f3bcc908;
    state[1] = 0xbb67ae8584caa73b;
    state[2] = 0x3c6ef372fe94f82b;
    state[3] = 0xa54ff53a5f1d36f1;
    state[4] = 0x510e527fade682d1;
    state[5] = 0x9b05688c2b3e6c1f;
    state[6] = 0x1f83d9abfb41bd6b;
    state[7] = 0x5be0cd19137e2179;
}

static void sha512_transform(uint64_t *state, const uint8_t data[]){
    uint64_t a, b, c, d, e, f, g, h, t1, t2, w[80];
    int i, j;

    for (i = 0, j = 0 ; i < 16 ; ++i, j += 8)
        w[i] = ((uint64_t)data[j] << 56) | ((uint64_t)data[j + 1] << 48) | ((uint64_t)data[j + 2] << 40) | ((uint64_t)data[j + 3] << 32) |
            ((uint64_t)data[j + 4] << 24) | ((uint64_t)data[j + 5] << 16) | ((uint64_t)data[j + 6] << 8) | ((uint64_t)data[j + 7]);
    
    for( ; i < 80 ; ++i)
        w[i] = SIG1(w[i - 2]) + w[i - 7] + SIG0(w[i - 15]) + w[i - 16];

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    for (i = 0; i < 80; ++i){
        t1 = h + CH(e,f,g) + EP1(e) + w[i] + k[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}
                                    
static void sha512_update(uint64_t *state, const uint8_t data[], size_t data_len){
    size_t i;
    uint8_t buf[128];
    memset(buf, 0, 128);

    for (i = 0; i < data_len; ++i){
        buf[i % 128] = data[i];
        if ((i % 128) == 127){
            sha512_transform(state, buf);
            memset(buf, 0, 128);
        }
    }

    buf[i % 128] = 0x80;
    if ((i % 128) >= 112) {
        sha512_transform(state, buf);
        memset(buf, 0, 128);
    }

    uint64_t bits_len = data_len * 8;
    buf[127] = bits_len & 0xff;
    buf[126] = (bits_len >> 8) & 0xff;
    buf[125] = (bits_len >> 16) & 0xff;
    buf[124] = (bits_len >> 24) & 0xff;
    buf[123] = (bits_len >> 32) & 0xff;
    buf[122] = (bits_len >> 40) & 0xff;
    buf[121] = (bits_len >> 48) & 0xff;
    buf[120] = (bits_len >> 56) & 0xff;

    sha512_transform(state, buf);
}

static void sha512_final(uint8_t hash[], uint64_t *state) {   
    for (int i = 0; i < 8; ++i) {
        hash[(i * 8) + 0] = (state[i] >> 56) & 0xff;
        hash[(i * 8) + 1] = (state[i] >> 48) & 0xff;
        hash[(i * 8) + 2] = (state[i] >> 40) & 0xff;
        hash[(i * 8) + 3] = (state[i] >> 32) & 0xff;
        hash[(i * 8) + 4] = (state[i] >> 24) & 0xff;
        hash[(i * 8) + 5] = (state[i] >> 16) & 0xff;
        hash[(i * 8) + 6] = (state[i] >> 8) & 0xff;
        hash[(i * 8) + 7] = state[i] & 0xff;
    }
}

uint8_t* SHA512(uint8_t *input, int input_len){
    uint64_t state[8 + 128 / 8];
    uint8_t* hash = (uint8_t *)malloc(sizeof(uint8_t) * SHA512_DIGEST_LENGTH);
    
    sha512_initialize(state);
    sha512_update(state, (uint8_t*)input, input_len);
    sha512_final(hash, state);

    return hash;
}