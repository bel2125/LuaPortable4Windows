/* Derived from https://github.com/kalven/sha-2 and converted from C++ to clean C */
/* sha-2 is a Public domain SHA-224/256/384/512 processors in C++ without
 * external dependencies. Adapted from LibTomCrypt. */

#include <stdint.h>

#ifndef SHA_2_H
#define SHA_2_H

struct sha256_state
{
    uint64_t length;
    uint32_t state[8];
    uint32_t curlen;
    unsigned char buf[64];
};

struct sha512_state
{
    uint64_t length;
    uint64_t state[8];
    uint32_t curlen;
    unsigned char buf[128];
};

struct sha224_state
{
    struct sha256_state md;
};

struct sha384_state
{
    struct sha512_state md;
};

void sha224_init(struct sha224_state* md);
void sha224_process(struct sha224_state* md, const void* in, uint32_t inlen);
void sha224_done(struct sha224_state* md, void* out);

void sha256_init(struct sha256_state* md);
void sha256_process(struct sha256_state* md, const void* in, uint32_t inlen);
void sha256_done(struct sha256_state* md, void* out);

void sha384_init(struct sha384_state* md);
void sha384_process(struct sha384_state* md, const void* in, uint32_t inlen);
void sha384_done(struct sha384_state* md, void* out);

void sha512_init(struct sha512_state* md);
void sha512_process(struct sha512_state* md, const void* in, uint32_t inlen);
void sha512_done(struct sha512_state* md, void* out);

#endif

