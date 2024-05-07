/*
 * Argon2 reference source code package - reference C implementations
 *
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
 *
 * You may use this work under the terms of a Creative Commons CC0 1.0
 * License/Waiver or the Apache Public License 2.0, at your option. The terms of
 * these licenses can be found at:
 *
 * - CC0 1.0 Universal : https://creativecommons.org/publicdomain/zero/1.0
 * - Apache 2.0        : https://www.apache.org/licenses/LICENSE-2.0
 *
 * You should have received a copy of both of these licenses along with this
 * software. If not, they may be obtained at the above URLs.
 */

#ifndef PORTABLE_a2blake2_H
#define PORTABLE_a2blake2_H

#include <argon2.h>

#if defined(__cplusplus)
extern "C" {
#endif

enum a2blake2b_constant {
    a2blake2B_BLOCKBYTES = 128,
    a2blake2B_OUTBYTES = 64,
    a2blake2B_KEYBYTES = 64,
    a2blake2B_SALTBYTES = 16,
    a2blake2B_PERSONALBYTES = 16
};

#pragma pack(push, 1)
typedef struct __a2blake2b_param {
    uint8_t digest_length;                   /* 1 */
    uint8_t key_length;                      /* 2 */
    uint8_t fanout;                          /* 3 */
    uint8_t depth;                           /* 4 */
    uint32_t leaf_length;                    /* 8 */
    uint64_t node_offset;                    /* 16 */
    uint8_t node_depth;                      /* 17 */
    uint8_t inner_length;                    /* 18 */
    uint8_t reserved[14];                    /* 32 */
    uint8_t salt[a2blake2B_SALTBYTES];         /* 48 */
    uint8_t personal[a2blake2B_PERSONALBYTES]; /* 64 */
} a2blake2b_param;
#pragma pack(pop)

typedef struct __a2blake2b_state {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t buf[a2blake2B_BLOCKBYTES];
    unsigned buflen;
    unsigned outlen;
    uint8_t last_node;
} a2blake2b_state;

/* Ensure param structs have not been wrongly padded */
/* Poor man's static_assert */
enum {
    a2blake2_size_check_0 = 1 / !!(CHAR_BIT == 8),
    a2blake2_size_check_2 =
        1 / !!(sizeof(a2blake2b_param) == sizeof(uint64_t) * CHAR_BIT)
};

/* Streaming API */
ARGON2_LOCAL int a2blake2b_init(a2blake2b_state *S, size_t outlen);
ARGON2_LOCAL int a2blake2b_init_key(a2blake2b_state *S, size_t outlen, const void *key,
                     size_t keylen);
ARGON2_LOCAL int a2blake2b_init_param(a2blake2b_state *S, const a2blake2b_param *P);
ARGON2_LOCAL int a2blake2b_update(a2blake2b_state *S, const void *in, size_t inlen);
ARGON2_LOCAL int a2blake2b_final(a2blake2b_state *S, void *out, size_t outlen);

/* Simple API */
ARGON2_LOCAL int a2blake2b(void *out, size_t outlen, const void *in, size_t inlen,
                         const void *key, size_t keylen);

/* Argon2 Team - Begin Code */
ARGON2_LOCAL int a2blake2b_long(void *out, size_t outlen, const void *in, size_t inlen);
/* Argon2 Team - End Code */

#if defined(__cplusplus)
}
#endif

#endif
