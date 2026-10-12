/*
 * xmss_hash.h - SHA-256 and SHAKE256 for sp800-208-xmss-esp32
 *
 * Portable C (no platform dependencies). Besides the usual incremental
 * interfaces, xmss_sha256_compress() is exported for the single-block fast
 * paths of LM-OTS, and xmss_keccak_f1600() for the SHAKE256 ones.
 *
 * Copyright (c) 2026 The sp800-208-xmss-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef XMSS_HASH_H
#define XMSS_HASH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- SHA-256 (FIPS 180-4) ---------------------------------------------- */

typedef struct {
  uint32_t h[8];
  uint8_t buf[64];
  uint64_t len; /* total bytes absorbed */
  size_t fill;  /* bytes in buf */
} xmss_sha256_ctx;

extern const uint32_t xmss_sha256_iv[8];

void xmss_sha256_compress(uint32_t h[8], const uint8_t block[64]);
/* the same, block given as 16 big-endian words */
void xmss_sha256_compress_words(uint32_t h[8], const uint32_t block[16]);
void xmss_sha256_init(xmss_sha256_ctx *c);
void xmss_sha256_update(xmss_sha256_ctx *c, const void *in, size_t len);
/* writes the first outlen (<= 32) bytes of the digest */
void xmss_sha256_final(xmss_sha256_ctx *c, uint8_t *out, size_t outlen);

/* ---- SHAKE256 (FIPS 202) ----------------------------------------------- */

#define XMSS_SHAKE256_RATE 136

typedef struct {
  uint64_t s[25];
  size_t pos; /* absorb / squeeze position within the rate */
} xmss_shake256_ctx;

void xmss_keccak_f1600(uint64_t s[25]);
void xmss_shake256_init(xmss_shake256_ctx *c);
void xmss_shake256_absorb(xmss_shake256_ctx *c, const void *in, size_t len);
void xmss_shake256_finalize(xmss_shake256_ctx *c);
void xmss_shake256_squeeze(xmss_shake256_ctx *c, uint8_t *out, size_t len);

/* ---- hash selected by the parameter set -------------------------------- */

/* SP 800-208 hash functions: SHA-256 (n = 32), SHA-256/192 (SHA-256
 * truncated to n = 24 bytes), SHAKE256/256 and SHAKE256/192. */
typedef struct {
  union {
    xmss_sha256_ctx sha;
    xmss_shake256_ctx shake;
  } u;
  uint8_t is_shake;
} xmss_hash_ctx;

void xmss_hash_init(xmss_hash_ctx *c, int is_shake);
void xmss_hash_update(xmss_hash_ctx *c, const void *in, size_t len);
void xmss_hash_final(xmss_hash_ctx *c, uint8_t *out, size_t n);

void xmss_zeroize(void *p, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* XMSS_HASH_H */
