/*
 * xmss_core.c - XMSS and XMSS^MT primitives (RFC 8391, NIST SP 800-208)
 *
 * Copyright (c) 2026 The sp800-208-xmss-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include "xmss_core.h"
#include "xmss_hash.h"
#include "xmss_hwsha.h"

/* hash function domain separators: toByte(X, padding) prefixes */
#define PAD_F 0
#define PAD_H 1
#define PAD_HASH 2
#define PAD_PRF 3
#define PAD_PRF_KEYGEN 4

/* address types */
#define ADRS_OTS 0
#define ADRS_LTREE 1
#define ADRS_HASHTREE 2

/* ---- parameter sets (SP 800-208 Section 5, w = 16) ---------------------- */

#define XP(OID, NAME, N, SHAKE, H) \
  {OID, 0, N, N / 4, N == 32 ? 8 : 1, SHAKE, H, 1, H, 2 * N, 3, 2 * N + 3, 4, NAME}
#define MP(OID, NAME, N, SHAKE, H, D) \
  {OID, 1, N, N / 4, N == 32 ? 8 : 1, SHAKE, H, D, H / D, 2 * N, 3, 2 * N + 3, (H + 7) / 8, NAME}

static const xmss_param XMSS_PARAMS[] = {
    XP(XMSS_SHA2_10_256, "XMSS-SHA2_10_256", 32, 0, 10),
    XP(XMSS_SHA2_16_256, "XMSS-SHA2_16_256", 32, 0, 16),
    XP(XMSS_SHA2_20_256, "XMSS-SHA2_20_256", 32, 0, 20),
    XP(XMSS_SHA2_10_192, "XMSS-SHA2_10_192", 24, 0, 10),
    XP(XMSS_SHA2_16_192, "XMSS-SHA2_16_192", 24, 0, 16),
    XP(XMSS_SHA2_20_192, "XMSS-SHA2_20_192", 24, 0, 20),
    XP(XMSS_SHAKE256_10_256, "XMSS-SHAKE256_10_256", 32, 1, 10),
    XP(XMSS_SHAKE256_16_256, "XMSS-SHAKE256_16_256", 32, 1, 16),
    XP(XMSS_SHAKE256_20_256, "XMSS-SHAKE256_20_256", 32, 1, 20),
    XP(XMSS_SHAKE256_10_192, "XMSS-SHAKE256_10_192", 24, 1, 10),
    XP(XMSS_SHAKE256_16_192, "XMSS-SHAKE256_16_192", 24, 1, 16),
    XP(XMSS_SHAKE256_20_192, "XMSS-SHAKE256_20_192", 24, 1, 20),
};

static const xmss_param XMSSMT_PARAMS[] = {
    MP(XMSSMT_SHA2_20_2_256, "XMSSMT-SHA2_20/2_256", 32, 0, 20, 2),
    MP(XMSSMT_SHA2_20_4_256, "XMSSMT-SHA2_20/4_256", 32, 0, 20, 4),
    MP(XMSSMT_SHA2_40_2_256, "XMSSMT-SHA2_40/2_256", 32, 0, 40, 2),
    MP(XMSSMT_SHA2_40_4_256, "XMSSMT-SHA2_40/4_256", 32, 0, 40, 4),
    MP(XMSSMT_SHA2_40_8_256, "XMSSMT-SHA2_40/8_256", 32, 0, 40, 8),
    MP(XMSSMT_SHA2_60_3_256, "XMSSMT-SHA2_60/3_256", 32, 0, 60, 3),
    MP(XMSSMT_SHA2_60_6_256, "XMSSMT-SHA2_60/6_256", 32, 0, 60, 6),
    MP(XMSSMT_SHA2_60_12_256, "XMSSMT-SHA2_60/12_256", 32, 0, 60, 12),
    MP(XMSSMT_SHA2_20_2_192, "XMSSMT-SHA2_20/2_192", 24, 0, 20, 2),
    MP(XMSSMT_SHA2_20_4_192, "XMSSMT-SHA2_20/4_192", 24, 0, 20, 4),
    MP(XMSSMT_SHA2_40_2_192, "XMSSMT-SHA2_40/2_192", 24, 0, 40, 2),
    MP(XMSSMT_SHA2_40_4_192, "XMSSMT-SHA2_40/4_192", 24, 0, 40, 4),
    MP(XMSSMT_SHA2_40_8_192, "XMSSMT-SHA2_40/8_192", 24, 0, 40, 8),
    MP(XMSSMT_SHA2_60_3_192, "XMSSMT-SHA2_60/3_192", 24, 0, 60, 3),
    MP(XMSSMT_SHA2_60_6_192, "XMSSMT-SHA2_60/6_192", 24, 0, 60, 6),
    MP(XMSSMT_SHA2_60_12_192, "XMSSMT-SHA2_60/12_192", 24, 0, 60, 12),
    MP(XMSSMT_SHAKE256_20_2_256, "XMSSMT-SHAKE256_20/2_256", 32, 1, 20, 2),
    MP(XMSSMT_SHAKE256_20_4_256, "XMSSMT-SHAKE256_20/4_256", 32, 1, 20, 4),
    MP(XMSSMT_SHAKE256_40_2_256, "XMSSMT-SHAKE256_40/2_256", 32, 1, 40, 2),
    MP(XMSSMT_SHAKE256_40_4_256, "XMSSMT-SHAKE256_40/4_256", 32, 1, 40, 4),
    MP(XMSSMT_SHAKE256_40_8_256, "XMSSMT-SHAKE256_40/8_256", 32, 1, 40, 8),
    MP(XMSSMT_SHAKE256_60_3_256, "XMSSMT-SHAKE256_60/3_256", 32, 1, 60, 3),
    MP(XMSSMT_SHAKE256_60_6_256, "XMSSMT-SHAKE256_60/6_256", 32, 1, 60, 6),
    MP(XMSSMT_SHAKE256_60_12_256, "XMSSMT-SHAKE256_60/12_256", 32, 1, 60, 12),
    MP(XMSSMT_SHAKE256_20_2_192, "XMSSMT-SHAKE256_20/2_192", 24, 1, 20, 2),
    MP(XMSSMT_SHAKE256_20_4_192, "XMSSMT-SHAKE256_20/4_192", 24, 1, 20, 4),
    MP(XMSSMT_SHAKE256_40_2_192, "XMSSMT-SHAKE256_40/2_192", 24, 1, 40, 2),
    MP(XMSSMT_SHAKE256_40_4_192, "XMSSMT-SHAKE256_40/4_192", 24, 1, 40, 4),
    MP(XMSSMT_SHAKE256_40_8_192, "XMSSMT-SHAKE256_40/8_192", 24, 1, 40, 8),
    MP(XMSSMT_SHAKE256_60_3_192, "XMSSMT-SHAKE256_60/3_192", 24, 1, 60, 3),
    MP(XMSSMT_SHAKE256_60_6_192, "XMSSMT-SHAKE256_60/6_192", 24, 1, 60, 6),
    MP(XMSSMT_SHAKE256_60_12_192, "XMSSMT-SHAKE256_60/12_192", 24, 1, 60, 12),
};

const xmss_param *xmss_param_get(uint32_t oid)
{
  size_t i;
  for (i = 0; i < sizeof XMSS_PARAMS / sizeof XMSS_PARAMS[0]; i++) {
    if (XMSS_PARAMS[i].oid == oid) {
      return &XMSS_PARAMS[i];
    }
  }
  return NULL;
}

const xmss_param *xmssmt_param_get(uint32_t oid)
{
  size_t i;
  for (i = 0; i < sizeof XMSSMT_PARAMS / sizeof XMSSMT_PARAMS[0]; i++) {
    if (XMSSMT_PARAMS[i].oid == oid) {
      return &XMSSMT_PARAMS[i];
    }
  }
  return NULL;
}

const xmss_param *xmss_param_by_name(const char *name)
{
  size_t i;
  for (i = 0; i < sizeof XMSS_PARAMS / sizeof XMSS_PARAMS[0]; i++) {
    if (strcmp(XMSS_PARAMS[i].name, name) == 0) {
      return &XMSS_PARAMS[i];
    }
  }
  for (i = 0; i < sizeof XMSSMT_PARAMS / sizeof XMSSMT_PARAMS[0]; i++) {
    if (strcmp(XMSSMT_PARAMS[i].name, name) == 0) {
      return &XMSSMT_PARAMS[i];
    }
  }
  return NULL;
}

void xmss_bytes_to_words(uint32_t *w, const uint8_t *b, unsigned nw)
{
  unsigned i;
  for (i = 0; i < nw; i++) {
    w[i] = xmss_get32(b + 4 * i);
  }
}

void xmss_words_to_bytes(uint8_t *b, const uint32_t *w, unsigned nw)
{
  unsigned i;
  for (i = 0; i < nw; i++) {
    xmss_put32(b + 4 * i, w[i]);
  }
}

/* ---- hashing of word strings -------------------------------------------- */

#define MAX_MSG_WORDS 32 /* H / PRF_keygen with n = 32: 8 + 8 + 16 words */

/* SHA-256 of mw words starting from IV (done = 0) or from a midstate after
 * `done` blocks; the first nw words of the digest go to out. */
static void sha_words(const uint32_t *mid, unsigned done, const uint32_t *m, unsigned mw,
                      uint32_t *out, unsigned nw, int hw)
{
  uint32_t blk[48], H[8];
  const uint64_t bits = ((uint64_t)done * 64 + 4u * mw) * 8;
  const unsigned nblocks = (mw + 1 + 2 + 15) / 16;
  unsigned i;
  memcpy(blk, m, 4u * mw);
  blk[mw] = 0x80000000u;
  for (i = mw + 1; i < nblocks * 16 - 2; i++) {
    blk[i] = 0;
  }
  blk[nblocks * 16 - 2] = (uint32_t)(bits >> 32);
  blk[nblocks * 16 - 1] = (uint32_t)bits;
#if defined(XMSS_HW_SHA_BUILD)
  if (hw && mid == NULL && xmss_hw_sha256_blocks(blk, nblocks, H) == 0) {
    memcpy(out, H, 4u * nw);
    return;
  }
#else
  (void)hw;
#endif
  memcpy(H, mid != NULL ? mid : xmss_sha256_iv, sizeof H);
  for (i = 0; i < nblocks; i++) {
    xmss_sha256_compress_words(H, blk + 16 * i);
  }
  memcpy(out, H, 4u * nw);
}

/* SHAKE256 of mw words, n-byte output as words */
static void shake_words(const uint32_t *m, unsigned mw, uint32_t *out, unsigned nw)
{
  uint8_t buf[4 * MAX_MSG_WORDS], o[XMSS_MAX_N];
  xmss_shake256_ctx c;
  xmss_words_to_bytes(buf, m, mw);
  xmss_shake256_init(&c);
  xmss_shake256_absorb(&c, buf, 4u * mw);
  xmss_shake256_finalize(&c);
  xmss_shake256_squeeze(&c, o, 4u * nw);
  xmss_bytes_to_words(out, o, nw);
}

static void hash_words(const xmss_param *p, int hw, const uint32_t *m, unsigned mw,
                       uint32_t *out)
{
  if (p->shake) {
    shake_words(m, mw, out, p->nw);
  } else {
    sha_words(NULL, 0, m, mw, out, p->nw, hw);
  }
}

/* toByte(x, padding) as words */
static inline unsigned put_prefix(const xmss_param *p, uint32_t *m, uint32_t x)
{
  unsigned i;
  for (i = 0; i + 1 < p->padw; i++) {
    m[i] = 0;
  }
  m[p->padw - 1] = x;
  return p->padw;
}

/* SHA-256 with n = 32 and no hardware: the first block of PRF (prefix ||
 * SEED) and PRF_keygen (prefix || S_XMSS) is constant per tree */
static inline int use_midstates(const xmss_tree *t)
{
  return !t->p->shake && t->p->n == 32 && !t->hw;
}

/* PRF(SEED, ADRS) */
static void prf_adrs(const xmss_tree *t, const uint32_t adrs[8], uint32_t *out)
{
  uint32_t m[MAX_MSG_WORDS];
  unsigned k;
  if (use_midstates(t)) {
    sha_words(t->mid_prf, 1, adrs, 8, out, 8, 0);
    return;
  }
  k = put_prefix(t->p, m, PAD_PRF);
  memcpy(m + k, t->seed, 4u * t->p->nw);
  k += t->p->nw;
  memcpy(m + k, adrs, 32);
  k += 8;
  hash_words(t->p, t->hw, m, k, out);
}

/* PRF_keygen(S_XMSS, SEED || ADRS) (SP 800-208 Algorithm 10') */
static void prf_keygen(const xmss_tree *t, const uint32_t adrs[8], uint32_t *out)
{
  uint32_t m[MAX_MSG_WORDS];
  const unsigned nw = t->p->nw;
  unsigned k;
  if (use_midstates(t)) {
    memcpy(m, t->seed, 32);
    memcpy(m + 8, adrs, 32);
    sha_words(t->mid_kg, 1, m, 16, out, 8, 0);
    return;
  }
  k = put_prefix(t->p, m, PAD_PRF_KEYGEN);
  memcpy(m + k, t->sk, 4u * nw);
  k += nw;
  memcpy(m + k, t->seed, 4u * nw);
  k += nw;
  memcpy(m + k, adrs, 32);
  k += 8;
  hash_words(t->p, t->hw, m, k, out);
}

/* F(KEY, M XOR BM) with KEY, BM from PRF(SEED, ADRS) (RFC 8391 4.1.2) */
static void thash_f(const xmss_tree *t, uint32_t adrs[8], const uint32_t *in, uint32_t *out)
{
  uint32_t m[MAX_MSG_WORDS], bm[XMSS_MAX_NW];
  const unsigned nw = t->p->nw;
  unsigned k, i;
  k = put_prefix(t->p, m, PAD_F);
  adrs[7] = 0;
  prf_adrs(t, adrs, m + k);
  k += nw;
  adrs[7] = 1;
  prf_adrs(t, adrs, bm);
  for (i = 0; i < nw; i++) {
    m[k + i] = in[i] ^ bm[i];
  }
  hash_words(t->p, t->hw, m, k + nw, out);
}

/* RAND_HASH(LEFT, RIGHT, SEED, ADRS) (RFC 8391 4.1.4) */
static void thash_h(const xmss_tree *t, uint32_t adrs[8], const uint32_t *l, const uint32_t *r,
                    uint32_t *out)
{
  uint32_t m[MAX_MSG_WORDS], bm[XMSS_MAX_NW];
  const unsigned nw = t->p->nw;
  unsigned k, i;
  k = put_prefix(t->p, m, PAD_H);
  adrs[7] = 0;
  prf_adrs(t, adrs, m + k);
  k += nw;
  adrs[7] = 1;
  prf_adrs(t, adrs, bm);
  for (i = 0; i < nw; i++) {
    m[k + i] = l[i] ^ bm[i];
  }
  k += nw;
  adrs[7] = 2;
  prf_adrs(t, adrs, bm);
  for (i = 0; i < nw; i++) {
    m[k + i] = r[i] ^ bm[i];
  }
  hash_words(t->p, t->hw, m, k + nw, out);
}

/* ---- tree context ------------------------------------------------------- */

void xmss_tree_init(xmss_tree *t, const xmss_param *p, const uint32_t *seed,
                    const uint32_t *sk, uint32_t layer, uint64_t tree)
{
  memset(t, 0, sizeof *t);
  t->p = p;
  memcpy(t->seed, seed, 4u * p->nw);
  if (sk != NULL) {
    memcpy(t->sk, sk, 4u * p->nw);
  }
  t->layer = layer;
  t->tree = tree;
#if defined(XMSS_HW_SHA_BUILD)
  t->hw = !p->shake && xmss_hw_sha_active();
#endif
  if (!p->shake && p->n == 32) {
    uint32_t blk[16];
    memset(blk, 0, 28);
    blk[7] = PAD_PRF;
    memcpy(blk + 8, t->seed, 32);
    memcpy(t->mid_prf, xmss_sha256_iv, 32);
    xmss_sha256_compress_words(t->mid_prf, blk);
    blk[7] = PAD_PRF_KEYGEN;
    memcpy(blk + 8, t->sk, 32);
    memcpy(t->mid_kg, xmss_sha256_iv, 32);
    xmss_sha256_compress_words(t->mid_kg, blk);
    xmss_zeroize(blk, sizeof blk);
  }
}

void xmss_tree_wipe(xmss_tree *t)
{
  xmss_zeroize(t, sizeof *t);
}

static void adrs_init(const xmss_tree *t, uint32_t adrs[8], uint32_t type)
{
  adrs[0] = t->layer;
  adrs[1] = (uint32_t)(t->tree >> 32);
  adrs[2] = (uint32_t)t->tree;
  adrs[3] = type;
  adrs[4] = adrs[5] = adrs[6] = adrs[7] = 0;
}

/* hold the SHA hardware for a sequence of hashes */
static inline void hw_begin(const xmss_tree *t)
{
#if defined(XMSS_HW_SHA_BUILD)
  if (t->hw) {
    xmss_hw_begin();
  }
#else
  (void)t;
#endif
}

static inline void hw_end(const xmss_tree *t)
{
#if defined(XMSS_HW_SHA_BUILD)
  if (t->hw) {
    xmss_hw_end();
  }
#else
  (void)t;
#endif
}

/* ---- WOTS+ (w = 16) ----------------------------------------------------- */

static void wots_digits(const xmss_param *p, const uint32_t *M, uint8_t *d)
{
  unsigned i, csum = 0;
  for (i = 0; i < p->len1; i++) {
    d[i] = (uint8_t)((M[i / 8] >> (28 - 4 * (i % 8))) & 15);
    csum += 15 - d[i];
  }
  /* len2 = 3 digits; toByte(csum << 4, 2) read as base-16 digits */
  csum <<= 4;
  d[p->len1] = (uint8_t)((csum >> 12) & 15);
  d[p->len1 + 1] = (uint8_t)((csum >> 8) & 15);
  d[p->len1 + 2] = (uint8_t)((csum >> 4) & 15);
}

static void chain(const xmss_tree *t, uint32_t adrs[8], uint32_t *x, unsigned start,
                  unsigned steps)
{
  unsigned i;
  for (i = start; i < start + steps && i < 16; i++) {
    adrs[6] = i;
    thash_f(t, adrs, x, x);
  }
}

/* WOTS+ public key of key pair q into pk (len * nw words) */
static void wots_pk(const xmss_tree *t, uint32_t q, uint32_t *pk)
{
  const unsigned nw = t->p->nw;
  uint32_t adrs[8];
  unsigned j;
  adrs_init(t, adrs, ADRS_OTS);
  adrs[4] = q;
  for (j = 0; j < t->p->len; j++) {
    adrs[5] = j;
    adrs[6] = 0;
    adrs[7] = 0;
    prf_keygen(t, adrs, pk + j * nw);
    chain(t, adrs, pk + j * nw, 0, 15);
  }
}

void xmss_wots_sign(const xmss_tree *t, uint32_t q, const uint32_t *M, uint8_t *sig)
{
  const unsigned nw = t->p->nw;
  uint8_t d[XMSS_MAX_LEN];
  uint32_t adrs[8], x[XMSS_MAX_NW];
  unsigned j;
  wots_digits(t->p, M, d);
  adrs_init(t, adrs, ADRS_OTS);
  adrs[4] = q;
  hw_begin(t);
  for (j = 0; j < t->p->len; j++) {
    adrs[5] = j;
    adrs[6] = 0;
    adrs[7] = 0;
    prf_keygen(t, adrs, x);
    chain(t, adrs, x, 0, d[j]);
    xmss_words_to_bytes(sig + j * t->p->n, x, nw);
  }
  hw_end(t);
  xmss_zeroize(x, sizeof x);
}

static void wots_pk_from_sig(const xmss_tree *t, uint32_t q, const uint32_t *M,
                             const uint8_t *sig, uint32_t *pk)
{
  const unsigned nw = t->p->nw;
  uint8_t d[XMSS_MAX_LEN];
  uint32_t adrs[8];
  unsigned j;
  wots_digits(t->p, M, d);
  adrs_init(t, adrs, ADRS_OTS);
  adrs[4] = q;
  for (j = 0; j < t->p->len; j++) {
    adrs[5] = j;
    xmss_bytes_to_words(pk + j * nw, sig + j * t->p->n, nw);
    chain(t, adrs, pk + j * nw, d[j], 15 - d[j]);
  }
}

/* L-tree: compresses the WOTS+ public key (destroyed) into the leaf */
static void ltree(const xmss_tree *t, uint32_t q, uint32_t *pk, uint32_t *leaf)
{
  const unsigned nw = t->p->nw;
  unsigned l = t->p->len, height = 0, i;
  uint32_t adrs[8];
  adrs_init(t, adrs, ADRS_LTREE);
  adrs[4] = q;
  while (l > 1) {
    adrs[5] = height;
    for (i = 0; i < l / 2; i++) {
      adrs[6] = i;
      thash_h(t, adrs, pk + 2 * i * nw, pk + (2 * i + 1) * nw, pk + i * nw);
    }
    if (l & 1) {
      memcpy(pk + (l / 2) * nw, pk + (l - 1) * nw, 4u * nw);
      l = l / 2 + 1;
    } else {
      l = l / 2;
    }
    height++;
  }
  memcpy(leaf, pk, 4u * nw);
}

void xmss_leaf(const xmss_tree *t, uint32_t q, uint32_t *out)
{
  uint32_t pk[XMSS_MAX_LEN * XMSS_MAX_NW];
  hw_begin(t);
  wots_pk(t, q, pk);
  ltree(t, q, pk, out);
  hw_end(t);
  xmss_yield();
}

void xmss_node(const xmss_tree *t, unsigned hc, uint32_t i, const uint32_t *left,
               const uint32_t *right, uint32_t *out)
{
  uint32_t adrs[8];
  adrs_init(t, adrs, ADRS_HASHTREE);
  adrs[5] = hc;
  adrs[6] = i;
  thash_h(t, adrs, left, right, out);
}

/* Node at height j, index i (2^j leaves); collects the authentication path
 * of leaf q (siblings below height j) if path != NULL. */
static void treehash(const xmss_tree *t, unsigned j, uint32_t i, uint32_t *out, uint32_t q,
                     uint32_t *path)
{
  const unsigned nw = t->p->nw;
  uint32_t stack[(XMSS_MAX_TH + 1) * XMSS_MAX_NW];
  uint8_t heights[XMSS_MAX_TH + 1];
  unsigned sp = 0;
  uint32_t leaf;
  const uint32_t first = i << j, count = 1u << j;
  for (leaf = first; leaf < first + count; leaf++) {
    uint32_t idx = leaf;
    xmss_leaf(t, leaf, stack + sp * nw);
    if (path != NULL && leaf == (q ^ 1u)) {
      memcpy(path, stack + sp * nw, 4u * nw);
    }
    heights[sp++] = 0;
    while (sp >= 2 && heights[sp - 1] == heights[sp - 2]) {
      const unsigned ht = heights[sp - 1];
      idx >>= 1;
      xmss_node(t, ht, idx, stack + (sp - 2) * nw, stack + (sp - 1) * nw,
                stack + (sp - 2) * nw);
      heights[sp - 2] = (uint8_t)(ht + 1);
      sp--;
      if (path != NULL && ht + 1 < t->p->th && idx == ((q >> (ht + 1)) ^ 1u)) {
        memcpy(path + (ht + 1) * nw, stack + (sp - 1) * nw, 4u * nw);
      }
    }
  }
  memcpy(out, stack, 4u * nw);
}

void xmss_tree_root(const xmss_tree *t, uint32_t *root)
{
  treehash(t, t->p->th, 0, root, 0, NULL);
}

void xmss_tree_sign_internal(const xmss_tree *t, uint32_t q, const uint32_t *M, uint8_t *sig)
{
  const xmss_param *p = t->p;
  uint32_t root[XMSS_MAX_NW], path[XMSS_MAX_TH * XMSS_MAX_NW];
  xmss_wots_sign(t, q, M, sig);
  treehash(t, p->th, 0, root, q, path);
  xmss_words_to_bytes(sig + (size_t)p->len * p->n, path, (unsigned)p->th * p->nw);
}

/* ---- message hashing ---------------------------------------------------- */

void xmss_prf_index(const xmss_param *p, const uint32_t *sk_prf, uint64_t idx, uint32_t *r)
{
  uint32_t m[MAX_MSG_WORDS];
  unsigned k = put_prefix(p, m, PAD_PRF), i;
  memcpy(m + k, sk_prf, 4u * p->nw);
  k += p->nw;
  for (i = 0; i < 6; i++) {
    m[k + i] = 0;
  }
  m[k + 6] = (uint32_t)(idx >> 32);
  m[k + 7] = (uint32_t)idx;
  hash_words(p, 0, m, k + 8, r);
  xmss_zeroize(m, sizeof m);
}

void xmss_hash_message(const xmss_param *p, const uint32_t *r, const uint32_t *root,
                       uint64_t idx, const uint8_t *msg, size_t msglen, uint32_t *out)
{
  uint8_t buf[32 + 3 * XMSS_MAX_N], o[XMSS_MAX_N];
  const unsigned n = p->n, pad = 4u * p->padw;
  xmss_hash_ctx h;
  unsigned i;
  memset(buf, 0, pad);
  buf[pad - 1] = PAD_HASH;
  xmss_words_to_bytes(buf + pad, r, p->nw);
  xmss_words_to_bytes(buf + pad + n, root, p->nw);
  memset(buf + pad + 2 * n, 0, n); /* toByte(idx, n) */
  for (i = 0; i < 8; i++) {
    buf[pad + 3 * n - 1 - i] = (uint8_t)(idx >> (8 * i));
  }
  xmss_hash_init(&h, p->shake);
  xmss_hash_update(&h, buf, pad + 3 * n);
  if (msglen) {
    xmss_hash_update(&h, msg, msglen);
  }
  xmss_hash_final(&h, o, n);
  xmss_bytes_to_words(out, o, p->nw);
}

/* ---- verification ------------------------------------------------------- */

/* Root of the tree (layer, tree) from a treeSig of M with leaf q */
static void root_from_sig(const xmss_tree *t, uint32_t q, const uint32_t *M, const uint8_t *sig,
                          uint32_t *root)
{
  const xmss_param *p = t->p;
  const unsigned nw = p->nw;
  uint32_t pk[XMSS_MAX_LEN * XMSS_MAX_NW], sib[XMSS_MAX_NW], node[XMSS_MAX_NW];
  const uint8_t *path = sig + (size_t)p->len * p->n;
  unsigned k;
  hw_begin(t);
  wots_pk_from_sig(t, q, M, sig, pk);
  ltree(t, q, pk, node);
  for (k = 0; k < p->th; k++) {
    xmss_bytes_to_words(sib, path + k * p->n, nw);
    if ((q >> k) & 1) {
      xmss_node(t, k, q >> (k + 1), sib, node, node);
    } else {
      xmss_node(t, k, q >> (k + 1), node, sib, node);
    }
  }
  hw_end(t);
  memcpy(root, node, 4u * nw);
}

static int verify_common(const xmss_param *p, const uint8_t *pk, size_t pklen,
                         const uint8_t *msg, size_t msglen, const uint8_t *sig, size_t siglen)
{
  uint32_t seed[XMSS_MAX_NW], pkroot[XMSS_MAX_NW], r[XMSS_MAX_NW], M[XMSS_MAX_NW];
  uint64_t idx = 0;
  unsigned i, j;
  const uint8_t *s;
  uint32_t diff = 0;
  if (p == NULL || pklen != xmss_pk_len(p) || siglen != xmss_sig_len(p)) {
    return -1;
  }
  for (i = 0; i < p->idx_bytes; i++) {
    idx = (idx << 8) | sig[i];
  }
  if (p->h < 64 && (idx >> p->h) != 0) {
    return -1;
  }
  xmss_bytes_to_words(pkroot, pk + 4, p->nw);
  xmss_bytes_to_words(seed, pk + 4 + p->n, p->nw);
  xmss_bytes_to_words(r, sig + p->idx_bytes, p->nw);
  xmss_hash_message(p, r, pkroot, idx, msg, msglen, M);
  s = sig + p->idx_bytes + p->n;
  for (j = 0; j < p->d; j++) {
    xmss_tree t;
    const uint32_t q = (uint32_t)(idx & ((1u << p->th) - 1));
    idx >>= p->th;
    xmss_tree_init(&t, p, seed, NULL, j, idx);
    root_from_sig(&t, q, M, s, M); /* M becomes the root of this layer */
    s += xmss_tree_sig_len(p);
  }
  for (i = 0; i < p->nw; i++) {
    diff |= M[i] ^ pkroot[i];
  }
  return diff == 0 ? 0 : -1;
}

int xmss_verify(const uint8_t *pk, size_t pklen, const uint8_t *msg, size_t msglen,
                const uint8_t *sig, size_t siglen)
{
  if (pklen < 4) {
    return -1;
  }
  return verify_common(xmss_param_get(xmss_get32(pk)), pk, pklen, msg, msglen, sig, siglen);
}

int xmssmt_verify(const uint8_t *pk, size_t pklen, const uint8_t *msg, size_t msglen,
                  const uint8_t *sig, size_t siglen)
{
  if (pklen < 4) {
    return -1;
  }
  return verify_common(xmssmt_param_get(xmss_get32(pk)), pk, pklen, msg, msglen, sig, siglen);
}

/* ---- deterministic single-tree XMSS (test vectors) ---------------------- */

void xmss_keygen_internal(const xmss_param *p, const uint8_t *sk_seed, const uint8_t *seed,
                          uint8_t *pk)
{
  xmss_tree t;
  uint32_t s[XMSS_MAX_NW], k[XMSS_MAX_NW], root[XMSS_MAX_NW];
  xmss_bytes_to_words(s, seed, p->nw);
  xmss_bytes_to_words(k, sk_seed, p->nw);
  xmss_tree_init(&t, p, s, k, 0, 0);
  xmss_tree_root(&t, root);
  xmss_put32(pk, p->oid);
  xmss_words_to_bytes(pk + 4, root, p->nw);
  memcpy(pk + 4 + p->n, seed, p->n);
  xmss_tree_wipe(&t);
  xmss_zeroize(k, sizeof k);
}

void xmss_sign_internal(const xmss_param *p, const uint8_t *sk_seed, const uint8_t *sk_prf,
                        const uint8_t *seed, const uint8_t *root, uint32_t idx,
                        const uint8_t *msg, size_t msglen, uint8_t *sig)
{
  xmss_tree t;
  uint32_t s[XMSS_MAX_NW], k[XMSS_MAX_NW], prf[XMSS_MAX_NW], rt[XMSS_MAX_NW];
  uint32_t r[XMSS_MAX_NW], M[XMSS_MAX_NW];
  xmss_bytes_to_words(s, seed, p->nw);
  xmss_bytes_to_words(k, sk_seed, p->nw);
  xmss_bytes_to_words(prf, sk_prf, p->nw);
  xmss_bytes_to_words(rt, root, p->nw);
  xmss_prf_index(p, prf, idx, r);
  xmss_hash_message(p, r, rt, idx, msg, msglen, M);
  xmss_put32(sig, idx);
  xmss_words_to_bytes(sig + 4, r, p->nw);
  xmss_tree_init(&t, p, s, k, 0, 0);
  xmss_tree_sign_internal(&t, idx, M, sig + 4 + p->n);
  xmss_tree_wipe(&t);
  xmss_zeroize(k, sizeof k);
  xmss_zeroize(prf, sizeof prf);
}
