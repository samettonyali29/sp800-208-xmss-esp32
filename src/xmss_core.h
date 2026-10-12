/*
 * xmss_core.h - XMSS and XMSS^MT primitives (RFC 8391, NIST SP 800-208)
 *
 * Stateless building blocks: parameter tables, the tweakable hash functions
 * (F, H, H_msg, PRF, PRF_keygen), WOTS+, L-trees, Merkle tree nodes,
 * verification, and the deterministic single-tree functions used by the
 * test vectors. The stateful private key is in xmss_key.c.
 *
 * Internally every n-byte string (seeds, keys, nodes, digests) is kept as
 * n/4 big-endian 32-bit words: all inputs of the XMSS hash functions are
 * word aligned, so the SHA-256 message blocks (and the hardware
 * accelerator's registers) are filled without byte shuffling.
 *
 * Copyright (c) 2026 The sp800-208-xmss-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef XMSS_CORE_H
#define XMSS_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- OIDs (RFC 8391, SP 800-208 Section 5) ------------------------------ */

/* XMSS */
#define XMSS_SHA2_10_256 0x00000001u
#define XMSS_SHA2_16_256 0x00000002u
#define XMSS_SHA2_20_256 0x00000003u
#define XMSS_SHA2_10_192 0x0000000Du
#define XMSS_SHA2_16_192 0x0000000Eu
#define XMSS_SHA2_20_192 0x0000000Fu
#define XMSS_SHAKE256_10_256 0x00000010u
#define XMSS_SHAKE256_16_256 0x00000011u
#define XMSS_SHAKE256_20_256 0x00000012u
#define XMSS_SHAKE256_10_192 0x00000013u
#define XMSS_SHAKE256_16_192 0x00000014u
#define XMSS_SHAKE256_20_192 0x00000015u

/* XMSS^MT */
#define XMSSMT_SHA2_20_2_256 0x00000001u
#define XMSSMT_SHA2_20_4_256 0x00000002u
#define XMSSMT_SHA2_40_2_256 0x00000003u
#define XMSSMT_SHA2_40_4_256 0x00000004u
#define XMSSMT_SHA2_40_8_256 0x00000005u
#define XMSSMT_SHA2_60_3_256 0x00000006u
#define XMSSMT_SHA2_60_6_256 0x00000007u
#define XMSSMT_SHA2_60_12_256 0x00000008u
#define XMSSMT_SHA2_20_2_192 0x00000021u
#define XMSSMT_SHA2_20_4_192 0x00000022u
#define XMSSMT_SHA2_40_2_192 0x00000023u
#define XMSSMT_SHA2_40_4_192 0x00000024u
#define XMSSMT_SHA2_40_8_192 0x00000025u
#define XMSSMT_SHA2_60_3_192 0x00000026u
#define XMSSMT_SHA2_60_6_192 0x00000027u
#define XMSSMT_SHA2_60_12_192 0x00000028u
#define XMSSMT_SHAKE256_20_2_256 0x00000029u
#define XMSSMT_SHAKE256_20_4_256 0x0000002Au
#define XMSSMT_SHAKE256_40_2_256 0x0000002Bu
#define XMSSMT_SHAKE256_40_4_256 0x0000002Cu
#define XMSSMT_SHAKE256_40_8_256 0x0000002Du
#define XMSSMT_SHAKE256_60_3_256 0x0000002Eu
#define XMSSMT_SHAKE256_60_6_256 0x0000002Fu
#define XMSSMT_SHAKE256_60_12_256 0x00000030u
#define XMSSMT_SHAKE256_20_2_192 0x00000031u
#define XMSSMT_SHAKE256_20_4_192 0x00000032u
#define XMSSMT_SHAKE256_40_2_192 0x00000033u
#define XMSSMT_SHAKE256_40_4_192 0x00000034u
#define XMSSMT_SHAKE256_40_8_192 0x00000035u
#define XMSSMT_SHAKE256_60_3_192 0x00000036u
#define XMSSMT_SHAKE256_60_6_192 0x00000037u
#define XMSSMT_SHAKE256_60_12_192 0x00000038u

#define XMSS_MAX_N 32
#define XMSS_MAX_NW 8 /* n / 4 */
#define XMSS_MAX_LEN 67
#define XMSS_MAX_TH 20 /* height of one tree */
#define XMSS_MAX_D 12

typedef struct {
  uint32_t oid;
  uint8_t mt;        /* 0: XMSS, 1: XMSS^MT */
  uint8_t n;         /* bytes */
  uint8_t nw;        /* n / 4 words */
  uint8_t padw;      /* words of the toByte(X, .) prefix: 8 (n = 32) or 1 (n = 24) */
  uint8_t shake;     /* 0: SHA-256(/192), 1: SHAKE256 */
  uint8_t h;         /* total height */
  uint8_t d;         /* layers */
  uint8_t th;        /* height of one tree = h / d */
  uint8_t len1, len2, len; /* WOTS+ (w = 16) */
  uint8_t idx_bytes; /* index in the signature: 4 (XMSS) or ceil(h / 8) */
  const char *name;
} xmss_param;

const xmss_param *xmss_param_get(uint32_t oid);   /* XMSS OIDs */
const xmss_param *xmssmt_param_get(uint32_t oid); /* XMSS^MT OIDs */
const xmss_param *xmss_param_by_name(const char *name); /* "XMSS-SHA2_10_256" */

static inline size_t xmss_pk_len(const xmss_param *p)
{
  return 4 + 2 * (size_t)p->n;
}
/* treeSig: WOTS+ signature || authentication path */
static inline size_t xmss_tree_sig_len(const xmss_param *p)
{
  return ((size_t)p->len + p->th) * p->n;
}
static inline size_t xmss_sig_len(const xmss_param *p)
{
  return p->idx_bytes + (size_t)p->n + p->d * xmss_tree_sig_len(p);
}

/* ---- helpers ------------------------------------------------------------ */

static inline void xmss_put32(uint8_t *b, uint32_t v)
{
  b[0] = (uint8_t)(v >> 24);
  b[1] = (uint8_t)(v >> 16);
  b[2] = (uint8_t)(v >> 8);
  b[3] = (uint8_t)v;
}
static inline uint32_t xmss_get32(const uint8_t *b)
{
  return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
}
/* n-byte string <-> n/4 big-endian words */
void xmss_bytes_to_words(uint32_t *w, const uint8_t *b, unsigned nw);
void xmss_words_to_bytes(uint8_t *b, const uint32_t *w, unsigned nw);

/* ---- one XMSS tree (hash context) --------------------------------------- */

typedef struct {
  const xmss_param *p;
  uint32_t seed[XMSS_MAX_NW];    /* SEED (public) */
  uint32_t sk[XMSS_MAX_NW];      /* S_XMSS (WOTS+ key derivation), secret */
  uint32_t layer;                /* address of this tree */
  uint64_t tree;
  /* SHA-256, n = 32: states after the first block of PRF / PRF_keygen */
  uint32_t mid_prf[8];
  uint32_t mid_kg[8];
  uint8_t hw; /* SHA-256 on the hardware accelerator */
} xmss_tree;

/* Sets up a tree context; sk may be NULL (verification only). */
void xmss_tree_init(xmss_tree *t, const xmss_param *p, const uint32_t *seed,
                    const uint32_t *sk, uint32_t layer, uint64_t tree);
void xmss_tree_wipe(xmss_tree *t);

/* Leaf q: L-tree of the WOTS+ public key of key pair q */
void xmss_leaf(const xmss_tree *t, uint32_t q, uint32_t *out);
/* Interior node: parent (height hc + 1, index i) of left/right (height hc) */
void xmss_node(const xmss_tree *t, unsigned hc, uint32_t i, const uint32_t *left,
               const uint32_t *right, uint32_t *out);

/* WOTS+ signature (len * n bytes) of the n-byte message M (words) with key
 * pair q */
void xmss_wots_sign(const xmss_tree *t, uint32_t q, const uint32_t *M, uint8_t *sig);

/* Root of the whole tree (2^th leaves) -- for tests and key generation */
void xmss_tree_root(const xmss_tree *t, uint32_t *root);
/* treeSig of M with leaf q, recomputing the tree for the path -- for tests */
void xmss_tree_sign_internal(const xmss_tree *t, uint32_t q, const uint32_t *M,
                             uint8_t *sig);

/* ---- message hashing ---------------------------------------------------- */

/* r = PRF(SK_PRF, toByte(idx, 32)) */
void xmss_prf_index(const xmss_param *p, const uint32_t *sk_prf, uint64_t idx, uint32_t *r);
/* M' = H_msg(r || root || toByte(idx, n), msg) */
void xmss_hash_message(const xmss_param *p, const uint32_t *r, const uint32_t *root,
                       uint64_t idx, const uint8_t *msg, size_t msglen, uint32_t *out);

/* ---- complete operations ------------------------------------------------ */

/* 0 = valid, -1 = invalid / malformed. pk: OID || root || SEED */
int xmss_verify(const uint8_t *pk, size_t pklen, const uint8_t *msg, size_t msglen,
                const uint8_t *sig, size_t siglen);
int xmssmt_verify(const uint8_t *pk, size_t pklen, const uint8_t *msg, size_t msglen,
                  const uint8_t *sig, size_t siglen);

/* Deterministic single-tree XMSS (d = 1), as in RFC 8391 / SP 800-208
 * Algorithm 10' and 12 -- for test vectors: public key from the seeds, and
 * the signature with index idx (the tree is recomputed). */
void xmss_keygen_internal(const xmss_param *p, const uint8_t *sk_seed, const uint8_t *seed,
                          uint8_t *pk);
void xmss_sign_internal(const xmss_param *p, const uint8_t *sk_seed, const uint8_t *sk_prf,
                        const uint8_t *seed, const uint8_t *root, uint32_t idx,
                        const uint8_t *msg, size_t msglen, uint8_t *sig);

/* Cooperative scheduling hook, called once per leaf (platform layer). */
void xmss_yield(void);

#ifdef __cplusplus
}
#endif

#endif /* XMSS_CORE_H */
