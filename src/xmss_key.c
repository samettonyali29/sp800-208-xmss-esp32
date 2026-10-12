/*
 * xmss_key.c - stateful XMSS / XMSS^MT private keys (see xmss_esp32.h)
 *
 * Levels: level 0 is the top tree (XMSS^MT layer d-1), level d-1 the bottom
 * tree (layer 0) that signs messages; XMSS is the case d = 1.
 *
 * Stored records:
 *   "hdr"   magic, XMSS / XMSS^MT, OID, SEED
 *   "ctr"   first signature index that has NOT been handed out yet
 *           (64-bit, big-endian); every index below it may have been used
 *   "lv<i>" tree of level i: tree number t, S_XMSS, SK_PRF, root and, for
 *           i > 0, the treeSig of its root by level i-1. A record in
 *           "pending" state (written before the tree is signed) marks an
 *           interrupted tree creation: that tree is abandoned.
 *   "ax<i>" tree cache of level i (public nodes), optional
 *
 * Index g (0 .. 2^h - 1): the bottom tree signs with leaf g mod 2^(h/d);
 * level i uses tree number t_i = g >> ((d - i) * h/d), whose root is signed
 * by leaf t_i mod 2^(h/d) of level i-1 (SP 800-208 Algorithm 12' with
 * idx_sig - t * 2^(h/d) = leaf). Each parent leaf signs exactly one child
 * tree, and the counter alone determines which one-time keys are used.
 *
 * Tree cache (per level, height h' = h/d, subtree height k = ceil(h'/2)):
 *   upper: all nodes of height >= k            2^(h'-k+1) nodes
 *   sub:   all nodes of the current subtree     2^(k+1) nodes
 *   next:  leaves of the following subtree, computed a few per signature
 *          (bottom level only)
 *
 * Copyright (c) 2026 The sp800-208-xmss-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>
#include "xmss_esp32.h"
#include "xmss_hash.h"

#define HDR_MAGIC0 'X'
#define HDR_MAGIC1 'M'
#define HDR_MAGIC2 'S'
#define HDR_MAGIC3 'K'
#define REC_VERSION 1
#define LV_PENDING 0
#define LV_READY 1

typedef struct {
  xmss_tree tree; /* parameters, SEED, S_XMSS, layer, tree number */
  uint32_t sk_prf[XMSS_MAX_NW];
  uint64_t t;
  uint8_t ready;
  uint32_t root[XMSS_MAX_NW];
  uint8_t *sig; /* treeSig of this level's root by level - 1 */
  size_t siglen;
  /* cache (nodes as n/4 words) */
  unsigned k;
  uint32_t *upper;
  uint32_t *sub;
  int64_t sub_idx;
  uint32_t *next;
  int64_t next_idx;
  uint32_t next_cnt;
} xmss_level;

struct xmss_key {
  xmss_store st;
  const xmss_param *p;
  unsigned levels; /* d */
  uint32_t seed[XMSS_MAX_NW];
  xmss_level lv[XMSS_MAX_D];
  unsigned below[XMSS_MAX_D]; /* (d - i) * h/d */
  uint64_t total, next, reserved;
  uint32_t autoreserve;
};

/* ---- helpers ------------------------------------------------------------ */

static void put64(uint8_t *b, uint64_t v)
{
  xmss_put32(b, (uint32_t)(v >> 32));
  xmss_put32(b + 4, (uint32_t)v);
}

static uint64_t get64(const uint8_t *b)
{
  return ((uint64_t)xmss_get32(b) << 32) | xmss_get32(b + 4);
}

static void rec_name(char *buf, const char *prefix, unsigned i)
{
  buf[0] = prefix[0];
  buf[1] = prefix[1];
  if (i < 10) {
    buf[2] = (char)('0' + i);
    buf[3] = 0;
  } else {
    buf[2] = (char)('0' + i / 10);
    buf[3] = (char)('0' + i % 10);
    buf[4] = 0;
  }
}

static unsigned subtree_height(unsigned h)
{
  return (h + 1) / 2;
}

#define NW(key) ((key)->p->nw)
#define TH(key) ((key)->p->th)

static void cache_free(xmss_level *lv)
{
  free(lv->upper);
  free(lv->sub);
  free(lv->next);
  lv->upper = lv->sub = lv->next = NULL;
  lv->sub_idx = lv->next_idx = -1;
  lv->next_cnt = 0;
}

static void level_free(xmss_level *lv)
{
  cache_free(lv);
  free(lv->sig);
  lv->sig = NULL;
  lv->siglen = 0;
  xmss_zeroize(lv->tree.sk, sizeof lv->tree.sk);
  xmss_zeroize(lv->tree.mid_kg, sizeof lv->tree.mid_kg);
  xmss_zeroize(lv->sk_prf, sizeof lv->sk_prf);
}

static int cache_alloc(const xmss_key *key, xmss_level *lv, int bottom)
{
  const unsigned nw = NW(key), h = TH(key), k = subtree_height(h);
  lv->k = k;
  lv->upper = (uint32_t *)malloc(((size_t)1 << (h - k + 1)) * nw * 4);
  lv->sub = (uint32_t *)malloc(((size_t)1 << (k + 1)) * nw * 4);
  lv->next = bottom ? (uint32_t *)malloc(((size_t)1 << k) * nw * 4) : NULL;
  lv->sub_idx = lv->next_idx = -1;
  lv->next_cnt = 0;
  if (lv->upper == NULL || lv->sub == NULL || (bottom && lv->next == NULL)) {
    cache_free(lv);
    return XMSS_ERR_NOMEM;
  }
  return XMSS_OK;
}

/* (Re)initialises the hash context of level i for tree number t */
static void level_tree_init(xmss_key *key, unsigned i, uint64_t t)
{
  xmss_level *lv = &key->lv[i];
  uint32_t sk[XMSS_MAX_NW];
  memcpy(sk, lv->tree.sk, sizeof sk);
  xmss_tree_init(&lv->tree, key->p, key->seed, sk, key->levels - 1 - i, t);
  lv->t = t;
  xmss_zeroize(sk, sizeof sk);
}

/* Interior nodes of subtree s from its leaves (local indices 2^k ..). Local
 * node l at depth dl has height k - dl and global index s*2^dl + l - 2^dl. */
static void subtree_hash_up(const xmss_key *key, const xmss_level *lv, uint64_t s, uint32_t *buf)
{
  const unsigned nw = NW(key), k = lv->k;
  uint32_t l;
  unsigned dl = k - 1;
  for (l = (1u << k) - 1; l >= 1; l--) {
    while (l < (1u << dl)) {
      dl--;
    }
    xmss_node(&lv->tree, k - dl - 1, (uint32_t)s * (1u << dl) + (l - (1u << dl)),
              buf + 2 * l * nw, buf + (2 * l + 1) * nw, buf + l * nw);
  }
}

static void subtree_compute(const xmss_key *key, const xmss_level *lv, uint64_t s, uint32_t *buf)
{
  const unsigned nw = NW(key), k = lv->k;
  uint32_t j;
  for (j = 0; j < (1u << k); j++) {
    xmss_leaf(&lv->tree, (uint32_t)(s << k) + j, buf + ((1u << k) + j) * nw);
  }
  subtree_hash_up(key, lv, s, buf);
}

/* upper[r]: node at depth dd = floor(log2 r), height h - dd, index r - 2^dd */
static void upper_hash_up(const xmss_key *key, const xmss_level *lv, uint32_t *upper)
{
  const unsigned nw = NW(key), h = TH(key), k = lv->k;
  uint32_t r;
  unsigned dd = h - k - 1;
  for (r = (1u << (h - k)) - 1; r >= 1; r--) {
    while (r < (1u << dd)) {
      dd--;
    }
    xmss_node(&lv->tree, h - dd - 1, r - (1u << dd), upper + 2 * r * nw,
              upper + (2 * r + 1) * nw, upper + r * nw);
  }
}

static int tree_build(xmss_key *key, xmss_level *lv, int bottom)
{
  const unsigned nw = NW(key), h = TH(key);
  unsigned k;
  int64_t s;
  int rc;
  cache_free(lv);
  rc = cache_alloc(key, lv, bottom);
  if (rc != XMSS_OK) {
    return rc;
  }
  k = lv->k;
  for (s = ((int64_t)1 << (h - k)) - 1; s >= 0; s--) {
    subtree_compute(key, lv, (uint64_t)s, lv->sub);
    memcpy(lv->upper + (((size_t)1 << (h - k)) + (size_t)s) * nw, lv->sub + nw, 4u * nw);
    if (s == 1 && bottom) {
      memcpy(lv->next, lv->sub + ((size_t)1 << k) * nw, ((size_t)1 << k) * nw * 4);
      lv->next_idx = 1;
      lv->next_cnt = 1u << k;
    }
  }
  lv->sub_idx = 0;
  upper_hash_up(key, lv, lv->upper);
  memcpy(lv->root, lv->upper + nw, 4u * nw);
  return XMSS_OK;
}

static int sub_select(const xmss_key *key, xmss_level *lv, uint64_t s)
{
  const unsigned nw = NW(key), h = TH(key), k = lv->k;
  if (lv->sub_idx != (int64_t)s) {
    if (lv->next != NULL && lv->next_idx == (int64_t)s && lv->next_cnt == (1u << k)) {
      memcpy(lv->sub + ((size_t)1 << k) * nw, lv->next, ((size_t)1 << k) * nw * 4);
      subtree_hash_up(key, lv, s, lv->sub);
      lv->next_idx = -1;
      lv->next_cnt = 0;
    } else {
      subtree_compute(key, lv, s, lv->sub);
    }
    lv->sub_idx = (int64_t)s;
  }
  if (memcmp(lv->sub + nw, lv->upper + (((size_t)1 << (h - k)) + s) * nw, 4u * nw) != 0) {
    lv->sub_idx = -1;
    return XMSS_ERR_INTERNAL; /* corrupted cache */
  }
  return XMSS_OK;
}

/* authentication path of leaf q as bytes */
static int auth_path(const xmss_key *key, xmss_level *lv, uint32_t q, uint8_t *path)
{
  const unsigned nw = NW(key), n = key->p->n, h = TH(key), k = lv->k;
  unsigned i;
  int rc = sub_select(key, lv, q >> k);
  if (rc != XMSS_OK) {
    return rc;
  }
  for (i = 0; i < h; i++) {
    if (i < k) {
      const uint32_t l = (((1u << k) + (q & ((1u << k) - 1))) >> i) ^ 1u;
      xmss_words_to_bytes(path + i * n, lv->sub + (size_t)l * nw, nw);
    } else {
      const uint32_t r = (((1u << h) + q) >> i) ^ 1u;
      xmss_words_to_bytes(path + i * n, lv->upper + (size_t)r * nw, nw);
    }
  }
  return XMSS_OK;
}

static void next_advance(const xmss_key *key, xmss_level *lv, uint32_t q)
{
  const unsigned nw = NW(key), h = TH(key), k = lv->k;
  const uint64_t s = q >> k;
  const uint32_t j = q & ((1u << k) - 1);
  uint32_t todo, sigs_left;
  if (lv->next == NULL || s + 1 >= ((uint64_t)1 << (h - k))) {
    return;
  }
  if (lv->next_idx != (int64_t)(s + 1)) {
    lv->next_idx = (int64_t)(s + 1);
    lv->next_cnt = 0;
  }
  sigs_left = (1u << k) - j;
  todo = ((1u << k) - lv->next_cnt + sigs_left - 1) / sigs_left;
  while (todo-- && lv->next_cnt < (1u << k)) {
    xmss_leaf(&lv->tree, (uint32_t)((s + 1) << k) + lv->next_cnt,
              lv->next + (size_t)lv->next_cnt * nw);
    lv->next_cnt++;
  }
}

/* treeSig (WOTS+ signature of M || authentication path) with leaf q */
static int level_tree_sig(const xmss_key *key, xmss_level *lv, uint32_t q, const uint32_t *M,
                          uint8_t *sig)
{
  int rc;
  xmss_wots_sign(&lv->tree, q, M, sig);
  rc = auth_path(key, lv, q, sig + (size_t)key->p->len * key->p->n);
  if (rc != XMSS_OK) {
    xmss_zeroize(sig, xmss_tree_sig_len(key->p));
  }
  return rc;
}

/* ---- records ------------------------------------------------------------ */

static int lv_write(xmss_key *key, unsigned i)
{
  xmss_level *lv = &key->lv[i];
  const unsigned n = key->p->n, nw = NW(key);
  const size_t len = 4 + 8 + 3 * (size_t)n + 4 + lv->siglen;
  uint8_t *b = (uint8_t *)malloc(len), *p;
  char name[6];
  int rc;
  if (b == NULL) {
    return XMSS_ERR_NOMEM;
  }
  p = b;
  *p++ = REC_VERSION;
  *p++ = lv->ready;
  *p++ = 0;
  *p++ = 0;
  put64(p, lv->t);
  p += 8;
  xmss_words_to_bytes(p, lv->tree.sk, nw);
  p += n;
  xmss_words_to_bytes(p, lv->sk_prf, nw);
  p += n;
  xmss_words_to_bytes(p, lv->root, nw);
  p += n;
  xmss_put32(p, (uint32_t)lv->siglen);
  p += 4;
  if (lv->siglen) {
    memcpy(p, lv->sig, lv->siglen);
  }
  rec_name(name, "lv", i);
  rc = key->st.write(key->st.ctx, name, b, len) == 0 ? XMSS_OK : XMSS_ERR_STORE;
  xmss_zeroize(b, len);
  free(b);
  return rc;
}

static int lv_read(xmss_key *key, unsigned i)
{
  xmss_level *lv = &key->lv[i];
  const unsigned n = key->p->n, nw = NW(key);
  const size_t cap = 4 + 8 + 3 * (size_t)n + 4 + xmss_tree_sig_len(key->p);
  uint8_t *b = (uint8_t *)malloc(cap);
  const uint8_t *p;
  size_t len = 0;
  char name[6];
  int rc;
  if (b == NULL) {
    return XMSS_ERR_NOMEM;
  }
  rec_name(name, "lv", i);
  rc = key->st.read(key->st.ctx, name, b, cap, &len);
  if (rc != 0) {
    free(b);
    return rc == 1 ? XMSS_ERR_STATE : XMSS_ERR_STORE;
  }
  rc = XMSS_ERR_STATE;
  if (len >= 4 + 8 + 3 * (size_t)n + 4 && b[0] == REC_VERSION && b[1] <= LV_READY) {
    uint32_t sk[XMSS_MAX_NW];
    p = b + 4;
    lv->ready = b[1];
    lv->t = get64(p);
    p += 8;
    xmss_bytes_to_words(sk, p, nw);
    p += n;
    xmss_bytes_to_words(lv->sk_prf, p, nw);
    p += n;
    xmss_bytes_to_words(lv->root, p, nw);
    p += n;
    lv->siglen = xmss_get32(p);
    p += 4;
    xmss_tree_init(&lv->tree, key->p, key->seed, sk, key->levels - 1 - i, lv->t);
    xmss_zeroize(sk, sizeof sk);
    if (lv->siglen == len - (size_t)(p - b)) {
      rc = XMSS_OK;
      if (lv->siglen) {
        lv->sig = (uint8_t *)malloc(lv->siglen);
        if (lv->sig == NULL) {
          rc = XMSS_ERR_NOMEM;
        } else {
          memcpy(lv->sig, p, lv->siglen);
        }
      }
    }
  }
  xmss_zeroize(b, cap);
  free(b);
  return rc;
}

static int ax_write(xmss_key *key, unsigned i)
{
  xmss_level *lv = &key->lv[i];
  const unsigned n = key->p->n, nw = NW(key);
  const size_t nodes = ((size_t)1 << (TH(key) - lv->k + 1)) - 1;
  const size_t len = 8 + nodes * n;
  uint8_t *b = (uint8_t *)malloc(len);
  char name[6];
  int rc;
  if (b == NULL) {
    return XMSS_ERR_NOMEM;
  }
  put64(b, lv->t);
  xmss_words_to_bytes(b + 8, lv->upper + nw, (unsigned)(nodes * nw));
  rec_name(name, "ax", i);
  rc = key->st.write(key->st.ctx, name, b, len) == 0 ? XMSS_OK : XMSS_ERR_STORE;
  free(b);
  return rc;
}

/* Loads the upper cache of a ready level; 0 if it is valid. */
static int ax_read(xmss_key *key, unsigned i, int bottom)
{
  xmss_level *lv = &key->lv[i];
  const unsigned n = key->p->n, nw = NW(key);
  size_t nodes, len = 0;
  uint8_t *b;
  uint32_t *check;
  char name[6];
  int rc;
  if (cache_alloc(key, lv, bottom) != XMSS_OK) {
    return XMSS_ERR_NOMEM;
  }
  nodes = ((size_t)1 << (TH(key) - lv->k + 1)) - 1;
  b = (uint8_t *)malloc(8 + nodes * n);
  check = (uint32_t *)malloc((nodes + 1) * nw * 4);
  rec_name(name, "ax", i);
  rc = -1;
  if (b != NULL && check != NULL &&
      key->st.read(key->st.ctx, name, b, 8 + nodes * n, &len) == 0 && len == 8 + nodes * n &&
      get64(b) == lv->t) {
    xmss_bytes_to_words(check + nw, b + 8, (unsigned)(nodes * nw));
    memcpy(lv->upper, check, (nodes + 1) * nw * 4);
    upper_hash_up(key, lv, check); /* recompute the interior nodes */
    if (memcmp(check + nw, lv->upper + nw, nodes * nw * 4) == 0 &&
        memcmp(check + nw, lv->root, 4u * nw) == 0) {
      rc = 0;
    }
  }
  free(b);
  free(check);
  if (rc != 0) {
    cache_free(lv);
  }
  return rc;
}

static int ctr_write(xmss_key *key, uint64_t v)
{
  uint8_t b[8];
  put64(b, v);
  if (key->st.write(key->st.ctx, "ctr", b, 8) != 0) {
    return XMSS_ERR_STORE;
  }
  key->reserved = v;
  return XMSS_OK;
}

/* ---- setup -------------------------------------------------------------- */

static const xmss_param *param_of(int mt, uint32_t oid)
{
  return mt ? xmssmt_param_get(oid) : xmss_param_get(oid);
}

static xmss_key *key_alloc(const xmss_store *store, const xmss_param *p)
{
  xmss_key *key = (xmss_key *)calloc(1, sizeof *key);
  unsigned i;
  if (key == NULL) {
    return NULL;
  }
  key->st = *store;
  key->p = p;
  key->levels = p->d;
  for (i = 0; i < p->d; i++) {
    key->lv[i].sub_idx = key->lv[i].next_idx = -1;
    key->below[i] = (p->d - i) * p->th;
  }
  key->total = p->h >= 64 ? UINT64_MAX : (uint64_t)1 << p->h;
  return key;
}

void xmss_key_free(xmss_key *key)
{
  unsigned i;
  if (key == NULL) {
    return;
  }
  for (i = 0; i < XMSS_MAX_D; i++) {
    level_free(&key->lv[i]);
  }
  xmss_zeroize(key, sizeof *key);
  free(key);
}

/* ---- signing ------------------------------------------------------------ */

/* Creates tree number t of level i (i >= 1) and has its root signed by
 * level i-1 (pending record first, see the header comment). */
static int tree_create(xmss_key *key, unsigned i, uint64_t t)
{
  xmss_level *lv = &key->lv[i], *parent = &key->lv[i - 1];
  const unsigned nw = NW(key), th = TH(key);
  uint8_t sb[XMSS_MAX_N];
  uint8_t *sig;
  int rc;

  if ((t >> th) != parent->t || !parent->ready) {
    return XMSS_ERR_INTERNAL;
  }
  level_free(lv);
  lv->ready = LV_PENDING;
  memset(lv->root, 0, sizeof lv->root);
  if (xmss_randombytes(sb, key->p->n) != 0) {
    return XMSS_ERR_RNG;
  }
  xmss_bytes_to_words(lv->tree.sk, sb, nw);
  if (xmss_randombytes(sb, key->p->n) != 0) {
    return XMSS_ERR_RNG;
  }
  xmss_bytes_to_words(lv->sk_prf, sb, nw);
  xmss_zeroize(sb, sizeof sb);
  level_tree_init(key, i, t);
  rc = lv_write(key, i);
  if (rc != XMSS_OK) {
    return rc;
  }
  rc = tree_build(key, lv, i + 1 == key->levels);
  if (rc != XMSS_OK) {
    return rc;
  }
  sig = (uint8_t *)malloc(xmss_tree_sig_len(key->p));
  if (sig == NULL) {
    return XMSS_ERR_NOMEM;
  }
  rc = level_tree_sig(key, parent, (uint32_t)(t & ((1u << th) - 1)), lv->root, sig);
  if (rc != XMSS_OK) {
    free(sig);
    return rc;
  }
  lv->sig = sig;
  lv->siglen = xmss_tree_sig_len(key->p);
  rc = ax_write(key, i);
  if (rc != XMSS_OK) {
    return rc;
  }
  lv->ready = LV_READY;
  return lv_write(key, i);
}

static int level_cache_ensure(xmss_key *key, unsigned i)
{
  xmss_level *lv = &key->lv[i];
  const int bottom = i + 1 == key->levels;
  if (lv->upper != NULL) {
    return XMSS_OK;
  }
  if (ax_read(key, i, bottom) != 0) {
    uint32_t root[XMSS_MAX_NW];
    int rc;
    memcpy(root, lv->root, sizeof root);
    rc = tree_build(key, lv, bottom);
    if (rc != XMSS_OK) {
      return rc;
    }
    if (memcmp(root, lv->root, 4u * NW(key)) != 0) {
      return XMSS_ERR_STATE; /* S_XMSS does not match the stored root */
    }
    ax_write(key, i); /* best effort */
  }
  return XMSS_OK;
}

static int trees_select(xmss_key *key, uint64_t *g)
{
  unsigned i;
  int rc;
restart:
  if (*g >= key->total) {
    return XMSS_ERR_EXHAUSTED;
  }
  for (i = 1; i < key->levels; i++) {
    xmss_level *lv = &key->lv[i];
    const uint64_t need = *g >> key->below[i];
    if (lv->t == need && lv->ready) {
      rc = level_cache_ensure(key, i);
      if (rc != XMSS_OK) {
        return rc;
      }
      continue;
    }
    if (lv->t > need) {
      return XMSS_ERR_STATE;
    }
    if (lv->t == need) {
      /* pending: abandon this tree and its signatures */
      const uint64_t g2 = (need + 1) << key->below[i];
      if (g2 <= *g || g2 > key->total) {
        return XMSS_ERR_INTERNAL;
      }
      rc = ctr_write(key, g2);
      if (rc != XMSS_OK) {
        return rc;
      }
      key->next = *g = g2;
      goto restart;
    }
    rc = tree_create(key, i, need);
    if (rc != XMSS_OK) {
      return rc;
    }
  }
  return XMSS_OK;
}

int xmss_key_sign(xmss_key *key, const uint8_t *msg, size_t msglen, uint8_t *sig,
                  size_t *siglen)
{
  const xmss_param *p;
  xmss_level *bottom;
  uint32_t r[XMSS_MAX_NW], M[XMSS_MAX_NW];
  uint64_t g;
  uint32_t q;
  uint8_t *s;
  unsigned i;
  int rc;

  if (key == NULL || siglen == NULL || (msg == NULL && msglen != 0)) {
    return XMSS_ERR_PARAM;
  }
  p = key->p;
  if (*siglen < xmss_sig_len(p)) {
    return XMSS_ERR_BUFFER;
  }
  g = key->next;
  rc = trees_select(key, &g);
  if (rc != XMSS_OK) {
    return rc;
  }
  /* write-ahead: index g is marked as used before the signature exists */
  if (g >= key->reserved) {
    uint64_t v = g + 1 + key->autoreserve;
    if (v > key->total || v < g) {
      v = key->total;
    }
    rc = ctr_write(key, v);
    if (rc != XMSS_OK) {
      return rc;
    }
  }
  key->next = g + 1;

  bottom = &key->lv[key->levels - 1];
  if (bottom->upper == NULL) {
    return XMSS_ERR_INTERNAL;
  }
  q = (uint32_t)(g & ((1u << p->th) - 1));
  /* idx_sig || r || treeSig(layer 0) || treeSig(layer 1) || ... */
  s = sig;
  for (i = 0; i < p->idx_bytes; i++) {
    s[i] = (uint8_t)(g >> (8 * (p->idx_bytes - 1 - i)));
  }
  s += p->idx_bytes;
  xmss_prf_index(p, bottom->sk_prf, g, r);
  xmss_words_to_bytes(s, r, p->nw);
  s += p->n;
  xmss_hash_message(p, r, key->lv[0].root, g, msg, msglen, M);
  rc = level_tree_sig(key, bottom, q, M, s);
  if (rc != XMSS_OK) {
    xmss_zeroize(sig, xmss_sig_len(p));
    return rc;
  }
  s += xmss_tree_sig_len(p);
  for (i = key->levels - 1; i >= 1; i--) {
    memcpy(s, key->lv[i].sig, key->lv[i].siglen);
    s += key->lv[i].siglen;
  }
  *siglen = xmss_sig_len(p);
  next_advance(key, bottom, q);
  return XMSS_OK;
}

int xmss_key_reserve(xmss_key *key, uint64_t n)
{
  uint64_t v;
  if (key == NULL) {
    return XMSS_ERR_PARAM;
  }
  v = key->next + n;
  if (v > key->total || v < key->next) {
    v = key->total;
  }
  return v > key->reserved ? ctr_write(key, v) : XMSS_OK;
}

void xmss_key_set_autoreserve(xmss_key *key, uint32_t n)
{
  if (key != NULL) {
    key->autoreserve = n;
  }
}

/* ---- generate / load ---------------------------------------------------- */

static int hdr_write(xmss_key *key)
{
  uint8_t b[12 + XMSS_MAX_N];
  b[0] = HDR_MAGIC0;
  b[1] = HDR_MAGIC1;
  b[2] = HDR_MAGIC2;
  b[3] = HDR_MAGIC3;
  b[4] = REC_VERSION;
  b[5] = key->p->mt;
  b[6] = 0;
  b[7] = 0;
  xmss_put32(b + 8, key->p->oid);
  xmss_words_to_bytes(b + 12, key->seed, NW(key));
  return key->st.write(key->st.ctx, "hdr", b, 12 + key->p->n) == 0 ? XMSS_OK : XMSS_ERR_STORE;
}

int xmss_key_erase(const xmss_store *store)
{
  unsigned i;
  char name[6];
  int rc = 0;
  rc |= store->erase(store->ctx, "hdr"); /* first: never a half-erased key */
  rc |= store->erase(store->ctx, "ctr");
  for (i = 0; i < XMSS_MAX_D; i++) {
    rec_name(name, "lv", i);
    rc |= store->erase(store->ctx, name);
    rec_name(name, "ax", i);
    rc |= store->erase(store->ctx, name);
  }
  return rc == 0 ? XMSS_OK : XMSS_ERR_STORE;
}

int xmss_key_generate(xmss_key **out, const xmss_store *store, int mt, uint32_t oid)
{
  const xmss_param *p = param_of(mt, oid);
  xmss_key *key;
  xmss_level *top;
  uint8_t sb[XMSS_MAX_N];
  unsigned i;
  int rc;
  if (out == NULL || store == NULL) {
    return XMSS_ERR_PARAM;
  }
  *out = NULL;
  if (p == NULL || p->th > XMSS_ESP32_MAX_KEYGEN_HEIGHT) {
    return XMSS_ERR_PARAM;
  }
  key = key_alloc(store, p);
  if (key == NULL) {
    return XMSS_ERR_NOMEM;
  }
  rc = xmss_key_erase(store);
  if (rc == XMSS_OK) {
    rc = ctr_write(key, 0);
  }
  top = &key->lv[0];
  if (rc == XMSS_OK) {
    /* SEED (shared), and S_XMSS / SK_PRF of the top tree */
    if (xmss_randombytes(sb, p->n) != 0) {
      rc = XMSS_ERR_RNG;
    } else {
      xmss_bytes_to_words(key->seed, sb, p->nw);
    }
    if (rc == XMSS_OK && xmss_randombytes(sb, p->n) == 0) {
      xmss_bytes_to_words(top->tree.sk, sb, p->nw);
    } else {
      rc = XMSS_ERR_RNG;
    }
    if (rc == XMSS_OK && xmss_randombytes(sb, p->n) == 0) {
      xmss_bytes_to_words(top->sk_prf, sb, p->nw);
    } else {
      rc = XMSS_ERR_RNG;
    }
    xmss_zeroize(sb, sizeof sb);
  }
  if (rc == XMSS_OK) {
    level_tree_init(key, 0, 0);
    rc = tree_build(key, top, key->levels == 1);
  }
  if (rc == XMSS_OK) {
    top->ready = LV_READY;
    rc = lv_write(key, 0);
  }
  if (rc == XMSS_OK) {
    rc = ax_write(key, 0);
  }
  for (i = 1; rc == XMSS_OK && i < key->levels; i++) {
    rc = tree_create(key, i, 0);
  }
  if (rc == XMSS_OK) {
    rc = hdr_write(key);
  }
  if (rc != XMSS_OK) {
    xmss_key_free(key);
    return rc;
  }
  *out = key;
  return XMSS_OK;
}

int xmss_key_load(xmss_key **out, const xmss_store *store)
{
  uint8_t b[12 + XMSS_MAX_N];
  const xmss_param *p;
  size_t len = 0;
  unsigned i;
  xmss_key *key;
  int rc;
  if (out == NULL || store == NULL) {
    return XMSS_ERR_PARAM;
  }
  *out = NULL;
  rc = store->read(store->ctx, "hdr", b, sizeof b, &len);
  if (rc == 1) {
    return XMSS_ERR_NOKEY;
  }
  if (rc != 0) {
    return XMSS_ERR_STORE;
  }
  if (len < 12 || b[0] != HDR_MAGIC0 || b[1] != HDR_MAGIC1 || b[2] != HDR_MAGIC2 ||
      b[3] != HDR_MAGIC3 || b[4] != REC_VERSION || b[5] > 1) {
    return XMSS_ERR_STATE;
  }
  p = param_of(b[5], xmss_get32(b + 8));
  if (p == NULL || len != 12u + p->n || p->th > XMSS_ESP32_MAX_KEYGEN_HEIGHT) {
    return XMSS_ERR_STATE;
  }
  key = key_alloc(store, p);
  if (key == NULL) {
    return XMSS_ERR_NOMEM;
  }
  xmss_bytes_to_words(key->seed, b + 12, p->nw);
  rc = store->read(store->ctx, "ctr", b, 8, &len);
  if (rc != 0 || len != 8) {
    xmss_key_free(key);
    return rc < 0 ? XMSS_ERR_STORE : XMSS_ERR_STATE;
  }
  key->next = key->reserved = get64(b);
  if (key->next > key->total) {
    xmss_key_free(key);
    return XMSS_ERR_STATE;
  }
  for (i = 0; i < key->levels; i++) {
    rc = lv_read(key, i);
    if (rc != XMSS_OK) {
      xmss_key_free(key);
      return rc;
    }
    if ((i == 0 && (key->lv[0].t != 0 || !key->lv[0].ready || key->lv[0].siglen != 0)) ||
        (i > 0 && key->lv[i].ready && key->lv[i].siglen != xmss_tree_sig_len(p))) {
      xmss_key_free(key);
      return XMSS_ERR_STATE;
    }
  }
  rc = level_cache_ensure(key, 0);
  if (rc != XMSS_OK) {
    xmss_key_free(key);
    return rc;
  }
  if (key->next < key->total) {
    uint64_t g = key->next;
    rc = trees_select(key, &g);
    if (rc != XMSS_OK && rc != XMSS_ERR_EXHAUSTED) {
      xmss_key_free(key);
      return rc;
    }
  }
  *out = key;
  return XMSS_OK;
}

/* ---- accessors ---------------------------------------------------------- */

const xmss_param *xmss_key_param(const xmss_key *key)
{
  return key == NULL ? NULL : key->p;
}

size_t xmss_key_public_key_len(const xmss_key *key)
{
  return key == NULL ? 0 : xmss_pk_len(key->p);
}

int xmss_key_public_key(const xmss_key *key, uint8_t *pk, size_t *pklen)
{
  if (key == NULL || pklen == NULL) {
    return XMSS_ERR_PARAM;
  }
  if (*pklen < xmss_pk_len(key->p)) {
    return XMSS_ERR_BUFFER;
  }
  xmss_put32(pk, key->p->oid);
  xmss_words_to_bytes(pk + 4, key->lv[0].root, NW(key));
  xmss_words_to_bytes(pk + 4 + key->p->n, key->seed, NW(key));
  *pklen = xmss_pk_len(key->p);
  return XMSS_OK;
}

size_t xmss_key_signature_len(const xmss_key *key)
{
  return key == NULL ? 0 : xmss_sig_len(key->p);
}

int xmss_key_is_mt(const xmss_key *key)
{
  return key != NULL && key->p->mt;
}

uint64_t xmss_key_total(const xmss_key *key)
{
  return key == NULL ? 0 : key->total;
}

uint64_t xmss_key_next_index(const xmss_key *key)
{
  return key == NULL ? 0 : key->next;
}

uint64_t xmss_key_remaining(const xmss_key *key)
{
  return key == NULL ? 0 : key->total - key->next;
}

size_t xmss_key_cache_size(const xmss_key *key)
{
  size_t sz = 0;
  unsigned i;
  if (key == NULL) {
    return 0;
  }
  for (i = 0; i < key->levels; i++) {
    const xmss_level *lv = &key->lv[i];
    const unsigned h = TH(key), k = subtree_height(h);
    const size_t node = 4u * NW(key);
    if (lv->upper != NULL) {
      sz += (((size_t)1 << (h - k + 1)) + ((size_t)1 << (k + 1))) * node;
    }
    if (lv->next != NULL) {
      sz += ((size_t)1 << k) * node;
    }
  }
  return sz;
}
