/*
 * kat_runner.h - runs the XMSS / XMSS^MT known-answer tests of
 * xmss_vectors.h
 *
 * Shared by the xmss_test_vectors sketch and the host tests. The includer
 * defines KAT_PRINTF(fmt, ...) before including this file, and
 * KAT_FULL_REGEN to also regenerate whole XMSS trees (1024 leaves each:
 * minutes on an ESP32, used by the host tests).
 *
 * Copyright (c) 2026 The sp800-208-xmss-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once
#include <stdlib.h>
#include <string.h>
#include "xmss_core.h"
#include "xmss_vectors.h"

typedef struct {
  unsigned pass, fail;
} kat_result;

static void kat_check(kat_result *r, int ok, const char *what, const char *name)
{
  if (ok) {
    r->pass++;
  } else {
    r->fail++;
    KAT_PRINTF("  [FAIL] %s: %s\n", name, what);
  }
}

static void kat_verify_case(kat_result *r, const xmss_tv *tv)
{
  int (*vf)(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t) =
      tv->mt ? xmssmt_verify : xmss_verify;
  uint8_t *s2 = (uint8_t *)malloc(tv->siglen), *m2 = (uint8_t *)malloc(tv->msglen + 1);
  kat_check(r, vf(tv->pk, tv->pklen, tv->msg, tv->msglen, tv->sig, tv->siglen) == 0,
            "valid signature rejected", tv->name);
  if (s2 == NULL || m2 == NULL) {
    free(s2);
    free(m2);
    kat_check(r, 0, "out of memory", tv->name);
    return;
  }
  memcpy(s2, tv->sig, tv->siglen);
  s2[(tv->siglen * 5) / 9] ^= 0x08;
  kat_check(r, vf(tv->pk, tv->pklen, tv->msg, tv->msglen, s2, tv->siglen) != 0,
            "tampered signature accepted", tv->name);
  memcpy(m2, tv->msg, tv->msglen);
  m2[tv->msglen] = 0x5a;
  kat_check(r, vf(tv->pk, tv->pklen, m2, tv->msglen + 1, tv->sig, tv->siglen) != 0,
            "changed message accepted", tv->name);
  kat_check(r, vf(tv->pk, tv->pklen, tv->msg, tv->msglen, tv->sig, tv->siglen - 1) != 0,
            "truncated signature accepted", tv->name);
  free(s2);
  free(m2);
}

/* XMSS: regenerate r and the WOTS+ signature (and, with KAT_FULL_REGEN, the
 * public key and the whole signature) from the seeds */
static void kat_regen_case(kat_result *r, const xmss_tv *tv)
{
  const xmss_param *p = xmss_param_get(tv->oid);
  const uint8_t *sk_seed = tv->seeds, *sk_prf = tv->seeds + p->n, *seed = tv->seeds + 2 * p->n;
  uint32_t s[XMSS_MAX_NW], k[XMSS_MAX_NW], prf[XMSS_MAX_NW], root[XMSS_MAX_NW];
  uint32_t rr[XMSS_MAX_NW], M[XMSS_MAX_NW];
  uint8_t rb[XMSS_MAX_N];
  const uint32_t idx = xmss_get32(tv->sig);
  uint8_t *wots = (uint8_t *)malloc((size_t)p->len * p->n);
  xmss_tree t;
  if (wots == NULL) {
    kat_check(r, 0, "out of memory", tv->name);
    return;
  }
  xmss_bytes_to_words(s, seed, p->nw);
  xmss_bytes_to_words(k, sk_seed, p->nw);
  xmss_bytes_to_words(prf, sk_prf, p->nw);
  xmss_bytes_to_words(root, tv->pk + 4, p->nw);
  xmss_prf_index(p, prf, idx, rr);
  xmss_words_to_bytes(rb, rr, p->nw);
  kat_check(r, memcmp(rb, tv->sig + 4, p->n) == 0, "randomizer r differs", tv->name);
  xmss_hash_message(p, rr, root, idx, tv->msg, tv->msglen, M);
  xmss_tree_init(&t, p, s, k, 0, 0);
  xmss_wots_sign(&t, idx, M, wots);
  kat_check(r, memcmp(wots, tv->sig + 4 + p->n, (size_t)p->len * p->n) == 0,
            "WOTS+ signature differs", tv->name);
  xmss_tree_wipe(&t);
  free(wots);
#if defined(KAT_FULL_REGEN)
  {
    uint8_t pk[4 + 2 * XMSS_MAX_N];
    uint8_t *sig = (uint8_t *)malloc(tv->siglen);
    xmss_keygen_internal(p, sk_seed, seed, pk);
    kat_check(r, memcmp(pk, tv->pk, tv->pklen) == 0, "public key differs", tv->name);
    if (sig != NULL) {
      xmss_sign_internal(p, sk_seed, sk_prf, seed, tv->pk + 4, idx, tv->msg, tv->msglen, sig);
      kat_check(r, memcmp(sig, tv->sig, tv->siglen) == 0, "signature differs", tv->name);
      free(sig);
    }
  }
#endif
}

static unsigned kat_run_all(kat_result *r)
{
  size_t i;
  memset(r, 0, sizeof *r);
  for (i = 0; i < XMSS_TV_COUNT; i++) {
    const xmss_tv *tv = &XMSS_TV[i];
    const unsigned before = r->fail;
    kat_verify_case(r, tv);
    if (!tv->mt) {
      kat_regen_case(r, tv);
    }
    const xmss_param *p = tv->mt ? xmssmt_param_get(tv->oid) : xmss_param_get(tv->oid);
    uint64_t idx = 0;
    unsigned b;
    for (b = 0; p != NULL && b < p->idx_bytes; b++) {
      idx = (idx << 8) | tv->sig[b];
    }
    KAT_PRINTF("%-28s idx %-3u %s%s\n", tv->name, (unsigned)idx,
               tv->mt ? "verified" : "verified, r + WOTS+ regenerated",
               r->fail == before ? "" : "  <-- FAILED");
  }
  return r->fail;
}
