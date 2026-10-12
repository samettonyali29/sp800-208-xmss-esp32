/*
 * xmss_esp32.h - stateful XMSS / XMSS^MT private keys for ESP32
 *
 * XMSS and XMSS^MT are *stateful* signature schemes: every signature uses a
 * one-time (WOTS+) key, and signing two different messages with the same
 * one-time key lets an attacker forge signatures. This module owns the
 * private key state and follows NIST SP 800-208 Sections 6.2, 7.2 and 8.1:
 *
 *   - the signature index is advanced and written to non-volatile storage
 *     *before* a signature is computed (write-ahead); if the write fails,
 *     no signature is produced;
 *   - a key whose state cannot be read consistently is refused, it is
 *     never "repaired" by reusing indices;
 *   - XMSS^MT is implemented as in SP 800-208 Section 7.2 (Algorithms 10'
 *     and 12'): every XMSS tree has its own random S_XMSS and SK_PRF, all
 *     share SEED, and the root of every lower tree is signed exactly once
 *     by its parent; that signature is stored. A lower tree whose creation
 *     was interrupted is abandoned, the parent's one-time key is never used
 *     a second time;
 *   - the WOTS+ private keys are derived with PRF_keygen(S_XMSS, SEED ||
 *     ADRS) (SP 800-208 Algorithm 10'), all seeds come from the RNG.
 *
 * Storage is abstracted by xmss_store (a small key-value interface); the
 * Arduino wrapper provides an NVS implementation (XMSS_NVS.h). The storage
 * write must be durable when it returns 0.
 *
 * Copyright (c) 2026 The sp800-208-xmss-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef XMSS_ESP32_H
#define XMSS_ESP32_H

#include <stddef.h>
#include <stdint.h>
#include "xmss_core.h"
#include "xmss_esp32_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* error codes */
#define XMSS_OK 0
#define XMSS_ERR_PARAM -1     /* unsupported parameters */
#define XMSS_ERR_NOMEM -2     /* out of memory */
#define XMSS_ERR_STORE -3     /* storage read / write failed */
#define XMSS_ERR_EXHAUSTED -4 /* all one-time keys used */
#define XMSS_ERR_RNG -5       /* random number generator failed */
#define XMSS_ERR_STATE -6     /* stored state inconsistent (key refused) */
#define XMSS_ERR_BUFFER -7    /* output buffer too small */
#define XMSS_ERR_NOKEY -8     /* no key in the storage */
#define XMSS_ERR_INTERNAL -9  /* self-check failed */

/* Key-value storage for the private key state (see sp800-208-lms-esp32's lms_store;
 * same contract). Names are at most 7 characters. */
typedef struct {
  int (*read)(void *ctx, const char *name, uint8_t *buf, size_t cap, size_t *len);
  int (*write)(void *ctx, const char *name, const uint8_t *buf, size_t len);
  int (*erase)(void *ctx, const char *name);
  void *ctx;
} xmss_store;

typedef struct xmss_key xmss_key;

/* Generates a new key and writes its state to the storage (replacing any
 * key stored there). mt = 0: XMSS OID (xmss_param_get), mt = 1: XMSS^MT OID
 * (xmssmt_param_get). The tree height (h / d) must be at most
 * XMSS_ESP32_MAX_KEYGEN_HEIGHT. */
int xmss_key_generate(xmss_key **key, const xmss_store *store, int mt, uint32_t oid);

/* Loads a key from the storage. */
int xmss_key_load(xmss_key **key, const xmss_store *store);

/* Signs msg; the state is updated in the storage before the signature is
 * computed. *siglen: in = capacity of sig, out = signature length. */
int xmss_key_sign(xmss_key *key, const uint8_t *msg, size_t msglen, uint8_t *sig,
                  size_t *siglen);

/* Reserve n signatures now / automatically (see sp800-208-lms-esp32: reserved
 * indices not used before a reload are lost, never reused). */
int xmss_key_reserve(xmss_key *key, uint64_t n);
void xmss_key_set_autoreserve(xmss_key *key, uint32_t n);

int xmss_key_public_key(const xmss_key *key, uint8_t *pk, size_t *pklen);
const xmss_param *xmss_key_param(const xmss_key *key);
size_t xmss_key_public_key_len(const xmss_key *key);
size_t xmss_key_signature_len(const xmss_key *key);
int xmss_key_is_mt(const xmss_key *key);
uint64_t xmss_key_total(const xmss_key *key);      /* 2^h */
uint64_t xmss_key_next_index(const xmss_key *key);
uint64_t xmss_key_remaining(const xmss_key *key);
size_t xmss_key_cache_size(const xmss_key *key);   /* RAM of the tree caches */

void xmss_key_free(xmss_key *key);
int xmss_key_erase(const xmss_store *store);

/* 1 if the SHA hardware accelerator is in use (XMSS_ESP32_HW_SHA enabled
 * and self-test passed) */
int xmss_hw_sha_active(void);
/* Runtime switch for comparisons (default on, no effect without
 * XMSS_ESP32_HW_SHA): 0 = compute new operations in software. */
void xmss_hw_sha_set_enabled(int on);

/* Platform layer (xmss_esp32_platform.c on ESP32): 0 on success. */
int xmss_randombytes(uint8_t *out, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* XMSS_ESP32_H */
