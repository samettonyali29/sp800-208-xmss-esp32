/*
 * XMSS.h - XMSS and XMSS^MT stateful hash-based signatures for ESP32
 *          (RFC 8391, NIST SP 800-208)
 *
 *   #include <XMSS.h>
 *   #include <XMSS_NVS.h>
 *
 *   XMSSNvsStorage storage;             // private key state in NVS
 *   storage.begin("xmss");              // NVS namespace
 *   XMSSMTKey key;                      // XMSS^MT: 2^20 signatures
 *   if (key.load(storage) != XMSS_OK)
 *     key.generate(storage, XMSSMT_SHA2_20_4_256);
 *   key.sign(msg, msgLen, sig, &sigLen);    // state saved before signing
 *   XMSSMTKey::verify(pk, pkLen, msg, msgLen, sig, sigLen);  // 0 = valid
 *
 *   XMSSKey single;                     // XMSS: one tree, 2^10..2^20
 *   single.generate(storage, XMSS_SHA2_10_256);
 *
 * Read the "Stateful signatures" section of the README before using this in
 * a product: a private key must never be copied, restored from a backup or
 * used from two places, or one-time keys get reused.
 *
 * Copyright (c) 2026 The sp800-208-xmss-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef XMSS_H
#define XMSS_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "xmss_esp32.h"
#include "xmss_hash.h"

/* Storage for the private key state (see XMSS_NVS.h for the NVS one). */
class XMSSStorage {
public:
  virtual ~XMSSStorage() {}
  /* 0 = ok, 1 = no such record, < 0 = error (also if cap is too small) */
  virtual int read(const char *name, uint8_t *buf, size_t cap, size_t *len) = 0;
  /* 0 = written and durable */
  virtual int write(const char *name, const uint8_t *buf, size_t len) = 0;
  /* 0 = removed or not present */
  virtual int erase(const char *name) = 0;

  xmss_store cStore() {
    xmss_store s = {readCb, writeCb, eraseCb, this};
    return s;
  }

private:
  static int readCb(void *c, const char *n, uint8_t *b, size_t cap, size_t *len) {
    return static_cast<XMSSStorage *>(c)->read(n, b, cap, len);
  }
  static int writeCb(void *c, const char *n, const uint8_t *b, size_t len) {
    return static_cast<XMSSStorage *>(c)->write(n, b, len);
  }
  static int eraseCb(void *c, const char *n) {
    return static_cast<XMSSStorage *>(c)->erase(n);
  }
};

class XMSSKeyBase {
public:
  ~XMSSKeyBase() { end(); }

  /* Signs msg. *sigLen: in = capacity of sig, out = signature length.
   * The private key state is written to the storage before the signature
   * is computed. Returns XMSS_OK or an XMSS_ERR_* code. */
  int sign(const uint8_t *msg, size_t msgLen, uint8_t *sig, size_t *sigLen) {
    return key_ ? xmss_key_sign(key_, msg, msgLen, sig, sigLen) : XMSS_ERR_NOKEY;
  }

  /* Copies the public key (OID || root || SEED); *pkLen: in = capacity. */
  int publicKey(uint8_t *pk, size_t *pkLen) const {
    return key_ ? xmss_key_public_key(key_, pk, pkLen) : XMSS_ERR_NOKEY;
  }

  int reserve(uint64_t n) { return key_ ? xmss_key_reserve(key_, n) : XMSS_ERR_NOKEY; }
  void setAutoReserve(uint32_t n) { xmss_key_set_autoreserve(key_, n); }

  bool loaded() const { return key_ != nullptr; }
  const xmss_param *params() const { return xmss_key_param(key_); }
  const char *name() const { return key_ ? xmss_key_param(key_)->name : ""; }
  uint32_t oid() const { return key_ ? xmss_key_param(key_)->oid : 0; }
  size_t publicKeySize() const { return xmss_key_public_key_len(key_); }
  size_t signatureSize() const { return xmss_key_signature_len(key_); }
  uint64_t totalSignatures() const { return xmss_key_total(key_); }
  uint64_t nextIndex() const { return xmss_key_next_index(key_); }
  uint64_t remaining() const { return xmss_key_remaining(key_); }
  size_t cacheSize() const { return xmss_key_cache_size(key_); }

  /* Frees the key from RAM (the stored state is kept). */
  void end() {
    xmss_key_free(key_);
    key_ = nullptr;
  }

  /* Removes the key from the storage. */
  static int erase(XMSSStorage &storage) {
    xmss_store s = storage.cStore();
    return xmss_key_erase(&s);
  }

  static const char *errorString(int rc) {
    switch (rc) {
      case XMSS_OK: return "ok";
      case XMSS_ERR_PARAM: return "unsupported parameters";
      case XMSS_ERR_NOMEM: return "out of memory";
      case XMSS_ERR_STORE: return "storage error";
      case XMSS_ERR_EXHAUSTED: return "key exhausted";
      case XMSS_ERR_RNG: return "RNG failure";
      case XMSS_ERR_STATE: return "inconsistent key state";
      case XMSS_ERR_BUFFER: return "buffer too small";
      case XMSS_ERR_NOKEY: return "no key";
      case XMSS_ERR_INTERNAL: return "internal error";
      default: return "error";
    }
  }

protected:
  XMSSKeyBase() : store_(), key_(nullptr) {}
  XMSSKeyBase(const XMSSKeyBase &) = delete;
  XMSSKeyBase &operator=(const XMSSKeyBase &) = delete;

  int doGenerate(XMSSStorage &storage, int mt, uint32_t oid) {
    end();
    store_ = storage.cStore();
    return xmss_key_generate(&key_, &store_, mt, oid);
  }

  int doLoad(XMSSStorage &storage, int mt) {
    end();
    store_ = storage.cStore();
    int rc = xmss_key_load(&key_, &store_);
    if (rc == XMSS_OK && xmss_key_is_mt(key_) != mt) {
      end();
      rc = XMSS_ERR_PARAM; /* stored key is of the other kind */
    }
    return rc;
  }

  xmss_store store_;
  xmss_key *key_;
};

/* XMSS: a single tree (OIDs XMSS_SHA2_10_256 ... XMSS_SHAKE256_20_192). */
class XMSSKey : public XMSSKeyBase {
public:
  int generate(XMSSStorage &storage, uint32_t oid) { return doGenerate(storage, 0, oid); }
  int load(XMSSStorage &storage) { return doLoad(storage, 0); }

  /* 0 = valid */
  static int verify(const uint8_t *pk, size_t pkLen, const uint8_t *msg, size_t msgLen,
                    const uint8_t *sig, size_t sigLen) {
    return xmss_verify(pk, pkLen, msg, msgLen, sig, sigLen);
  }
  static size_t publicKeySize(uint32_t oid) {
    const xmss_param *p = xmss_param_get(oid);
    return p ? xmss_pk_len(p) : 0;
  }
  static size_t signatureSize(uint32_t oid) {
    const xmss_param *p = xmss_param_get(oid);
    return p ? xmss_sig_len(p) : 0;
  }
  using XMSSKeyBase::publicKeySize;
  using XMSSKeyBase::signatureSize;
};

/* XMSS^MT: d layers of trees (OIDs XMSSMT_SHA2_20_2_256 ...). */
class XMSSMTKey : public XMSSKeyBase {
public:
  int generate(XMSSStorage &storage, uint32_t oid) { return doGenerate(storage, 1, oid); }
  int load(XMSSStorage &storage) { return doLoad(storage, 1); }

  static int verify(const uint8_t *pk, size_t pkLen, const uint8_t *msg, size_t msgLen,
                    const uint8_t *sig, size_t sigLen) {
    return xmssmt_verify(pk, pkLen, msg, msgLen, sig, sigLen);
  }
  static size_t publicKeySize(uint32_t oid) {
    const xmss_param *p = xmssmt_param_get(oid);
    return p ? xmss_pk_len(p) : 0;
  }
  static size_t signatureSize(uint32_t oid) {
    const xmss_param *p = xmssmt_param_get(oid);
    return p ? xmss_sig_len(p) : 0;
  }
  using XMSSKeyBase::publicKeySize;
  using XMSSKeyBase::signatureSize;
};

/* RAM-only storage: the state is lost on reset. For tests and benchmarks
 * only -- a key in RAM storage must never be used after a reset. */
class XMSSRamStorage : public XMSSStorage {
public:
  ~XMSSRamStorage() { clear(); }
  int read(const char *name, uint8_t *buf, size_t cap, size_t *len) override {
    Rec *r = find(name);
    if (r == nullptr) return 1;
    if (r->len > cap) return -2;
    memcpy(buf, r->data, r->len);
    *len = r->len;
    return 0;
  }
  int write(const char *name, const uint8_t *buf, size_t len) override {
    Rec *r = find(name);
    if (r == nullptr) {
      if (count_ == MAX_RECS) return -1;
      r = &recs_[count_++];
      strncpy(r->name, name, sizeof(r->name) - 1);
      r->name[sizeof(r->name) - 1] = 0;
      r->data = nullptr;
      r->len = 0;
    }
    uint8_t *d = (uint8_t *)malloc(len ? len : 1);
    if (d == nullptr) return -1;
    memcpy(d, buf, len);
    wipeFree(r);
    r->data = d;
    r->len = len;
    return 0;
  }
  int erase(const char *name) override {
    Rec *r = find(name);
    if (r != nullptr) {
      wipeFree(r);
      *r = recs_[--count_];
    }
    return 0;
  }
  void clear() {
    for (unsigned i = 0; i < count_; i++) wipeFree(&recs_[i]);
    count_ = 0;
  }

private:
  struct Rec {
    char name[8];
    uint8_t *data;
    size_t len;
  };
  static const unsigned MAX_RECS = 2 * XMSS_MAX_D + 2;
  Rec recs_[MAX_RECS];
  unsigned count_ = 0;
  Rec *find(const char *name) {
    for (unsigned i = 0; i < count_; i++)
      if (strcmp(recs_[i].name, name) == 0) return &recs_[i];
    return nullptr;
  }
  static void wipeFree(Rec *r) {
    if (r->data) {
      xmss_zeroize(r->data, r->len);
      free(r->data);
      r->data = nullptr;
    }
  }
};

#endif /* XMSS_H */
