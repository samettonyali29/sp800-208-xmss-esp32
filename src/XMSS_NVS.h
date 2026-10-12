/*
 * XMSS_NVS.h - NVS (Non-Volatile Storage) storage for XMSS / XMSS^MT keys
 *
 *   XMSSNvsStorage storage;
 *   storage.begin("xmss");      // NVS namespace (max 15 chars), one key each
 *   key.generate(storage, ...) / key.load(storage)
 *
 * Every state update is committed (nvs_commit) before write() returns, and
 * NVS replaces an entry atomically (a power loss leaves the old or the new
 * value), which is what the write-ahead state update of xmss_key_sign needs.
 *
 * Space: ~0.2 KB for the key records, plus the tree caches (2 KB per
 * height-10 tree with n = 32) and, for XMSS^MT, one stored treeSig per lower
 * layer ((67 + h/d) * 32 bytes, e.g. 2.3 KB for XMSSMT-SHA2_20/4_256). The
 * default NVS partition is 20 KB (shared with Wi-Fi calibration data etc.):
 * parameter sets with many layers (40/8, 60/6, 60/12) need a larger NVS
 * partition.
 *
 * Security: NVS is unencrypted unless NVS / flash encryption is enabled, so
 * the private seeds can be read by anyone with physical access. Never copy
 * or restore an NVS image containing a key: an older state means reused
 * one-time keys.
 *
 * Copyright (c) 2026 The sp800-208-xmss-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef XMSS_NVS_H
#define XMSS_NVS_H

#include <Preferences.h>
#include "XMSS.h"

class XMSSNvsStorage : public XMSSStorage {
public:
  ~XMSSNvsStorage() { end(); }

  bool begin(const char *ns) {
    end();
    open_ = prefs_.begin(ns, false);
    return open_;
  }
  void end() {
    if (open_) {
      prefs_.end();
      open_ = false;
    }
  }

  int read(const char *name, uint8_t *buf, size_t cap, size_t *len) override {
    if (!open_) return -1;
    if (!prefs_.isKey(name)) return 1;
    const size_t n = prefs_.getBytesLength(name);
    if (n > cap) return -2;
    if (prefs_.getBytes(name, buf, n) != n) return -1;
    *len = n;
    return 0;
  }
  int write(const char *name, const uint8_t *buf, size_t len) override {
    if (!open_) return -1;
    return prefs_.putBytes(name, buf, len) == len ? 0 : -1;
  }
  int erase(const char *name) override {
    if (!open_) return -1;
    if (!prefs_.isKey(name)) return 0;
    return prefs_.remove(name) ? 0 : -1;
  }

private:
  Preferences prefs_;
  bool open_ = false;
};

#endif /* XMSS_NVS_H */
