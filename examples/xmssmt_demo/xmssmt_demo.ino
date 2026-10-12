/*
 * XMSS^MT demo: multi-tree XMSS as in NIST SP 800-208 Section 7.2
 *
 * XMSS^MT stacks XMSS trees in d layers: the top tree signs the roots of
 * the trees below it, the bottom trees sign messages. XMSSMT-SHA2_20/4_256
 * has 4 layers of height 5: 2^20 signatures, while only 4 x 32 one-time
 * keys are computed at key generation. Following SP 800-208 Algorithm 10',
 * every tree gets its own random S_XMSS and SK_PRF (all share SEED), and
 * the root of each lower tree is signed exactly once; a new bottom tree is
 * generated whenever the current one is used up -- visible as a slower
 * signature every 32 messages.
 *
 * The demo signs a 64 KB "firmware image", prints the structure of an
 * XMSS^MT signature and checks that a modified image is rejected.
 *
 * The state is kept in RAM here (XMSSRamStorage); see xmss_nvs_storage for
 * persistent keys.
 *
 * Copyright (c) 2026 The sp800-208-xmss-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <Arduino.h>
#include <XMSS.h>

static const uint32_t OID = XMSSMT_SHA2_20_4_256;

static XMSSRamStorage storage;
static XMSSMTKey key;
static uint8_t pk[68];
static size_t pkLen = sizeof pk;
static uint8_t sig[10 * 1024];
static uint8_t *image;
static const size_t IMAGE_SIZE = 64 * 1024;

static void describeSignature(const xmss_param *p, const uint8_t *s, size_t len) {
  uint64_t idx = 0;
  for (unsigned i = 0; i < p->idx_bytes; i++) idx = (idx << 8) | s[i];
  Serial.printf("%s signature, %u bytes:\n", p->name, (unsigned)len);
  Serial.printf("  idx_sig %llu (%u bytes), r (%u bytes)\n", (unsigned long long)idx,
                p->idx_bytes, p->n);
  for (unsigned j = 0; j < p->d; j++) {
    const uint32_t leaf = (uint32_t)(idx & ((1u << p->th) - 1));
    idx >>= p->th;
    Serial.printf("  layer %u treeSig: tree %llu, leaf %2u: WOTS+ %u bytes + auth path %u bytes "
                  "(signs %s)\n",
                  j, (unsigned long long)idx, (unsigned)leaf, (unsigned)(p->len * p->n),
                  (unsigned)(p->th * p->n), j == 0 ? "the message" : "the root of layer below");
  }
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("\n=== XMSS^MT demo ===");
  image = (uint8_t *)malloc(IMAGE_SIZE);
  if (image == nullptr) return;
  for (size_t i = 0; i < IMAGE_SIZE; i++) image[i] = (uint8_t)(i * 7 + (i >> 9));

  unsigned long t0 = millis();
  int rc = key.generate(storage, OID);
  if (rc != XMSS_OK) {
    Serial.printf("Keygen failed: %s\n", XMSSKeyBase::errorString(rc));
    return;
  }
  key.publicKey(pk, &pkLen);
  Serial.printf("%s key generated in %lu ms: %llu signatures, public key %u bytes, "
                "signature %u bytes, tree caches %u bytes RAM\n",
                key.name(), millis() - t0, (unsigned long long)key.totalSignatures(),
                (unsigned)pkLen, (unsigned)key.signatureSize(), (unsigned)key.cacheSize());

  size_t sigLen = sizeof sig;
  key.sign(image, IMAGE_SIZE, sig, &sigLen);
  describeSignature(key.params(), sig, sigLen);
  t0 = millis();
  bool ok = XMSSMTKey::verify(pk, pkLen, image, IMAGE_SIZE, sig, sigLen) == 0;
  Serial.printf("Firmware image (64 KB) signature: %s (verify %lu ms)\n", ok ? "VALID" : "INVALID",
                millis() - t0);
  image[12345] ^= 1;
  ok = XMSSMTKey::verify(pk, pkLen, image, IMAGE_SIZE, sig, sigLen) == 0;
  Serial.printf("Modified image: %s\n", ok ? "ACCEPTED (error!)" : "rejected");
  image[12345] ^= 1;
  Serial.println("\nSigning 70 more messages (a new bottom tree every 32):");
}

void loop() {
  static int n = 0;
  if (!key.loaded() || n >= 70) {
    delay(1000);
    return;
  }
  char msg[32];
  snprintf(msg, sizeof msg, "message %d", n);
  size_t sigLen = sizeof sig;
  unsigned long t0 = micros();
  int rc = key.sign((const uint8_t *)msg, strlen(msg), sig, &sigLen);
  unsigned long us = micros() - t0;
  bool ok = rc == XMSS_OK &&
            XMSSMTKey::verify(pk, pkLen, (const uint8_t *)msg, strlen(msg), sig, sigLen) == 0;
  const uint64_t g = key.nextIndex() - 1;
  if (n % 8 == 0 || g % 32 == 0) {
    Serial.printf("  #%-3d index %4llu (bottom tree %llu, leaf %2llu): %8.2f ms %s%s\n", n,
                  (unsigned long long)g, (unsigned long long)(g / 32), (unsigned long long)(g % 32),
                  us / 1000.0, ok ? "valid" : "INVALID",
                  g % 32 == 0 ? "  <- new bottom tree generated" : "");
  }
  n++;
  if (n == 70) Serial.println("XMSS^MT demo complete.");
}
