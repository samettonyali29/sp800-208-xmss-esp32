/*
 * Simple XMSS^MT example (stateful hash-based signatures, RFC 8391 /
 * NIST SP 800-208)
 *
 * Generates an XMSSMT-SHA2_20/4_256 key (4 layers of trees of height 5:
 * 2^20 signatures, only 4 x 32 one-time keys computed at key generation),
 * signs a few messages and verifies them.
 *
 * XMSS is *stateful*: every signature consumes one of the one-time keys and
 * the private key state must be saved before each signature is released.
 * This example keeps the state in RAM (XMSSRamStorage), which is only
 * acceptable for a demonstration: after a reset the key is gone. See
 * xmss_nvs_storage for a key that survives resets.
 *
 * Copyright (c) 2026 The sp800-208-xmss-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <Arduino.h>
#include <XMSS.h>

static uint8_t sig[10 * 1024];

void setup() {
  Serial.begin(115200);
  delay(1000);

  XMSSRamStorage storage;  // volatile: demonstration only
  XMSSMTKey key;

  unsigned long start = millis();
  int rc = key.generate(storage, XMSSMT_SHA2_20_4_256);
  if (rc != XMSS_OK) {
    Serial.printf("Keygen failed: %s\n", XMSSKeyBase::errorString(rc));
    return;
  }
  Serial.printf("%s key generated in %lu ms: %llu signatures available\n", key.name(),
                millis() - start, (unsigned long long)key.remaining());

  uint8_t pk[68];
  size_t pkLen = sizeof pk;
  key.publicKey(pk, &pkLen);
  Serial.printf("Public key: %u bytes, signature: %u bytes\n", (unsigned)pkLen,
                (unsigned)key.signatureSize());

  for (int i = 0; i < 3; i++) {
    char msg[40];
    snprintf(msg, sizeof msg, "Hello, post-quantum world #%d", i);
    size_t sigLen = sizeof sig;
    start = millis();
    rc = key.sign((const uint8_t *)msg, strlen(msg), sig, &sigLen);
    if (rc != XMSS_OK) {
      Serial.printf("Signing failed: %s\n", XMSSKeyBase::errorString(rc));
      return;
    }
    unsigned long tSign = millis() - start;
    start = millis();
    bool ok = XMSSMTKey::verify(pk, pkLen, (const uint8_t *)msg, strlen(msg), sig, sigLen) == 0;
    Serial.printf("\"%s\": index %llu, signed in %lu ms, verify %s (%lu ms), %llu left\n", msg,
                  (unsigned long long)(key.nextIndex() - 1), tSign, ok ? "OK" : "FAILED",
                  millis() - start, (unsigned long long)key.remaining());
  }
}

void loop() {
  delay(1000);
}
