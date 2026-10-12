/*
 * XMSS key with persistent state in NVS
 *
 * First boot:  generates an XMSS key (XMSS-SHA2_10_256: 1024 signatures,
 *              ~1.5 min in software, ~15 s with XMSS_ESP32_HW_SHA) and
 *              stores it in NVS.
 * Next boots:  loads the key (the tree cache is stored too, so this takes
 *              milliseconds) and continues with the next unused one-time key.
 *
 * Every 5 seconds a message is signed and verified; the one-time key index
 * keeps increasing across resets and power cycles -- press the reset
 * button and watch. The index is written to NVS *before* each signature is
 * computed, so even a reset in the middle of signing never leads to a
 * one-time key being used twice (an index may be skipped instead).
 *
 * Serial commands: 'r' reserve 10 signatures (fewer flash writes),
 *                  'e' erase the key and restart.
 *
 * Copyright (c) 2026 The sp800-208-xmss-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <Arduino.h>
#include <XMSS.h>
#include <XMSS_NVS.h>

static XMSSNvsStorage storage;
static XMSSKey key;
static uint8_t pk[68];
static size_t pkLen = sizeof pk;
static uint8_t sig[2600];

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("\n=== XMSS with NVS state storage ===");
  if (!storage.begin("xmss")) {
    Serial.println("NVS open failed");
    return;
  }
  unsigned long start = millis();
  int rc = key.load(storage);
  if (rc == XMSS_OK) {
    Serial.printf("Key loaded in %lu ms: next one-time key %llu, %llu signatures left\n",
                  millis() - start, (unsigned long long)key.nextIndex(),
                  (unsigned long long)key.remaining());
  } else {
    Serial.printf("No usable key in NVS (%s), generating one...\n", XMSSKeyBase::errorString(rc));
    rc = key.generate(storage, XMSS_SHA2_10_256);
    if (rc != XMSS_OK) {
      Serial.printf("Keygen failed: %s\n", XMSSKeyBase::errorString(rc));
      return;
    }
    Serial.printf("Key generated and stored in %lu ms\n", millis() - start);
  }
  key.publicKey(pk, &pkLen);
  Serial.print("Public key: ");
  for (size_t i = 0; i < pkLen; i++) Serial.printf("%02x", pk[i]);
  Serial.println();
}

void loop() {
  static unsigned long last = 0;
  if (Serial.available()) {
    char c = Serial.read();
    if (c == 'e') {
      XMSSKeyBase::erase(storage);
      Serial.println("Key erased, restarting...");
      delay(100);
      ESP.restart();
    } else if (c == 'r') {
      int rc = key.reserve(10);
      Serial.printf("Reserved 10 signatures: %s\n", XMSSKeyBase::errorString(rc));
    }
  }
  if (!key.loaded() || millis() - last < 5000) {
    delay(10);
    return;
  }
  last = millis();
  char msg[48];
  snprintf(msg, sizeof msg, "uptime %lu ms", millis());
  size_t sigLen = sizeof sig;
  unsigned long t0 = millis();
  int rc = key.sign((const uint8_t *)msg, strlen(msg), sig, &sigLen);
  unsigned long tSign = millis() - t0;
  if (rc != XMSS_OK) {
    Serial.printf("Signing failed: %s\n", XMSSKeyBase::errorString(rc));
    return;
  }
  bool ok = XMSSKey::verify(pk, pkLen, (const uint8_t *)msg, strlen(msg), sig, sigLen) == 0;
  Serial.printf("idx=%4u  \"%s\"  sign %lu ms (incl. NVS write)  verify %s  left %llu\n",
                (unsigned)xmss_get32(sig), msg, tSign, ok ? "OK" : "FAILED",
                (unsigned long long)key.remaining());
}
