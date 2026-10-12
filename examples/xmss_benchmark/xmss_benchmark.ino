/*
 * XMSS / XMSS^MT benchmark
 *
 * Measures key generation, signing and verification for a selection of
 * parameter sets (RAM storage, so flash write times are not included; an
 * NVS state update adds a few ms per signature, see README), plus the speed
 * of the hash primitives. Results also as CSV lines.
 *
 * Build flags: -DBENCH_SETS=mask (bits below, default 0x33: the four
 *              SHA-256 sets with the shortest key generation),
 *              -DBENCH_SIGS=n (signatures per set: min(n, 2^(h/d)),
 *              default 256)
 *
 * Copyright (c) 2026 The sp800-208-xmss-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <Arduino.h>
#include <XMSS.h>
#include <esp_timer.h>
#include <xmss_hwsha.h>

#ifndef BENCH_SETS
#define BENCH_SETS 0x33
#endif
#ifndef BENCH_SIGS
#define BENCH_SIGS 256  // per set at most min(BENCH_SIGS, 2^(h/d))
#endif

struct BenchSet {
  bool mt;
  uint32_t oid;
};

static const BenchSet SETS[] = {
    /* 0 */ {false, XMSS_SHA2_10_256},
    /* 1 */ {false, XMSS_SHA2_10_192},
    /* 2 */ {false, XMSS_SHAKE256_10_256},
    /* 3 */ {false, XMSS_SHAKE256_10_192},
    /* 4 */ {true, XMSSMT_SHA2_20_4_256},
    /* 5 */ {true, XMSSMT_SHA2_20_4_192},
    /* 6 */ {true, XMSSMT_SHAKE256_20_4_256},
    /* 7 */ {true, XMSSMT_SHA2_20_2_256},
    /* 8 */ {true, XMSSMT_SHA2_40_8_256},
    /* 9 */ {true, XMSSMT_SHA2_60_12_256},
};

static uint8_t sig[28 * 1024];

static double nowMs() {
  return esp_timer_get_time() / 1000.0;
}

static void benchPrimitives() {
  uint32_t st[8];
  uint8_t block[64] = {1, 2, 3};
  uint64_t ks[25] = {0};
  const int N = 20000, NK = 2000;
  memcpy(st, xmss_sha256_iv, sizeof st);
  double t0 = nowMs();
  for (int i = 0; i < N; i++) xmss_sha256_compress(st, block);
  double tSha = (nowMs() - t0) * 1000.0 / N;
  t0 = nowMs();
  for (int i = 0; i < NK; i++) xmss_keccak_f1600(ks);
  double tK = (nowMs() - t0) * 1000.0 / NK;
  Serial.printf("SHA-256 compression: %.2f us, Keccak-f1600: %.2f us (%u, %u)\n", tSha, tK,
                (unsigned)st[0], (unsigned)ks[0]);
  Serial.printf("CSV,primitive,sha256_compress_us,%.3f\nCSV,primitive,keccak_f1600_us,%.3f\n", tSha, tK);
#if defined(XMSS_ESP32_HW_SHA)
  if (xmss_hw_sha_active()) {
    uint32_t words[16] = {1, 2, 3}, h[8];
    t0 = nowMs();
    for (int i = 0; i < N; i++) xmss_hw_sha256_blocks(words, 1, h);
    double tHw1 = (nowMs() - t0) * 1000.0 / N;
    xmss_hw_begin();
    t0 = nowMs();
    for (int i = 0; i < N; i++) xmss_hw_sha256_blocks(words, 1, h);
    double tHw2 = (nowMs() - t0) * 1000.0 / N;
    xmss_hw_end();
    Serial.printf("SHA-256 hardware block: %.2f us (with session: %.2f us)\n", tHw1, tHw2);
  }
#endif
}

template <class K>
void benchKey(const BenchSet &b) {
  XMSSRamStorage storage;
  K key;
  uint8_t pk[68], msg[32];
  size_t pkLen = sizeof pk;
  const xmss_param *p = b.mt ? xmssmt_param_get(b.oid) : xmss_param_get(b.oid);
  double t0 = nowMs(), tSign = 0, tSignMax = 0, tVerify = 0;
  int rc = key.generate(storage, b.oid);
  const double tKeygen = nowMs() - t0;
  if (rc != XMSS_OK) {
    Serial.printf("%s: keygen failed: %s\n", p->name, XMSSKeyBase::errorString(rc));
    return;
  }
  key.publicKey(pk, &pkLen);
  unsigned n = 0;
  const unsigned nsigs = BENCH_SIGS < (1u << p->th) ? BENCH_SIGS : (1u << p->th);
  for (; n < nsigs; n++) {
    size_t sl = sizeof sig;
    esp_fill_random(msg, sizeof msg);
    double t1 = nowMs();
    rc = key.sign(msg, sizeof msg, sig, &sl);
    double t2 = nowMs();
    int v = K::verify(pk, pkLen, msg, sizeof msg, sig, sl);
    tVerify += nowMs() - t2;
    tSign += t2 - t1;
    if (t2 - t1 > tSignMax) tSignMax = t2 - t1;
    if (rc != XMSS_OK || v != 0) {
      Serial.printf("%s: sign/verify failed (%s)\n", p->name, XMSSKeyBase::errorString(rc));
      return;
    }
  }
  Serial.printf("%-26s keygen %9.1f ms  sign %7.2f ms (max %7.1f, %u sigs)  verify %6.2f ms  "
                "sig %5u B  cache %5u B\n",
                p->name, tKeygen, tSign / n, tSignMax, n, tVerify / n,
                (unsigned)key.signatureSize(), (unsigned)key.cacheSize());
  Serial.printf("CSV,%s,%.1f,%.3f,%.1f,%.3f,%u\n", p->name, tKeygen, tSign / n, tSignMax,
                tVerify / n, (unsigned)key.signatureSize());
}

static void benchSet(const BenchSet &b) {
  if (b.mt) {
    benchKey<XMSSMTKey>(b);
  } else {
    benchKey<XMSSKey>(b);
  }
}

static void benchTask(void *) {
  Serial.println();
  Serial.println("================================================");
  Serial.println("  XMSS / XMSS^MT benchmark (ESP32)");
  Serial.println("================================================");
  Serial.printf("CPU %u MHz, %u signatures per set, SHA-256: %s\n", (unsigned)getCpuFrequencyMhz(),
                BENCH_SIGS, xmss_hw_sha_active() ? "hardware (XMSS_ESP32_HW_SHA)" : "software");
  benchPrimitives();
  for (unsigned i = 0; i < sizeof SETS / sizeof SETS[0]; i++) {
    if (BENCH_SETS & (1u << i)) benchSet(SETS[i]);
  }
  // ESP-IDF reports the high-water mark in bytes; the task has 16 KB
  Serial.printf("Peak stack use of this task: %u bytes (incl. the benchmark itself)\n",
                (unsigned)(16 * 1024 - uxTaskGetStackHighWaterMark(NULL)));
  Serial.println("Benchmark complete.");
  vTaskDelete(NULL);
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  xTaskCreatePinnedToCore(benchTask, "bench", 16 * 1024, NULL, 1, NULL, 1);
}

void loop() {
  delay(1000);
}
