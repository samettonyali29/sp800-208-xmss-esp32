/*
 * xmss_hwsha.c - optional SHA-256 hardware acceleration (XMSS_ESP32_HW_SHA)
 *
 * The XMSS hash functions F, H, PRF and PRF_keygen of the SHA-256 parameter
 * sets hash short messages of 1-3 blocks (52-128 bytes). The original
 * ESP32's SHA accelerator cannot resume from a midstate, so each of them is
 * hashed from the initial state; the software path saves the first block
 * of PRF / PRF_keygen with a precomputed midstate, but one hardware block
 * costs ~250 CPU cycles instead of ~5000, so the hardware still wins by far.
 * Only H_msg (once per signature) stays in software.
 *
 * Hardware access (same scheme as fips205-slhdsa-esp32):
 *   - Original ESP32 (separate SHA-1 / SHA-256 / SHA-384+512 engines that
 *     share one register block): all engines are locked for a whole WOTS+
 *     operation (xmss_hw_begin/end), so the shared text registers are ours
 *     and no critical section is needed. They are briefly released every
 *     SESSION_CALLS blocks so that blocking users (esp_sha) get a turn;
 *     mbedTLS try-locks the engines and falls back to software meanwhile.
 *     (SHA-384 and SHA-512 share one lock; locking both would deadlock.)
 *   - ESP32-S2/S3/C3/C6... (single engine, ESP-IDF >= 5): the engine is
 *     acquired for batches of SESSION_CALLS blocks only, because mbedTLS
 *     waits for it. (Compile-tested only.)
 *   - Other targets: no hardware, xmss_hw_sha256_block() returns -1 and the
 *     caller computes in software.
 *
 * Before the first use a self-test compares hardware and software results
 * (and determines the digest register byte order); if it fails, everything
 * is computed in software.
 *
 * Copyright (c) 2026 The sp800-208-xmss-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "xmss_hwsha.h"

#if defined(ESP_PLATFORM) && defined(XMSS_ESP32_HW_SHA)

#include <stdbool.h>
#include <string.h>
#include <sdkconfig.h>
#include <esp_idf_version.h>
#include <soc/soc_caps.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include "xmss_hash.h"

#if defined(CONFIG_IDF_TARGET_ESP32)
#define HW_CLASSIC 1
#include <sha/sha_parallel_engine.h>
#include <hal/sha_ll.h>
#include <soc/dport_access.h>
#include <soc/hwcrypto_reg.h>
#define SESSION_CALLS 256
#elif ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0) && defined(SOC_SHA_SUPPORTED)
#define HW_CORE 1
#include <sha/sha_core.h>
#define SESSION_CALLS 64
#endif

#if defined(HW_CLASSIC) || defined(HW_CORE)
#define HW_AVAILABLE 1
#endif

enum { HW_UNTESTED = 0, HW_OK = 1, HW_FAILED = 2 };
static volatile int s_state = HW_UNTESTED;
static bool s_testing;   /* self-test in progress: use the hardware */
static uint8_t s_mode;   /* digest byte order: 0 as read, 1 swapped words */
static volatile bool s_enabled = true; /* runtime switch */

#if defined(HW_AVAILABLE)
static TaskHandle_t s_owner; /* task holding a session */
static unsigned s_depth;
static unsigned s_calls;

static void hw_acquire(void)
{
#if defined(HW_CLASSIC)
  esp_sha_lock_engine(SHA1);
  esp_sha_lock_engine(SHA2_256);
  esp_sha_lock_engine(SHA2_512);
#else
  esp_sha_acquire_hardware();
#endif
}

static void hw_release(void)
{
#if defined(HW_CLASSIC)
  esp_sha_unlock_engine(SHA2_512);
  esp_sha_unlock_engine(SHA2_256);
  esp_sha_unlock_engine(SHA1);
#else
  esp_sha_release_hardware();
#endif
}

/* true if the engine was acquired for this block only (no session) */
static bool hw_enter(void)
{
  if (s_owner != NULL && s_owner == xTaskGetCurrentTaskHandle()) {
    if (++s_calls >= SESSION_CALLS) {
      s_calls = 0;
      hw_release(); /* let other users of the SHA engine in */
      taskYIELD();
      hw_acquire();
    }
    return false;
  }
  hw_acquire();
  return true;
}

/* SHA-256 of nblocks padded blocks (16 big-endian words each) from the IV,
 * digest words in register order. */
static void hw_blocks(const uint32_t *blocks, unsigned nblocks, uint32_t dig[8])
{
  const bool per_call = hw_enter();
#if defined(HW_CLASSIC)
  volatile uint32_t *text = (volatile uint32_t *)SHA_TEXT_BASE;
  unsigned i, b;
  for (b = 0; b < nblocks; b++) {
    const uint32_t *blk = blocks + 16 * b;
    if (b > 0) {
      while (DPORT_REG_READ(SHA_256_BUSY_REG) != 0) {
      }
    }
    for (i = 0; i < 16; i++) {
      text[i] = blk[i]; /* the text registers take big-endian words */
    }
    if (b == 0) {
      sha_ll_start_block(SHA2_256);
    } else {
      sha_ll_continue_block(SHA2_256);
    }
  }
  while (DPORT_REG_READ(SHA_256_BUSY_REG) != 0) {
  }
  sha_ll_load(SHA2_256); /* digest -> text registers */
  while (DPORT_REG_READ(SHA_256_BUSY_REG) != 0) {
  }
  DPORT_INTERRUPT_DISABLE();
  for (i = 0; i < 8; i++) {
    dig[i] = DPORT_SEQUENCE_REG_READ((uint32_t)&text[i]);
  }
  DPORT_INTERRUPT_RESTORE();
#else
  uint32_t le[16];
  unsigned i, b;
  esp_sha_set_mode(SHA2_256);
  for (b = 0; b < nblocks; b++) {
    for (i = 0; i < 16; i++) {
      le[i] = __builtin_bswap32(blocks[16 * b + i]); /* esp_sha_block takes the bytes */
    }
    esp_sha_block(SHA2_256, le, b == 0);
  }
  esp_sha_read_digest_state(SHA2_256, dig);
#endif
  if (per_call) {
    hw_release();
  }
}
#endif /* HW_AVAILABLE */

/* register words -> state words H0..H7 (mode 1: registers hold H[i];
 * mode 0: byte-swapped) */
static inline void to_state(uint32_t dig[8], uint8_t mode)
{
  unsigned i;
  if (mode == 0) {
    for (i = 0; i < 8; i++) {
      dig[i] = __builtin_bswap32(dig[i]);
    }
  }
}

int xmss_hw_sha256_blocks(const uint32_t *blocks, unsigned nblocks, uint32_t h[8])
{
#if defined(HW_AVAILABLE)
  if (s_state != HW_OK && !s_testing) {
    return -1;
  }
  hw_blocks(blocks, nblocks, h);
  to_state(h, s_mode);
  return 0;
#else
  (void)blocks;
  (void)nblocks;
  (void)h;
  return -1;
#endif
}

#if defined(HW_AVAILABLE)
/* hardware vs. software on messages of 0..150 bytes (1-3 blocks) */
static bool selftest(void)
{
  uint32_t words[48], st[8], dig[8], got[8];
  uint8_t msg[192]; /* 3 blocks */
  int mode = -1;
  unsigned t, i;
  for (t = 0; t < 14; t++) {
    const unsigned len = (t * 37) % 151;
    const unsigned nblocks = (len + 9 + 63) / 64;
    uint64_t bits = (uint64_t)len * 8;
    xmss_sha256_ctx c;
    uint8_t ref[32];
    memset(msg, 0, sizeof msg);
    for (i = 0; i < len; i++) {
      msg[i] = (uint8_t)(i * 131 + 7 * t + 1);
    }
    xmss_sha256_init(&c);
    xmss_sha256_update(&c, msg, len);
    xmss_sha256_final(&c, ref, 32);
    for (i = 0; i < 8; i++) {
      st[i] = ((uint32_t)ref[4 * i] << 24) | ((uint32_t)ref[4 * i + 1] << 16) |
              ((uint32_t)ref[4 * i + 2] << 8) | ref[4 * i + 3];
    }
    msg[len] = 0x80; /* pad, then bytes -> big-endian words */
    for (i = 0; i < 8; i++) {
      msg[nblocks * 64 - 1 - i] = (uint8_t)(bits >> (8 * i));
    }
    for (i = 0; i < nblocks * 16; i++) {
      words[i] = ((uint32_t)msg[4 * i] << 24) | ((uint32_t)msg[4 * i + 1] << 16) |
                 ((uint32_t)msg[4 * i + 2] << 8) | msg[4 * i + 3];
    }
    hw_blocks(words, nblocks, dig);
    if (mode < 0) {
      for (i = 0; i <= 1 && mode < 0; i++) {
        memcpy(got, dig, sizeof got);
        to_state(got, (uint8_t)i);
        if (memcmp(got, st, sizeof st) == 0) {
          mode = (int)i;
        }
      }
      if (mode < 0) {
        return false;
      }
    }
    to_state(dig, (uint8_t)mode);
    if (memcmp(dig, st, sizeof st) != 0) {
      return false;
    }
  }
  s_mode = (uint8_t)mode;
  return true;
}
#endif

int xmss_hw_sha_active(void)
{
  if (s_state == HW_UNTESTED) {
#if defined(HW_AVAILABLE)
    static portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;
    static bool running = false;
    bool mine = false;
    taskENTER_CRITICAL(&mux);
    if (!running) {
      running = mine = true;
    }
    taskEXIT_CRITICAL(&mux);
    if (mine) {
      bool ok;
      s_testing = true;
      ok = selftest();
      s_testing = false;
      s_state = ok ? HW_OK : HW_FAILED;
    } else {
      while (s_state == HW_UNTESTED) {
        vTaskDelay(1); /* another task is running the self-test */
      }
    }
#else
    s_state = HW_FAILED;
#endif
  }
  return s_state == HW_OK && s_enabled;
}

void xmss_hw_sha_set_enabled(int on)
{
  s_enabled = on != 0;
}

void xmss_hw_begin(void)
{
#if defined(HW_AVAILABLE)
  TaskHandle_t me = xTaskGetCurrentTaskHandle();
  if (!xmss_hw_sha_active()) {
    return;
  }
  if (s_owner == me) {
    s_depth++;
    return;
  }
  hw_acquire();
  s_calls = 0;
  s_depth = 1;
  s_owner = me;
#endif
}

void xmss_hw_end(void)
{
#if defined(HW_AVAILABLE)
  if (s_owner == NULL || s_owner != xTaskGetCurrentTaskHandle()) {
    return;
  }
  if (--s_depth == 0) {
    s_owner = NULL;
    hw_release();
  }
#endif
}

#else /* no hardware acceleration configured */

int xmss_hw_sha_active(void)
{
  return 0;
}

void xmss_hw_sha_set_enabled(int on)
{
  (void)on;
}

#endif
