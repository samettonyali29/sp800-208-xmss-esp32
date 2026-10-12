/*
 * xmss_esp32_platform.c - ESP32 platform layer of sp800-208-xmss-esp32
 *
 * 1. Random numbers: xmss_randombytes() reads the ESP32 hardware RNG
 *    (esp_fill_random). Its output is true random whenever an entropy
 *    source is running: Wi-Fi or Bluetooth enabled, or
 *    bootloader_random_enable() active (see the "Random Number Generation"
 *    chapter of the ESP-IDF API reference). SP 800-208 Section 6.2 asks for
 *    an approved RBG for SEED, S_XMSS and SK_PRF.
 *
 * 2. Task watchdog: key generation computes every one-time public key of a
 *    tree (seconds to minutes). The Arduino-ESP32 core watches the idle task
 *    of core 0 with a 5 s panic timeout. xmss_yield() is called once per
 *    leaf; every 500 ms of computation it sleeps for one tick, so the idle
 *    task runs and feeds the watchdog (same scheme as fips205-slhdsa-esp32).
 *
 * On other platforms, compile without this file and provide
 * xmss_randombytes() and xmss_yield() yourself.
 *
 * Copyright (c) 2026 The sp800-208-xmss-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#if defined(ESP_PLATFORM)

#include <stddef.h>
#include <stdint.h>
#include <esp_random.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include "xmss_esp32.h"

#ifndef XMSS_ESP32_YIELD_MS
#define XMSS_ESP32_YIELD_MS 500
#endif

int xmss_randombytes(uint8_t *out, size_t len)
{
  if (len == 0) {
    return 0;
  }
  if (out == NULL) {
    return -1;
  }
  esp_fill_random(out, len);
  return 0;
}

void xmss_yield(void)
{
  static volatile TickType_t last;
  const TickType_t now = xTaskGetTickCount();
  if ((TickType_t)(now - last) >= pdMS_TO_TICKS(XMSS_ESP32_YIELD_MS)) {
    last = now;
    vTaskDelay(1); /* lets the idle task run (and feed the task watchdog) */
  }
}

#endif /* ESP_PLATFORM */
