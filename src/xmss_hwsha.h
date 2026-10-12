/*
 * xmss_hwsha.h - optional SHA-256 hardware acceleration (see xmss_hwsha.c)
 *
 * Copyright (c) 2026 The sp800-208-xmss-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef XMSS_HWSHA_H
#define XMSS_HWSHA_H

#include <stddef.h>
#include <stdint.h>
#include "xmss_esp32_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 1 if XMSS_ESP32_HW_SHA is enabled and the hardware passed its self-test
 * (the self-test runs on the first call). */
int xmss_hw_sha_active(void);
/* Runtime switch (default on): with 0, xmss_hw_sha_active() reports 0 and
 * newly started operations compute in software -- for comparisons. */
void xmss_hw_sha_set_enabled(int on);

#if defined(ESP_PLATFORM) && defined(XMSS_ESP32_HW_SHA)
#define XMSS_HW_SHA_BUILD 1
/* SHA-256 of an already padded message of nblocks blocks, given as
 * 16 * nblocks big-endian words, from the initial state; h receives the
 * state words H0..H7 (as the software compression function produces them).
 * 0 = done in hardware, -1 = hardware not in use (compute in software). */
int xmss_hw_sha256_blocks(const uint32_t *blocks, unsigned nblocks, uint32_t h[8]);
/* Hold the SHA engines for a sequence of blocks (nestable). */
void xmss_hw_begin(void);
void xmss_hw_end(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* XMSS_HWSHA_H */
