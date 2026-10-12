/*
 * xmss_esp32_config.h - build options of sp800-208-xmss-esp32
 *
 * Options can be set here, or as compiler flags (PlatformIO: build_flags,
 * arduino-cli: --build-property "compiler.c.extra_flags=..." and
 * "compiler.cpp.extra_flags=...").
 *
 * Copyright (c) 2026 The sp800-208-xmss-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef XMSS_ESP32_CONFIG_H
#define XMSS_ESP32_CONFIG_H

/*
 * XMSS_ESP32_MAX_KEYGEN_HEIGHT  (default: 16)
 *
 * Largest tree height (h for XMSS, h/d for XMSS^MT) accepted for key
 * generation and signing; all parameter sets can always be verified.
 * Generating a tree means computing all of its 2^h WOTS+ public keys: on an
 * ESP32 at 240 MHz a height-10 tree takes ~1.5 min in software (~15 s with
 * XMSS_ESP32_HW_SHA), a height-16 tree 64 times as long, and its tree cache
 * needs ~48 KB of RAM. For more signatures use XMSS^MT.
 */
#ifndef XMSS_ESP32_MAX_KEYGEN_HEIGHT
#define XMSS_ESP32_MAX_KEYGEN_HEIGHT 16
#endif

/*
 * XMSS_ESP32_HW_SHA  (default: off)
 *
 * Compute the SHA-256 hashes of F, H, PRF and PRF_keygen (nearly all of
 * the work) with the ESP32's SHA hardware accelerator (see README). SHAKE
 * parameter sets are not affected. A self-test runs before the first use;
 * if it fails, the software implementation is used. xmss_hw_sha_active()
 * tells which one is in use.
 * The Arduino IDE has no per-sketch compiler flags: uncomment the line.
 */
/* #define XMSS_ESP32_HW_SHA */

#endif /* XMSS_ESP32_CONFIG_H */
