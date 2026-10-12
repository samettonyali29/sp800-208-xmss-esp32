/*
 * XMSS / XMSS^MT (RFC 8391, NIST SP 800-208) live demo for the M5StickC PLUS2
 * (ESP32-PICO-V3-02, 1.14" 135x240 ST7789V2 display).
 *
 * Stateful signatures: the key lives in NVS; every second a message is
 * signed with the next one-time key and verified. The screen shows the
 * timings (last and average), the one-time key index q of the latest
 * signature and the signature status. After a reset or power cycle the key
 * is loaded again and q continues where it stopped (the index is stored
 * before each signature is computed). When a key is used up, a new one is
 * generated.
 *
 *   Button A (front, "M5"):  tamper test -- flips one bit of the latest
 *                            signature and shows that verification rejects it
 *   Button B (right side):   switch parameter set (generates a new key; only
 *                            one key is kept in NVS)
 *
 * Key generation computes every one-time key of a tree (1.5 min for a
 * height-10 XMSS tree in software), so the cryptography runs in its own
 * task: the display stays live and shows the elapsed time of the running
 * step. With the SHA hardware backend (XMSS_ESP32_HW_SHA, see
 * src/xmss_esp32_config.h) the SHA-256 sets run several times faster; the
 * header then shows "HW".
 *
 * Requires the M5Unified library (Library Manager: "M5Unified"), which also
 * keeps the PLUS2 powered on battery (HOLD pin G4).
 * Board: "M5StickCPlus2" (esp32:esp32:m5stack_stickc_plus2).
 *
 * Copyright (c) 2026 The sp800-208-xmss-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <M5Unified.h>
#include <XMSS.h>
#include <XMSS_NVS.h>

// Colors (RGB565)
#define COL_BG       0x0000
#define COL_HEADER   0x04B4  // teal (same in all demos)
#define COL_CARD     0x2124
#define COL_ACTIVE   0x4A49  // card of the running step
#define COL_LABEL    0xBDF7
#define COL_OK       0x07E0
#define COL_ERR      0xF800
#define COL_WARN     0xFD20

struct Variant {
  const char *alg;   // header: small algorithm name
  const char *name;  // header: bold parameter set
  bool shake;
  bool mt;
  uint32_t oid;
};

// Parameter sets whose key state fits the default 20 KB NVS partition next
// to Wi-Fi data (XMSS^MT stores one signature per lower layer: 3 x 1.3 KB
// for the 20/4_192 sets; XMSSMT-SHA2_20/4_256 needs 3 x 2.3 KB). The header
// shows short names: "SHA2 20/4" = XMSSMT-SHA2_20/4_192, "SHAKE 20/4" =
// XMSSMT-SHAKE256_20/4_192 (the full names are logged on the serial port).
static const Variant VARIANTS[] = {
    {"XMSS^MT", "SHA2 20/4", false, true, XMSSMT_SHA2_20_4_192},
    {"XMSS^MT", "SHAKE 20/4", true, true, XMSSMT_SHAKE256_20_4_192},
    {"XMSS", "SHA2_10_256", false, false, XMSS_SHA2_10_256},
    {"XMSS", "SHA2_10_192", false, false, XMSS_SHA2_10_192},
};
static const int NVARIANTS = sizeof(VARIANTS) / sizeof(VARIANTS[0]);
static const char *OP_LABEL[3] = {"KeyGen", "Sign", "Verify"};

static XMSSNvsStorage storage;
static XMSSKey xmssKey;
static XMSSMTKey mtKey;
static uint8_t pk[68];
static size_t pkLen;
static uint8_t sig[10 * 1024];
static size_t sigLen;
static char msg[48];

// ---- state shared between the crypto task and the UI (loop) --------------
struct Shared {
  int variant;
  int phase;  // -1 idle, 0..2 running KeyGen/Sign/Verify
  uint32_t phaseStartMs;
  uint32_t runs, failures;
  uint32_t cnt[3];  // operations per card
  uint64_t sumUs[3];
  uint32_t lastUs[3];
  uint32_t loadMs;   // key loaded from NVS (no key generation needed)
  bool loaded;
  uint64_t q, total;  // one-time key of the latest signature
  uint8_t fp[2];      // signature fingerprint
  char status[32];
  uint16_t statusColor;
  bool haveSig;
};
static Shared st;
static portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;
static volatile bool switchRequested = false, tamperRequested = false;

static void setStatus(const char *s, uint16_t color) {
  portENTER_CRITICAL(&mux);
  strncpy(st.status, s, sizeof(st.status) - 1);
  st.statusColor = color;
  portEXIT_CRITICAL(&mux);
}

static void setPhase(int phase) {
  portENTER_CRITICAL(&mux);
  st.phase = phase;
  st.phaseStartMs = millis();
  portEXIT_CRITICAL(&mux);
}

static void record(int op, uint32_t us) {
  portENTER_CRITICAL(&mux);
  st.cnt[op]++;
  st.lastUs[op] = us;
  st.sumUs[op] += us;
  portEXIT_CRITICAL(&mux);
}

static XMSSKeyBase &key() {
  return VARIANTS[st.variant].mt ? (XMSSKeyBase &)mtKey : (XMSSKeyBase &)xmssKey;
}

static int verifyLatest() {
  const Variant &v = VARIANTS[st.variant];
  return v.mt ? XMSSMTKey::verify(pk, pkLen, (const uint8_t *)msg, strlen(msg), sig, sigLen)
              : XMSSKey::verify(pk, pkLen, (const uint8_t *)msg, strlen(msg), sig, sigLen);
}

// Variant of a loaded key, -1 if none matches
static int variantOf(const XMSSKeyBase &k, bool mt) {
  for (int i = 0; i < NVARIANTS; i++) {
    if (VARIANTS[i].mt == mt && VARIANTS[i].oid == k.oid()) return i;
  }
  return -1;
}

// At boot: load the stored key (any variant). Otherwise / afterwards:
// generate a key of the current variant (replacing the stored one).
static bool openKey(bool atBoot) {
  int rc = XMSS_ERR_NOKEY;
  if (atBoot) {
    uint32_t t0 = millis();
    int idx = -1;
    if (mtKey.load(storage) == XMSS_OK) {
      idx = variantOf(mtKey, true);
    } else if (xmssKey.load(storage) == XMSS_OK) {
      idx = variantOf(xmssKey, false);
    }
    if (idx >= 0) {
      portENTER_CRITICAL(&mux);
      st.variant = idx;
      portEXIT_CRITICAL(&mux);
    }
    if (idx >= 0 && key().remaining() > 0) {
      rc = XMSS_OK;
      portENTER_CRITICAL(&mux);
      st.loaded = true;
      st.loadMs = millis() - t0;
      portEXIT_CRITICAL(&mux);
      Serial.printf("%s: key loaded from NVS in %lu ms, next one-time key %llu of %llu\n",
                    key().name(), (unsigned long)(millis() - t0),
                    (unsigned long long)key().nextIndex(),
                    (unsigned long long)key().totalSignatures());
    } else {
      xmssKey.end();
      mtKey.end();
    }
  }
  const Variant &v = VARIANTS[st.variant];
  if (rc != XMSS_OK) {
    setStatus("generating key", COL_LABEL);
    setPhase(0);
    uint32_t t0 = micros();
    rc = v.mt ? mtKey.generate(storage, v.oid) : xmssKey.generate(storage, v.oid);
    uint32_t us = micros() - t0;
    setPhase(-1);
    if (rc != XMSS_OK) {
      Serial.printf("Key generation failed: %s\n", XMSSKeyBase::errorString(rc));
      setStatus("keygen FAILED", COL_ERR);
      return false;
    }
    record(0, us);
    Serial.printf("%s: key generated in %.1f ms (%llu signatures)\n", key().name(), us / 1000.0,
                  (unsigned long long)key().totalSignatures());
  }
  pkLen = sizeof(pk);
  key().publicKey(pk, &pkLen);
  portENTER_CRITICAL(&mux);
  st.total = key().totalSignatures();
  portEXIT_CRITICAL(&mux);
  return true;
}

static void cryptoTask(void *) {
  bool ready = storage.begin("xmssdemo") && openKey(true);
  for (;;) {
    if (switchRequested) {
      switchRequested = false;
      xmssKey.end();
      mtKey.end();
      portENTER_CRITICAL(&mux);
      int next = (st.variant + 1) % NVARIANTS;
      memset(&st, 0, sizeof(st));
      st.variant = next;
      st.phase = -1;
      portEXIT_CRITICAL(&mux);
      Serial.printf("Switched to %s %s\n", VARIANTS[next].alg, VARIANTS[next].name);
      setStatus("starting...", COL_LABEL);
      ready = openKey(false);  // new key for the new parameter set
    }
    if (!ready) {
      vTaskDelay(pdMS_TO_TICKS(100));
      continue;
    }

    if (tamperRequested) {
      tamperRequested = false;
      if (st.haveSig) {
        size_t pos = esp_random() % sigLen;
        uint8_t bit = 1u << (esp_random() & 7);
        sig[pos] ^= bit;
        bool rejected = verifyLatest() != 0;
        sig[pos] ^= bit;
        Serial.printf("Tamper test (sig byte %u flipped): %s\n", (unsigned)pos,
                      rejected ? "REJECTED" : "NOT rejected!");
        setStatus(rejected ? "tamper REJECTED" : "tamper ACCEPTED!", rejected ? COL_WARN : COL_ERR);
        vTaskDelay(pdMS_TO_TICKS(2500));
      }
      continue;
    }

    // Sign the next message with the next one-time key, then verify
    snprintf(msg, sizeof(msg), "M5StickC PLUS2 message #%lu", (unsigned long)st.runs);
    sigLen = sizeof(sig);
    const uint64_t q = key().nextIndex();
    setPhase(1);
    uint32_t t0 = micros();
    int rc = key().sign((const uint8_t *)msg, strlen(msg), sig, &sigLen);
    uint32_t tSign = micros() - t0;
    if (rc == XMSS_ERR_EXHAUSTED) {  // all one-time keys used: new key
      setPhase(-1);
      Serial.println("Key exhausted, generating a new one");
      ready = openKey(false);
      continue;
    }
    uint32_t tVerify = 0;
    if (rc == XMSS_OK) {
      setPhase(2);
      t0 = micros();
      rc = verifyLatest();
      tVerify = micros() - t0;
    }
    setPhase(-1);
    if (switchRequested) continue;

    const bool ok = rc == 0;
    // fingerprint: the randomizer r (after the index)
    const size_t fpOffset = key().params()->idx_bytes;
    record(1, tSign);
    if (tVerify) record(2, tVerify);
    portENTER_CRITICAL(&mux);
    st.runs++;
    if (!ok) st.failures++;
    st.q = q;
    memcpy(st.fp, sig + fpOffset, sizeof(st.fp));
    st.haveSig = ok;
    portEXIT_CRITICAL(&mux);
    setStatus(ok ? "signature VALID" : "FAILED", ok ? COL_OK : COL_ERR);
    Serial.printf("%s q=%llu sign=%.2fms verify=%.2fms %s, %llu left\n", key().name(),
                  (unsigned long long)q, tSign / 1000.0, tVerify / 1000.0,
                  ok ? "VALID" : "FAILED", (unsigned long long)key().remaining());
    vTaskDelay(pdMS_TO_TICKS(1000));
  }
}

// ---- UI ------------------------------------------------------------------
static M5Canvas canvas(&M5.Display);  // off-screen buffer: flicker-free

// Times: "6.15 ms" below 100 ms, "123.4 ms" below 10 s, "54.27 s" above
// (same format in all demos)
static void fmtTime(char *buf, size_t n, double ms) {
  if (ms < 100) {
    snprintf(buf, n, "%.2f ms", ms);
  } else if (ms < 10000) {
    snprintf(buf, n, "%.1f ms", ms);
  } else {
    snprintf(buf, n, "%.2f s", ms / 1000.0);
  }
}

// Header: small algorithm name + bold parameter set (same in all demos)
static void drawTitle(const char *alg, const char *variant) {
  canvas.setTextColor(TFT_WHITE, COL_HEADER);
  canvas.setTextDatum(middle_left);
  canvas.setFont(&fonts::Font2);
  canvas.drawString(alg, 6, 12);
  const int x = 6 + canvas.textWidth(alg) + 6;
  canvas.setFont(&fonts::FreeSansBold9pt7b);
  canvas.drawString(variant, x, 11);
  canvas.setFont(&fonts::Font2);
}

static void drawScreen() {
  Shared s;
  portENTER_CRITICAL(&mux);
  s = st;
  portEXIT_CRITICAL(&mux);
  const int W = canvas.width();
  const Variant &v = VARIANTS[s.variant];
  canvas.fillScreen(COL_BG);

  // Header
  canvas.fillRect(0, 0, W, 22, COL_HEADER);
  drawTitle(v.alg, v.name);
  canvas.setTextDatum(middle_right);
  canvas.drawString(String(M5.Power.getBatteryLevel()) + "%", W - 5, 11);
  if (!v.shake && xmss_hw_sha_active()) {
    canvas.drawString("HW", W - 46, 11);  // SHA hardware accelerator in use
  }

  // Timing rows: last run and average (or live elapsed time while running)
  canvas.setFont(&fonts::Font2);
  for (int i = 0; i < 3; i++) {
    int y = 26 + i * 21;
    const bool running = s.phase == i;
    const uint16_t bg = running ? COL_ACTIVE : COL_CARD;
    canvas.fillRoundRect(3, y, W - 6, 19, 4, bg);
    canvas.setTextDatum(middle_left);
    canvas.setTextColor(COL_LABEL, bg);
    canvas.drawString(OP_LABEL[i], 9, y + 10);
    char last[16], avg[16], buf[40];
    if (running) {
      fmtTime(last, sizeof(last), (double)(millis() - s.phaseStartMs));
      snprintf(buf, sizeof(buf), "running %s", last);
      canvas.setTextColor(COL_WARN, bg);
    } else if (s.cnt[i] == 0) {
      if (i == 0 && s.loaded) {  // key loaded from NVS instead of generated
        fmtTime(last, sizeof(last), (double)s.loadMs);
        snprintf(buf, sizeof(buf), "loaded %s", last);
      } else {
        snprintf(buf, sizeof(buf), "-");
      }
      canvas.setTextColor(TFT_WHITE, bg);
    } else {
      fmtTime(last, sizeof(last), s.lastUs[i] / 1000.0);
      fmtTime(avg, sizeof(avg), s.sumUs[i] / 1000.0 / s.cnt[i]);
      snprintf(buf, sizeof(buf), "%s  avg %s", last, avg);
      canvas.setTextColor(TFT_WHITE, bg);
    }
    canvas.setTextDatum(middle_right);
    canvas.drawString(buf, W - 9, y + 10);
  }

  // One-time key index + signature fingerprint, status
  canvas.setTextDatum(middle_left);
  canvas.setTextColor(COL_LABEL, COL_BG);
  char fp[40];
  if (s.runs) {
    char total[16];
    if (s.total > 65536) {  // 2^20 etc.: keep the line short
      snprintf(total, sizeof(total), "2^%u", (unsigned)(63 - __builtin_clzll(s.total)));
    } else {
      snprintf(total, sizeof(total), "%llu", (unsigned long long)s.total);
    }
    snprintf(fp, sizeof(fp), "q %llu/%s %02X%02X", (unsigned long long)s.q, total, s.fp[0],
             s.fp[1]);
  } else {
    snprintf(fp, sizeof(fp), "q -");
  }
  canvas.drawString(fp, 6, 99);
  canvas.setTextColor(s.statusColor, COL_BG);
  canvas.setTextDatum(middle_right);
  canvas.drawString(s.status, W - 6, 99);

  // Footer
  canvas.setTextColor(COL_LABEL, COL_BG);
  canvas.setTextDatum(middle_left);
  char foot[48];
  snprintf(foot, sizeof(foot), "#%lu  fail %lu", (unsigned long)s.runs, (unsigned long)s.failures);
  canvas.drawString(foot, 6, 122);
  canvas.setTextDatum(middle_right);
  canvas.drawString(switchRequested ? "switching..." : "A:tamper B:level", W - 6, 122);

  canvas.pushSprite(0, 0);
}

// ---- Arduino ---------------------------------------------------------------
void setup() {
  auto cfg = M5.config();
  M5.begin(cfg);
  Serial.begin(115200);
  M5.Display.setRotation(1);  // landscape, 240 x 135
  M5.Display.setBrightness(96);
  canvas.createSprite(M5.Display.width(), M5.Display.height());
  memset(&st, 0, sizeof(st));
  st.phase = -1;
  setStatus("ready", COL_LABEL);
  Serial.println("\nXMSS / XMSS^MT live demo (M5StickC PLUS2)");
  // crypto on core 0, the UI runs on core 1 (loop)
  xTaskCreatePinnedToCore(cryptoTask, "xmss", 12 * 1024, NULL, 1, NULL, 0);
}

void loop() {
  static uint32_t lastDraw = 0;
  M5.update();
  if (M5.BtnB.wasPressed()) switchRequested = true;
  if (M5.BtnA.wasPressed()) tamperRequested = true;
  if (millis() - lastDraw >= 200) {
    lastDraw = millis();
    drawScreen();
  }
  delay(10);
}
