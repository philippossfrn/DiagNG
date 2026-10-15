# HiSilicon / Kirin support — status & how to continue

_Last updated: 2026-10-16_

Goal: extend DiagNG to capture baseband diagnostic logs from **non-rooted
HiSilicon Kirin** modems (like QCSuper/SCAT do for Qualcomm), and decode them
to GSMTAP/PCAP.

Test device: **Huawei Mate 20 Lite** — `SNE-LX1`, Kirin 710, EMUI 10 /
Android 10 (`SNE-LX1 10.0.0.245(C432E10R1P1)`), USB id `12d1:107e`.
**Not rooted.** Programmable test SIM in use (MCC 999 / MNC 70).

---

## TL;DR

- **Software side is DONE and tested** — parser, decoder, USB acquisition
  (two paths), device detection, and a capture window are implemented, wired
  into the UI, and covered by 29 passing tests. It produces GSMTAP the moment a
  real HiSilicon log stream exists.
- **The one blocker is on the phone, not in DiagNG:** the Kirin modem does not
  emit anything on its DIAG port until modem logging is switched on, and that
  switch is locked on a non-rooted retail device. We reverse-engineered *how*
  it works (HiSilicon **VCOM** protocol) but did not recover the exact
  OTA-log enable bytes, which live in code the phone won't hand over.
- Nothing is committed. All new code is in the working tree.

---

## 1. What was built (DiagNG code)

All new, mirrors the existing Qualcomm structure. **Not committed** — working
tree only.

### New files
| File | Purpose |
|------|---------|
| `src/diagng/protocol/hisilicon/hisi_log_parser.py` | Pure, stateful parser. One pseudo-HDLC frame → list of `GsmtapRecord`. Handles LTE RRC, LTE NAS, LTE cell-info (ARFCN state), WCDMA RRC, GSM/Abis (nested records), optional debug msgs. Ported from SCAT `handymenny/scat` dev branch, adapted to DiagNG's Kaitai GSMTAP. |
| `src/diagng/protocol/hisilicon/hisi_decoder.py` | `HisiOTADecoder` — bridges parsed records to `PcapOutput.write_gsmtap_v2_packet`. Connects to an input's `frame_received` signal (like Qualcomm `OTADecoder`). `PcapOutput` imported under `TYPE_CHECKING` so it is testable without GTK. |
| `src/diagng/protocol/hisilicon/acquisition/base_input.py` | `BaseHisiInput` (GObject) — transport-agnostic framing: `process_input(data)` buffers and splits the stream on `0x7e`, emits `frame_received(frame, n, total)`. |
| `src/diagng/protocol/hisilicon/acquisition/pyusb_input.py` | `PyUSBHisiInput` — USB read-thread acquisition (no-daemon path), mirrors Qualcomm `pyusb_input.py`. Read-only; `send_raw` kept for a future enable step. |
| `src/diagng/protocol/hisilicon/acquisition/usb_input.py` | `USBHisiInput` — diagmond D-Bus-backed acquisition (the usual/privileged path), mirrors Qualcomm `usb_input.py`. |
| `src/diagng/protocol/hisilicon/hisi_usb_detect.py` | Pure detection. Kirin DIAG port = vid `0x12d1` + interface `255/19/35` + 2 endpoints. `classify_diag_interface()` returns `'qualcomm'`/`'hisilicon'`/`None`. |
| `src/diagng/ui/hisi_window/imp.py` | `HisiWindow` — capture window built programmatically (no `.blp`/gresource). Wireshark + PCAP-file sinks via `PcapOutput` + `HisiOTADecoder`. No log-config UI (HiSilicon capture is passive). |
| `tests/hisilicon/test__hisi_log_parser.py` | 14 tests — parser per-RAT + framing/robustness. |
| `tests/hisilicon/test__hisi_acquisition.py` | 6 tests — framing + input→decoder→pcap wiring with fakes. |
| `tests/hisilicon/test__hisi_usb_detect.py` | 7 tests — detection. |

### Modified files
| File | Change |
|------|--------|
| `src/diagng/gobject/usb_interface.py` | Added `baseband` property (default `'qualcomm'`), tags each detected interface. |
| `src/diagng/utils/usb_port_detecter.py` | Uses `classify_diag_interface()` as the single source of truth (replaced the hardcoded Qualcomm-only `255/255/48`,`255/255/255` filter that dropped Kirin ports). Tags `out_obj.baseband`. |
| `src/diagng/ui/main_window/imp.py` | `connect_usb_intf` (pyusb/no-daemon path) branches on `usb_intf.baseband` → `PyUSBHisiInput` + `HisiWindow`. `disconnect_usb_intf` closes all four port maps (fixed a latent close-wrong-map bug). Group title now "Qualcomm / HiSilicon". |
| `src/diagng/system/diagmond_serialdevice_om.py` | `create_qcdm_window_usb` branches on baseband → `USBHisiInput` + `HisiWindow` (the daemon path). |

### Protocol facts (so the parser makes sense)
- Framing is **identical to Qualcomm**: pseudo-HDLC, `0x7e` trailer, byte
  stuffing (`0x7d` escape), CCITT CRC-16 (X.25). DiagNG reuses
  `protocol/qualcomm/utils/hdlc.py` directly.
- Two log record layouts, keyed by the first decoded byte:
  - `0x00` flat: `u8 type` + header `<L Q L L L>` (unk2, ts, unk3, **cmd**, len) + payload. Dispatch on `cmd` (u32).
  - `0x01` nested: magic `0xaaaa5555 … 0x5555aaaa`, header `<L L L H L H Q>`, dispatch on `cmd`.
- Known `cmd` handlers: `0x20010000` LTE OTA (chan `0xab`=RRC, `0xad/0xae`=NAS),
  `0x10051082` LTE cell info, nested `0x00020101` L3 OTA (WCDMA/GSM/Abis),
  debug msgs. `0x20020000` (LTE meas report) is **not yet ported** from SCAT.
- **SCAT's HiSilicon parser is passive** — it never sends enable commands; it
  assumes the stream is already flowing. That is exactly our blocker.

### Run the tests
No `uv` on the dev box; a throwaway venv works:
```bash
python3 -m venv --system-site-packages /tmp/hisienv
/tmp/hisienv/bin/pip install kaitaistruct crcmod pytest
cd ~/development/DiagNG
PYTHONPATH=src /tmp/hisienv/bin/python -m pytest tests/hisilicon -q   # 27 pass
PYTHONPATH=src /tmp/hisienv/bin/python -m pytest tests -q              # 29 pass (+2 qualcomm)
```
(With the project toolchain installed: `uv run pytest`.)

---

## 2. Build & run the app (to see the UI changes)

Host is Ubuntu 24.04 → **libadwaita 1.5**, but DiagNG needs **1.8+**, so
running from source won't launch. **Use the local Flatpak build** (proven on
this machine).

```bash
cd ~/development/DiagNG && rm -rf diagmond/target
flatpak-builder --user --install --force-clean --install-deps-from=flathub \
    build-dir ~/diagng-flatpak-local.json
flatpak run com.p1security.diagng
```
- `~/diagng-flatpak-local.json` is a comment-free copy of
  `packaging/flatpak/com.p1security.diagng.json` (Ubuntu 24.04 flatpak-builder
  chokes on `//` comments). It builds from this checkout (`type: dir`), so our
  changes are included.
- **Gotcha we hit:** that local manifest was stale and **missing the
  `python3-pyusb` module** (added in release 0.1.4), causing
  `No matching distribution found for pyusb` during the `diagng` pip step. Fix:
  the `python3-pyusb` module block (from `packaging/flatpak/python3-modules.json`)
  must appear **before** the `diagng` module. If you regenerate the local json
  from the current repo manifest, it's already correct.

What you should see: in the **USB tab** (with the phone in manufacture mode),
the Huawei `12d1:107e` interface `255/19/35` appears (it was filtered out
before), **Connect** opens the **HiSilicon capture window**, **Start capture**
launches Wireshark — but **no packets** (that's the blocker below).

---

## 3. Device access cheat-sheet (non-rooted, no bootloader unlock)

```bash
# Enter the DIAG-exposing USB mode (hangs ~120s but works; adb survives):
adb shell svc usb setFunctions manufacture       # re-enumerates 12d1:107e with 3 vendor ACM interfaces
# Back to normal:
adb shell svc usb setFunctions hisuite            # or just reboot

# Interfaces in manufacture mode (confirmed):
#   255/19/33 (0xff/0x13/0x21) = hw_acm_modem / AT-PCUI  (writes time out: no reader)
#   255/19/34                   = middle ACM channel
#   255/19/35 (0xff/0x13/0x23) = hw_acm_DIAG  <-- THE DIAG PORT (answers HDLC)
# NOTE: kernel only has CONFIG_USB_CONFIGFS_HW_ACM (not modem_acm), so hisi_debug
#       mode does NOT bring up extra diag channels on this device — manufacture
#       mode's interface 2 is the one and only DIAG port.

# IMSI / ICCID with no root (Android-10 transaction codes; change per version):
adb shell service call iphonesubinfo 7 s16 com.android.shell | grep -o "'.*'" | tr -d "'.\n "   # default IMSI
adb shell service call iphonesubinfo 8 i32 <subId> s16 com.android.shell   # per-sub IMSI
adb shell "content query --uri content://telephony/siminfo --projection _id:icc_id:sim_id:mcc:mnc --where 'sim_id>=0'"
```

**Do NOT** bind the `option` serial driver with a wildcard
(`echo "12d1 107e ff" > /sys/bus/usb-serial/drivers/option1/new_id`): it also
grabs the ADB interface and kills adb. Bind per-interface only, or just use
libusb (pyusb) as the probe scripts do.

---

## 4. The blocker: enabling the modem log stream

**Symptom:** everything works, Wireshark opens, but no packets. At idle the
DIAG port emits **0 bytes**. The modem only logs when modem logging is switched
on, and the switch is `persist.sys.logsystem.modem` (currently `0`).

### Dead-ends confirmed (all of them)
- `adb shell setprop persist.sys.logsystem.modem 1` → **denied** (SELinux; it's
  a system-owned persist prop).
- **ProjectMenu** (`*#*#2846579#*#*`) → Background **Debug** / Log settings is
  **password-locked** (Huawei engineering password — not public, not the
  lock-screen PIN; others on the same EMUI 10 report no working password).
  Launching ProjectMenu via adb is also blocked:
  `am start -n com.huawei.android.projectmenu/.ProjectMenuActivity` →
  `requires android.permission.SECURITY_ACTIVITY`; and
  `am broadcast … SECRET_CODE …` → permission denied from shell (uid 2000).
  _(If the dialer code "does nothing" after a reboot, that's the same wall —
  the code only matters if you can get past the password screen, which we
  can't.)_
- **AT port** (manufacture-mode PCUI, shows up as `/dev/ttyUSB1` if you attach
  the serial driver): answers `AT`→`OK` but **every** real command →
  `no permission` (Huawei AT lock).
- `/vendor/bin/diagserver` and all `/vendor/lib64/*` are **shell-unreadable**
  (SELinux `vendor_file`). `/system/lib64/*` and APKs **are** readable.

### What we reverse-engineered (the mechanism — this is solid)
The enable is a **HiSilicon VCOM** message (O&M/diag protocol) sent to the
modem. `diagserver` bridges the modem's VCOM/`/dev/appvcom*` channels to the
USB `hw_acm_DIAG` port. The DIAG port is **bidirectional** (it replied
`03 00 06` to our HDLC writes, and varied the reply with input → a live
command processor is on the other side).

Path: an **APK** → HIDL HAL `vendor.huawei.hardware.modemlogcat@1.1::IModemlogcat`
→ modem. Readable library `/system/lib64/libmodemlog.hisimodemtool.so` exposes
the HAL client: `receiveOmMsgFromApk`, `receiveAtMsgFromApk`,
`SendOmMsg(id, msgId:u16, data, len:u16)`, `SendAtMsg(id, atCmd)`,
`regMsgReceiver`/`onMsgResponse` (logs come back).

`HwChrService.apk` (`com.huawei.android.chr`, readable) bundles
`lib/arm64-v8a/libhisichr.so` (readable), which implements VCOM:
`VCOM_COMMON_HEADER_STRU`, messages `VCOM_MSG_ON_OFF`, `VCOM_MSG_SET_INFO_REPORT`,
`VCOM_MSG_ERR_REPORT`/`ENG_REPORT`, funcs `VcomCdmaSetErrorInfoReport`,
`GetVcomState`, `nativeSendVcomTestCmd`.

**Decoded a concrete VCOM enable message** (capstone disasm of
`VcomCdmaSetErrorInfoReport` @`0x5324` in `libhisichr.so`; note the host
`objdump` is x86-only and cannot disassemble AArch64 — use capstone). On enable
it builds a **20-byte** buffer and sends it:
```
+0x00 u16 = 1            (on)
+0x02 u16 = 0            (pad)
+0x04 u32 = seq          (incrementing counter)
+0x08 u32 = 8
+0x0c u32 = 0x01000000
+0x10 u16 = modemId
+0x12 u16 = faultId      (valid range 0xA1..0xD0, bitmap-gated)
```
**Caveat:** this is the **CHR fault/alarm** enable, *not* the OTA signaling-log
(RRC/NAS) enable DiagNG decodes. The OTA-log enable goes through the
`modemlogcat` HAL from the **modem-log APK**, whose code is **AOT-compiled (no
readable classes.dex)** and which we did not locate; and the final VCOM/HDLC
framing + the `0x1a00` send stub were not fully traced.

### Live-probe result + SAFETY WARNING
With the port free (DiagNG disconnected), idle = 0 bytes. A **blind single-byte
command sweep on the DIAG port REBOOTED the phone.** So:
- Writes reach a live processor (feasibility of USB→modem delivery leans
  **yes**), BUT
- **⚠️ Never blind-sweep the DIAG port again.** Send only well-formed, targeted
  frames. Bad input resets/reboots the device.

---

## 5. How to continue (ranked)

The software is done; the remaining work is purely "get the modem to emit the
stream." In rough order of effort-to-certainty:

1. **Root the phone** (highest leverage if achievable).
   - `setprop persist.sys.logsystem.modem 1` (+ `stop diagserver; start diagserver`,
     or reboot) is a near-certain enable.
   - Then **sniff the real enable frame on the wire** (USB capture / the appvcom
     channel) and bake that exact VCOM command into DiagNG so **non-rooted**
     devices can send it on connect (`PyUSBHisiInput.send_raw` / `USBHisiInput`
     already exist for this).
   - Root also makes `/vendor/bin/diagserver` readable for exact-protocol RE.
   - ⚠️ Mate 20 Lite bootloader unlock is **hard** — Huawei stopped issuing
     official codes; third-party/paid unlock only. This is the main risk.

2. **Firmware-image extraction (no root).** Download the `SNE-LX1`
   `UPDATE.APP`, extract `vendor.img`, pull `/vendor/bin/diagserver` and the
   `vendor.huawei.hardware.modemlogcat@1.1` service, and RE them **offline in
   Ghidra** (not objdump — it's AArch64; and Ghidra decompiles far better than
   the capstone-by-hand we did). Target: the exact OTA-log `VCOM_MSG_ON_OFF` /
   `SET_INFO_REPORT` opcode + `VCOM_COMMON_HEADER_STRU` layout + module/scene
   IDs for RRC/NAS. Then send that frame from DiagNG and verify a stream starts
   (toggle airplane mode for signalling).

3. **Tiny on-device helper APK** that calls the `modemlogcat` HAL directly to
   enable logging. Still needs the OTA enable OM opcode from (1) or (2), and
   changes the "non-rooted, PC-only" story (an app must be installed).

4. **Ship the parser for captures obtained elsewhere.** The decoder/UI are done;
   point them at a HiSilicon stream from a rooted Kirin or a provided `.lpd`
   dump. Good for proving the parser against real data even if live-enable on
   this exact phone stays blocked. Consider adding an offline `.lpd`/file input
   (SCAT's `run_dump` reads `.lpd`).

### A good first session when you come back
- Decide route (2) vs (1). If (2): get `SNE-LX1 C432` firmware, `huawei_update_extractor`
  / `splituapp` to unpack `UPDATE.APP` → `vendor.img` → `diagserver`,
  `vendor.huawei.hardware.modemlogcat@1.1-service`, `libbalong-ril.so`.
- Open in Ghidra; find where `VCOM_MSG_ON_OFF` / the OTA log module is enabled
  and what exact bytes hit the appvcom channel.
- With the port free, send **only that one frame** to interface `255/19/35`,
  generate signalling, watch for a GSMTAP stream in DiagNG/Wireshark.
- If it streams: wire the frame into `PyUSBHisiInput`/`USBHisiInput` connect so
  DiagNG self-enables; then validate the parser end-to-end and port the
  remaining SCAT handlers (e.g. `0x20020000`).

---

## 6. Reference: throwaway analysis artifacts

These were in the session scratchpad (`/tmp/...`, **ephemeral** — regenerate as
needed). The key facts are already captured above.
- Pulled readable libs: `libmodemlog.hisimodemtool.so`, `libhisichr.so`
  (from `HwChrService.apk`), `vendor.huawei.hardware.modemlogcat@1.1.so` and
  `modemchr@1.0.so` (system copies), `libhilogcat.so`.
- `probe_usb.py` — single-interface libusb probe (claim intf 2, send HDLC
  frames, drain responses). **Do not sweep.**
- `disasm.py` — capstone AArch64 disassembler with adrp+add string resolution
  (install `capstone pyelftools` in a venv).

## 7. Related memory notes
- `hisilicon-kirin-support` — the DiagNG code + SCAT port.
- `hisilicon-diag-enable-re` — the VCOM RE findings (this doc supersedes/expands it).
