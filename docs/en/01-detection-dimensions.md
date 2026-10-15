> **English** | [简体中文](../zh/01-detection-dimensions.md)

# Detection Dimension Checklist

When auditing an app's device risk control, walk through each dimension and verify: **is there a detection, at which layer does it run, and can it be trivially bypassed?**
For every dimension we give: the **signal** (how it is judged), the **layer** (Java / Native / system service / cross-layer), and the **common gaps**.

> For how findings are graded, see [03-risk-grading.md](03-risk-grading.md); for the per-dimension evasion techniques and the detections you should have, see [02-evasion-vs-detection.md](02-evasion-vs-detection.md).

---

## 1. Root / Magisk / KernelSU / APatch

| Signal | Layer | Notes |
|------|----|------|
| `su` binary paths, Magisk paths/packages, `which su` | Java/Native | Basic; easily hidden by the denylist |
| magisk/zygisk sockets in `/proc/net/unix` | Native | Strong trace the denylist cannot hide |
| mount/namespace inconsistency, mount traces in `/proc/self/mountinfo` | Native | Still queryable after Shamiko hiding |
| SELinux set to Permissive/Disabled | Java/Native | Weak single-point signal |
| Play Integrity `MEETS_STRONG_INTEGRITY` | Server-side verification | **Strongest**; hardware-backed, cannot be forged by root |

**Common gaps**: only checking paths/package names (defeated the moment the denylist hides them); not checking sockets / namespaces / Play Integrity.

## 2. Hook / Injection frameworks (Frida / Xposed / LSPosed / in-house)

| Signal | Layer | Notes |
|------|----|------|
| Framework signature strings in `/proc/self/maps`, Frida ports 27042/27043 | Native | Names can be randomized |
| Inline-hook on the first bytes of key functions, `.text` segment CRC check | Native | Catches inline hooks; restoring the permission bits does not help the attacker evade |
| Executable mappings loaded from a non-app install directory (dirty page) | Native | Generic signature of an injected `.so` |
| Classloader integrity: foreign sources in `dexElements`/`nativeLibraryPathElements` | Java (cross-layer) | See dimension 9 |
| Code integrity: APK signature / DEX·SO verification | Java/Native | Defends against repackaging |

**Common gaps**: matching only on framework **names** (defeated by a rename); no structural/behavioral detection; no classloader identity-level integrity.

## 3. Emulator (QEMU / Goldfish / x86 VM)

| Signal | Notes |
|------|------|
| `ro.kernel.qemu`, `ro.hardware`=goldfish/ranchu/vbox, sdk_gphone model | Obvious properties |
| `/dev/qemu_pipe`, `/dev/socket/qemud`, genyd, `bluestacks.prop` | Dedicated nodes |
| ARM on x86 + translation layer libhoudini / libndk_translation | CPU architecture anomaly |
| Placeholder identifiers (getDeviceId all zeros, fixed android_id) | |

**Common gaps**: only checking properties, not device nodes/translation layers; insufficient coverage of newer ARM emulators (non-x86).

## 4. Cloud phone (redroid / Docker-ARM)

| Signal | Notes |
|------|------|
| Sensors missing / all zeros / flat with no variation over time (no physical chassis) | **Strongest basis**: no real hardware |
| No baseband, radioVersion=unknown + SIM ABSENT | |
| Software GPU rendering (SwiftShader / LLVMpipe / VirGL / virtio_gpu) | Containers have no real GPU |
| `/proc/1/cgroup` contains docker, overlayfs, `ro.kernel.qemu` | Container traces |
| Server CPU (Ampere Altra / Graviton / Xeon / EPYC) | |

**Common gaps**: the sensor signal alone has a high false-positive rate (measured precision ~62%, collateral ~10%), so it **must not drive a verdict on its own** and must be fused with multiple signals.

## 5. Device tampering / fingerprint spoofing (core)

| Signal | Notes |
|------|------|
| **Cross-layer fingerprint inconsistency**: `file_* / native` layer ≠ `Build` (Java) layer | **Best cost/benefit and hardest to evade**; the key to a verdict |
| Multi-channel property inconsistency: getprop subprocess / SystemProperties / JNI / on-disk property-area ground truth contradict each other | |
| build.prop modified, `ro.debuggable=1`, `ro.build.tags=test-keys` | |
| build.prop mtime anomaly (e.g. frozen at year 2009) | |

**Common gaps**: only reading the Java-layer `Build` (the easiest to hook); no Java vs Native/file cross-check; not reading via a `getprop` subprocess or reading build.prop directly (the attacker's `file_*` ground-truth technique). See dimension 10.

## 6. Malicious hook chain (framework + injection + business disguise)

Framework present + injected `.so`/`.dex` from a non-app path + disguised business logic/UA → high risk; framework present only → medium.
**Common gaps**: treating "framework present" as high risk outright (collateral damage to hotfix/packers); or conversely only checking "is there disguise" while ignoring the injection itself.

## 7. Device farms / automation (ADB / Accessibility)

| Signal | Notes |
|------|------|
| Malicious accessibility service + bulk clustering | |
| ADB-injected input events, ADB-TCP 5555 already connected, device-farm ports | |
| `ro.debuggable=1` / `ro.adb.secure=0` | |

**Common gaps**: `adb keyevent` is itself legitimate; a verdict must combine behavior + clustering, not a hard block on a single point.

## 8. Refurbished boards / IMEI respoofing / one-device-many-accounts / app cloning

| Dimension | Signal |
|------|------|
| Mainboard refurbishment | mainboard_tag + abnormal/zeroed IMEI + frequent "new device" |
| One device, many accounts | Same device identifier bound to a large number of accounts (server-side graph) |
| App cloning / dual-instance | duokai* markers, abnormal virtualpath, virtualization framework packages (VirtualApp etc.) |

## 9. In-process integrity (classloader / load provenance) ★

Modern injection stuffs an `.so`/dex into the host process and then loads it, leaving in-process structural traces:

| Signal | Notes |
|------|------|
| dex in the classloader's `dexElements` coming from a **non-install directory** (app-private writable dirs `/data/data`, `/data/user`) | Legitimate code loads only from the read-only install dir `/data/app` |
| `nativeLibraryPathElements` pointing to a writable directory | Where the injector's dlopen'd `.so` lands |
| `dalvik-classes*.dex extracted from <app-private code_cache>` in `/proc/self/maps` | The VMA name ART assigns; survives even after the file is deleted |
| Empty names / duplicate names / count greater than expected in dexElements | Someone tampered with the classloader metadata |

**Common gaps**: no in-process integrity self-check at all; or relying on a single dimension (the attacker can bypass them one by one, so you need multi-dimensional cross-checks).
**Key realization**: in-process self-checks fundamentally cannot stop **an injector that controls the process** (it can reflectively forge/remove any in-process structure); they only raise the cost. The **final line of defense is hardware attestation (Play Integrity STRONG_INTEGRITY) + server-side behavior/graph analysis**.

## 10. Cross-layer ground-truth reads (the attacker's file_* technique) ★

To obtain real-device values for a cross-check, attackers bypass in-process hooks and read from the lower layers:

| Ground-truth channel | What it reads | What you should therefore detect |
|---------|---------|----------------|
| fork+exec `/system/bin/getprop` subprocess | Reads properties in a separate process, bypassing this process's Java hooks | You should use the same technique to obtain ground truth for a cross-check |
| Reading the `/system/build.prop` file directly | File-layer ground truth | |
| inline-svc (raw syscall) reading `/proc/self/maps`, `/proc/self/mountinfo` directly | Bypasses hooks on libc open/read | Read directly via svc and compare against the libc read; a mismatch means it was filtered |
| Parsing the `/dev/__properties__` on-disk trie directly | Property-area ground truth vs in-process `__system_property_get` | |

**Common gaps**: all reads go through Java/libc (all within hook range); no cross-check via subprocess/svc/file layer.

## 11. Location spoofing

| Signal | Layer | Notes |
|------|----|------|
| `isFromMockProvider` / test provider | Java | Basic, easily evaded |
| LocationManager + fused location (FusedLocationProvider) output consistency | Java/server-side | |
| **GMS fused-location bypass**: coordinates are computed in the GMS process, so they must be checked at the system-service provider source or on the server | System service | Hooking only the app side misses them |
| Raw GNSS (GnssMeasurement / NMEA) high-precision back-derivation | | A spoofer will suppress raw GNSS |
| IP geolocation ↔ timezone ↔ GPS three-way consistency | Server-side | |

**Common gaps**: only checking the mock provider; not cross-checking IP/timezone/GPS consistency (server-side is the most robust).

## 12. Environment toggles (low risk; escalate only when combined)

ADB debugging, USB debugging, VPN, proxy, developer options, accessible data directory — individually low risk; escalate when ≥2 are combined or they accompany a high-risk dimension.

---

## Detection self-health (must-check during an audit)

- Detection fields returning `except_error` in bulk (the detection threw) = likely adversarial bypass → should alert separately and route to manual review.
- Core fields returning placeholder values at scale (e.g. `6666` / empty) = information is being blocked → a weak suspicious signal.
- Low-layer signals hit but the server-side aggregate labels are all zero = likely missed verdict / broken rule chain → recheck.
