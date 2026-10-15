> **English** | [简体中文](../zh/04-so-sdk-audit.md)

# Auditing .so Files and Third-Party SDKs

> An app's risk-control capability often lives half in its own code and half in the **.so files and third-party SDKs** it bundles. A common pitfall during an audit is to "assume it is safe because it integrates some risk-control SDK," whereas you must verify **which detections it actually provides** and whether it leaves gaps.

---

## 1. Audit the real capabilities of a bundled .so

Use `scripts/so_symbols.py` to extract each `.so`'s exported symbols + string signatures and judge what it does:

| What to look at | Notes |
|--------|------|
| **Exported JNI symbols** (`Java_...`) | Infer which detection methods it exposes to Java (e.g. `...getMagiskNativeProbe`, `...getInlineSvcMapsProbe`) |
| **String signatures** | Does it contain `/proc/self/maps`, `/proc/net/unix`, `magisk`, `qemu`, `frida`, `ptrace`, `su`, etc. → which dimensions it detects |
| **syscall / inline-svc traces** | Any direct reads bypassing libc (`svc #0`, raw openat/read) → whether it can "obtain ground truth around hooks" |
| **Anti-debugging** | `ptrace`, `TracerPid`, `/proc/self/status` → self-protection |
| **Code integrity** | Does it do `.text` CRC / signature verification |
| **Missing items** | Against [01-detection-dimensions.md](01-detection-dimensions.md), which dimensions this `.so` does not cover |

**Key point**: many "risk-control SDKs" only do shallow property/path-layer checks and **lack** cross-layer cross-checks, svc direct reads, and classloader integrity → those are the gaps at the `.so` layer.

---

## 2. Identify known risk-control / anti-fraud SDKs

Use `scripts/sdk_fingerprint.py` to identify bundled commercial risk-control SDKs by **package-name prefix / .so name / class name** (example signatures, not exhaustive):

| SDK category | Identifying signature (example) | Typical capability |
|---------|----------------|---------|
| Device fingerprint / anti-fraud | Specific so name / package prefix (varies by vendor) | Device fingerprint, root/emulator/hook detection, risk scoring |
| Packer shell | `libDexHelper`, `libjiagu`, `libshell`, `libpreverify`, etc. | Code protection (not risk control, but affects static audit) |
| Hotfix / pluginization | Tinker / Sophix / RePlugin classes/files | **Loads dex from the data directory** → a legitimate false-positive source for injection detection |
| Push / analytics | Collects device identifiers | A privacy-compliance concern |

After identifying an SDK:
1. Check the SDK's public docs/version and verify the detection dimensions it **claims**;
2. Against the checklist, the dimensions it **does not cover** are overall gaps;
3. If a packer shell is present, note that static analysis is limited and must be combined with dynamic/runtime verification.

---

## 3. Common pitfalls of "integrated an SDK = safe"

- **Only integrated fingerprint collection, not risk scoring**: the SDK only reports raw parameters while the verdict logic lives on the server — if the server rules are missing (e.g. low-layer signals hit but labels are all zero), the collection is wasted.
- **Outdated version**: an old SDK version covers new evasion techniques (newer ARM cloud phones, A14+ injection methods) insufficiently.
- **Wrong init timing / scope**: the risk-control SDK initializes after the key business flow, or does not cover all processes → leaves a window.
- **Over-reliance on a single layer**: only Java-layer detection, no native/server-side → see [sections E/F of 02](02-evasion-vs-detection.md).
- **No self-health monitoring of detection**: no awareness when the SDK is hooked and fed fakes (no alert on except_error).

---

## 4. Static audit workflow (with the scripts)

```bash
# 1) Unpack + manifest: permissions, components, .so list, dex count
python scripts/apk_static_scan.py target.apk -o out/scan.json

# 2) Capability profile of each .so
for so in out/libs/*.so; do python scripts/so_symbols.py "$so"; done

# 3) Identify bundled risk-control / packer / hotfix SDKs
python scripts/sdk_fingerprint.py target.apk

# 4) Coverage checklist → report (which dimensions have detection, which are missing)
python scripts/coverage_checklist.py out/scan.json -o out/coverage.md
```

Then hand the `out/` results together with the docs in this directory to the AI and produce a conclusion following [prompts/audit-prompt.en.md](../prompts/audit-prompt.en.md).

> Static analysis can only see "whether traces of these capabilities exist"; **whether it can actually catch the attack** must be verified on a real device (you can use the companion reference-collection app as a reference implementation).
