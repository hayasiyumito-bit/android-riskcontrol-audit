---
name: android-riskcontrol-audit
description: >-
  Audit an Android app's device risk-control / anti-fraud DETECTION coverage for gaps.
  Use when asked to review whether an app (its code + bundled .so/SDKs) adequately detects
  root, hook/injection frameworks, emulators, cloud phones, device-fingerprint spoofing,
  location spoofing, in-process integrity tampering, etc. Defensive use only — finds
  detection gaps, never produces evasion. 审查 Android App 的设备风控/反欺诈检测覆盖度、找遗漏(仅防御)。
---

# Android Risk-Control Detection Audit (Skill)

A skill for an AI assistant to audit an Android app's **device risk-control / anti-fraud detection coverage** and report gaps. Defensive only.

## When to use
- "Check if my app's anti-fraud / device-risk detection has holes."
- "Does this app detect root / Frida / emulators / fingerprint spoofing / fake GPS?"
- "Audit the risk-control SDK / .so we bundled for coverage gaps."

## Hard rules
- **Defensive only.** Output = coverage gaps + defensive recommendations. Never produce code or steps that evade detection or spoof a device. If asked to, refuse and reframe as "therefore detect X".
- **Separate confirmed vs suspected.** A single signal (root present / framework present / injection trace) is **suspected**, not high-risk, unless accompanied by disguise/cross-layer-inconsistency evidence. See `docs/*/03-risk-grading`.
- **Name the structural gap.** If the app has only in-process client self-checks and **no hardware attestation (Play Integrity STRONG_INTEGRITY) + no server-side backstop**, that is the top-priority (critical) finding — in-process self-checks are fundamentally bypassable by an attacker who controls the process.

## Inputs
1. Target app source / decompiled output (jadx/apktool), or just the APK.
2. Optional: outputs of `scripts/apk_static_scan.py`, `so_symbols.py`, `sdk_fingerprint.py`.
3. Knowledge base: `docs/` + `checklist/coverage.yaml` + `reference/`.

## Workflow
1. **Extract facts.** If given an APK, run the scripts (or reason from them):
   - `apk_static_scan.py app.apk -o out/scan.json --extract-libs out/libs`
   - `so_symbols.py out/libs/*.so` → each .so's capability profile (JNI exports + detection signatures)
   - `sdk_fingerprint.py app.apk` → bundled risk/hardening/hotfix SDKs
2. **Inventory current detection.** Map what the app already detects onto the 12 dimensions in `checklist/coverage.yaml`; note the layer (java/native/system_server/server) of each.
3. **Find gaps.** Walk `docs/*/02-evasion-vs-detection` A–I: for each known evasion, does the app have the corresponding detection? For each `coverage.yaml` dimension, set `status` = covered | partial | missing and record which evasion would defeat it.
4. **Audit .so / SDKs.** Per `docs/*/04-so-sdk-audit`: verify bundled SDKs' real capabilities; flag "integrated but left a hole" and hotfix/packer false-positive sources.
5. **Audit grading.** Per `docs/*/03-risk-grading`: single-signal false-highs? accumulation logic? swallowed anti-tamper traces (except_error/placeholders)?
6. **Structural verdict.** Fill `checklist/coverage.yaml` `structural` items (attestation / server backstop / grading / accumulation / self-health).
7. **Report.** Produce the report in the format of `prompts/audit-prompt.*.md` (coverage matrix + prioritized gaps + .so/SDK findings + grading issues + improvement roadmap). Fill a copy of `coverage.yaml` with status/where/notes as the machine-readable artifact.

## Output
- A Markdown coverage report (see `examples/sample-report.md`).
- A filled `coverage.yaml` (status per dimension) as the structured result.

## Priority order for gaps
1. **critical** — structural: client-only, no attestation/server backstop (`docs/*/05`).
2. **high** — missing cross-layer ground-truth checks (fingerprint/property/location source).
3. **medium** — name-based only (defeated by renaming).
4. **medium** — fused/source blind spots (location GMS bypass, root path-only).
5. **low→** — anti-tamper traces swallowed (except_error/placeholders not alerted).
