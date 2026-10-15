<!-- Language: **English** | [简体中文](README.zh-CN.md) -->

# Android Risk-Control Detection Audit Kit

**English** | [简体中文](README.zh-CN.md)

> AI-assisted auditing of an Android app's **device risk-control / anti-fraud detection** for coverage **gaps**.
> For app developers, risk and security teams — **defensive use only**.

## What this is

Modern apps rely on device risk-control SDKs to identify high-risk environments: Root/Magisk, hook/injection frameworks (Frida/Xposed/LSPosed), emulators, cloud phones, device-fingerprint spoofing, device farms, app cloning, refurbished/IMEI-changed devices, and more. Attackers continuously develop new **evasions** to slip past these checks.

This kit packages — as a **knowledge base + checklist + Python scripts** — *which detection dimensions exist, which known evasions apply to each, what you should therefore detect, and how to grade/score findings*. An AI (or a human) uses it to audit a target app:

- **Review the app's own code** — which dimensions does its detection cover? Is the grading sane?
- **Review bundled .so / third-party SDKs** — what do they actually detect? Any "integrated but a hole left open"?
- **Find gaps** — against the *evasion → required detection* mapping, which attack vectors can't currently be caught.

Output: a **detection-coverage audit report** (covered / partial / missing per dimension + prioritized fixes).

## What this is NOT

- ❌ Not an evasion/bypass tool. It contains **no** code to evade detection or spoof a device.
- ❌ It does not write your risk SDK for you — it audits coverage and points out gaps.
- Every "evasion" in the knowledge base is written **defensively**: *attackers do X → therefore you should detect Y.*

## For AI assistants

- **`SKILL.md`** — the audit workflow as a skill (entry point for Claude / Cursor / other agents).
- **`AGENTS.md`** — repo-level rules AI assistants should follow here.
- **`checklist/coverage.yaml`** — machine-readable 12-dimension + structural checklist to fill in.

## Layout

```
SKILL.md                    # AI audit workflow (skill)
AGENTS.md                   # rules for AI assistants
checklist/coverage.yaml     # machine-readable coverage checklist
docs/
  en/ 01..05                # English knowledge base
  zh/ 01..05                # 中文知识库
prompts/
  audit-prompt.en.md        # ready-to-paste audit prompt (EN)
  audit-prompt.zh.md        # 审查提示词(中文)
scripts/
  apk_static_scan.py        # APK static scan: perms / components / .so / SDK
  so_symbols.py             # .so capability profile: JNI exports + detection signatures
  sdk_fingerprint.py        # detect bundled risk / hardening / hotfix SDKs
  coverage_checklist.py     # scan.json -> coverage report skeleton
examples/sample-report.md   # sample audit report
reference/                  # risk-grading methodology docs (zh)
```

Knowledge base:
- `docs/*/01-detection-dimensions` — all detection dimensions (root/hook/emulator/cloud/fingerprint/injection/location/integrity/...).
- `docs/*/02-evasion-vs-detection` — **core**: evasion → required detection (how to find gaps).
- `docs/*/03-risk-grading` — grading model (signal certainty × kill-chain completeness).
- `docs/*/04-so-sdk-audit` — auditing bundled .so / third-party SDKs.
- `docs/*/05-server-and-attestation` — the real backstop: hardware attestation + server-side.

## Quick start

```bash
pip install -r scripts/requirements.txt       # androguard is optional
# 1) Static scan an APK -> .so / SDK / permission inventory
python scripts/apk_static_scan.py target.apk -o out/scan.json --extract-libs out/libs
# 2) Profile each .so (JNI exports + detection signatures)
python scripts/so_symbols.py out/libs/*.so
# 3) Identify bundled risk / hardening / hotfix SDKs
python scripts/sdk_fingerprint.py target.apk
# 4) Coverage report skeleton
python scripts/coverage_checklist.py out/scan.json -o out/coverage.md
```

Then hand `out/` + `docs/` + `checklist/coverage.yaml` to an AI and follow `SKILL.md` to produce the coverage report.

## Reference detector (optional companion)

An open-source **device-info collection / detection reference app** (package `com.android.device`) implements many of these checks as a runnable, on-device detector with live verdicts — handy to validate "can this check actually catch it on a real device".

- Repository: `<fill in the reference app's git URL here>`

> The two projects are independent; the app is cited only as a runnable reference.

## Scope & compliance

- Intended use: **defensive coverage audit of apps you own or are authorized to assess.**
- Contains and produces **no** detection-evasion or device-spoofing capability.
- Knowledge is drawn from public risk-control / anti-fraud detection research (see each doc's references).
