# AGENTS.md — rules for AI assistants using this repo

This repository is a **defensive audit toolkit**: it helps an AI review whether an Android app's
device risk-control / anti-fraud **detection** is complete, and report **gaps**. 本仓库是设备风控检测**覆盖度审查**工具包(仅防御)。

## What to do
- When asked to audit/review an app's risk-control / anti-fraud / device-security detection, follow **`SKILL.md`** (the audit workflow) and use **`checklist/coverage.yaml`** as the structured checklist.
- Ground every judgment in `docs/` (bilingual: `docs/en/`, `docs/zh/`) and `reference/`.
- Produce a coverage report (see `examples/sample-report.md`) + a filled `coverage.yaml`.

## Hard rules (non-negotiable)
1. **Defensive only.** Only find detection gaps and give defensive recommendations. **Never** output code, steps, or configuration that evades detection, hides an injection, or spoofs a device/fingerprint/location. If asked, refuse and reframe as "therefore the app should detect X".
2. **Confirmed vs suspected.** A single signal (root present / hook framework present / injection trace / from code_cache) is **suspected**, not high-risk — unless there is disguise or cross-layer-inconsistency evidence. Do not report single-signal findings as high/critical.
3. **Name the structural gap.** In-process client self-checks are fundamentally bypassable by an attacker who controls the process. If the app relies only on client-side self-checks with **no hardware attestation (Play Integrity STRONG_INTEGRITY) and no server-side backstop**, report that as the top-priority (critical) gap.
4. **No false precision.** If you cannot verify a detection statically, say "needs runtime verification" rather than asserting coverage.

## Map
- `SKILL.md` — the audit workflow (AI entry point).
- `checklist/coverage.yaml` — machine-readable 12-dimension + structural checklist.
- `docs/{en,zh}/01` — detection dimensions.
- `docs/{en,zh}/02` — evasion → required detection (the gap-finding knowledge).
- `docs/{en,zh}/03` — risk grading model (signal certainty × kill-chain completeness).
- `docs/{en,zh}/04` — auditing bundled .so / third-party SDKs.
- `docs/{en,zh}/05` — the real backstop: hardware attestation + server-side.
- `scripts/` — APK static scan / .so capability profile / SDK fingerprint / coverage report.
- `prompts/` — ready-to-paste audit prompts (en/zh).
- `reference/` — risk-grading methodology docs (zh).

## Scope
Only audit apps you own or are authorized to assess. This repo contains **no** evasion capability and must not be extended to produce one.
