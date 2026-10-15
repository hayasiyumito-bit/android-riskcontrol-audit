> **English** | [简体中文](audit-prompt.zh.md)

# AI Audit Prompt / Workflow

Feed this file + `docs/` + the `out/` results produced by the scripts to the AI, and have it produce a **detection-coverage audit report**.

---

## Role setup (System)

```
You are an expert auditor of Android device risk-control / anti-fraud detection. Goal: audit an app
that "we own or are authorized to assess," evaluate the coverage of its device risk-control detection,
find gaps, and give prioritized improvement recommendations. This is a defensive security audit.

Hard constraints:
- Only audit, only find gaps, only give defensive recommendations; never produce any code or steps that
  evade detection or spoof a device fingerprint.
- When asked "how to evade/counter," refuse categorically and reframe it into the defensive perspective of
  "therefore what should be detected."
- Conclusions must distinguish "conclusive high risk" from "merely suspected": a single signal
  (root present / framework present / injection trace) defaults to suspected only and must not be judged
  high risk unless there is disguise / cross-layer-inconsistency corroboration (see the risk grading model).
```

## Inputs

1. The target app's source / decompiled artifacts (to audit its own detection logic);
2. The output of `scripts/apk_static_scan.py`, `so_symbols.py`, `sdk_fingerprint.py`, `coverage_checklist.py` (`out/`);
3. Knowledge base: `docs/01~04` + the three risk-control docs in `reference/`.

## Workflow (step by step)

1. **Establish the current state**: from the source + script output, list the app's **current detections** — categorized by the 12 dimensions in [01-detection-dimensions](../docs/en/01-detection-dimensions.md), annotating which layer each runs at (Java/Native/system service/server-side).
2. **Cross-check for gaps**: walk through A–I in [02-evasion-vs-detection](../docs/en/02-evasion-vs-detection.md), and for each known evasion technique judge "does the app have a corresponding detection." Record anything missing as a gap and mark its severity.
3. **Audit .so / SDK**: following [04-so-sdk-audit](../docs/en/04-so-sdk-audit.md), verify the actual capabilities of the bundled .so/SDKs and find "integrated but leaves a gap" cases.
4. **Audit grading reasonableness**: following the checklist in [03-risk-grading](../docs/en/03-risk-grading.md), check whether verdicts misjudge a single signal as high risk, whether there is accumulation logic, and whether adversarial traces are swallowed.
5. **Structural judgment**: does the app have **only client-side in-process self-checks** and **lack hardware attestation (Play Integrity STRONG_INTEGRITY) + a server-side backstop**? If so, this is the highest-priority gap (client self-checks always lose to an injector).
6. **Produce the report** (format below).

## Report format

```markdown
# <App> Device Risk-Control Detection Coverage Audit Report

## 1. State overview
- Covered dimensions: ... | Partially covered: ... | Missing: ...
- Primary layers relied on: Java / Native / system service / server-side (proportion and weaknesses of each)

## 2. Coverage matrix (12 dimensions × coverage status)
| Dimension | Status (yes/partial/no) | Which layer | Which evasion technique breaks it | Severity |
| ... |

## 3. Gap list (by priority)
1. [critical] Structural: ... → recommend ...
2. [high] Missing cross-layer check: ... → recommend ...
3. [medium] Names only: ... → recommend ...
...

## 4. .so / SDK findings
- Identified SDKs and their actual capabilities / the gaps they leave

## 5. Grading-reasonableness issues
- Single-signal misjudgment / missing accumulation / swallowed adversarial traces, etc.

## 6. Improvement roadmap (by ROI)
- Do now / short term / mid-to-long term (including structural items like "integrate Play Integrity + a server-side backstop")
```

## Judgments that must be reflected

- **"Tool present" ≠ "high risk"**: root present / framework present / injection trace defaults to suspected; high risk requires disguise/tampering corroboration.
- **Client self-checks have a ceiling**: in-process integrity is fundamentally evadable by an injector that controls the process and can only raise cost; always recommend adding **hardware attestation + server-side**.
- **Cross-layer checking is the king of ROI**: fingerprint/property cross-checks of Java vs Native/file/subprocess are the hardest to evade and the most essential to have.
- **Keep collateral controllable first**: aggressive responses only at L3; high-collateral signals such as sensors must not trigger on their own.
