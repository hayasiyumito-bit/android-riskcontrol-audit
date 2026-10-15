> **English** | [简体中文](../zh/03-risk-grading.md)

# Risk Grading Model

> Core formula: **risk level = signal certainty × kill-chain completeness**.
> When auditing an app, do not only look at "what is detected" but also at "**whether the grading is reasonable**" — misjudging a single signal as high risk harms real users and is a common defect.

---

## The three tiers: general principle

| Tier | Criterion | Typical |
|----|------|------|
| **High (conclusive / direct action)** | A certain cheating environment, **or** a complete "tool + disguise/injection" chain | Cloud phone, emulator, device-tampering fraud, device-farm operation, Frida injection + disguise |
| **Medium (suspected / needs manual review / re-verification)** | A tool/capability present, but no complete kill chain formed | Root without injection, framework without disguise, isolated injection trace, app cloning |
| **Low (report only / cluster)** | A single-point environment anomaly, common for developers/power users | Plain adb, plain VPN/proxy, mock location, bootloader unlock |

Mnemonic: **"environment certain" or "tool + disguise/injection" → high; "tool only" → medium; "toggle anomaly only" → low.**

---

## Key: what counts as "conclusive high risk" vs "merely suspected"

This is the easiest place to go wrong in an audit. **Finding the mere "existence" of a tool/framework/injection should not be reported as high-risk red outright.**

### Conclusive high risk (cross-layer evidence of disguise/tampering)
- Fingerprint **cross-layer inconsistency** (file/native layer ≠ Java layer): near-zero false positives, the strongest.
- Property-area ground truth ≠ in-process read / multi-channel property inconsistency: active spoofing evidence.
- A system-critical file replaced by a bind-mount (mount injection): an active spoofing mechanism.
- boot state spoofed (getprop ground truth ≠ in-process).
- Confirmed emulator/VM/cloud phone (multi-signal fusion, not a single sensor).

### Merely suspected (a single "existence" signal of a tool/framework/injection → manual review, not reported red on its own)
- A hook framework / LSPosed / Xposed-type **present** (no accompanying disguise confirmed).
- An **injection trace** hot-loaded from code_cache (note: hotfix frameworks Tinker/Sophix and packer shells also load from the data directory, so this **will false-positive** and must be disambiguated by "is it a foreign identity," see below).
- Root / Magisk / su **present**, but fingerprint consistent, no injection, no disguise.
- A framework signature matched by name (defeated by a rename).
- Detection under adversarial pressure (except_error / placeholder): WATCH, route to manual.

### Why "injection present" defaults to merely suspected
Loading code from the app's own `code_cache` is **not rare in legitimate scenarios**: mainstream hotfix frameworks (Tinker, Sophix, Robust, etc.), pluginization frameworks (RePlugin, Shadow, etc.), and commercial packer shells (which drop the decrypted real dex into the data directory and then load it) all do this. "Loaded from code_cache" alone cannot distinguish injection from a hotfix → **false positive**.

**Conditions to disambiguate and escalate to conclusive** (after excluding hotfixes):
- The injected payload is a **foreign-package** APK/class (containing a package name not belonging to this app);
- the dex has an **Xposed entry point** (`IXposedHookLoadPackage` etc.);
- it correlates with an LSPosed detection from sepolicy;
- it is accompanied by a fingerprint cross-layer mismatch.
Any one satisfied → escalate from suspected to conclusive.

---

## Multi-signal fusion (anti single-point collateral)

- **Every single rule has false positives** (custom ROMs, tablets, developer devices); use **weighted scoring + a threshold**, not a single-point hard block.
- Document-level rule: **≥2 medium-risk hits → escalate to high risk / trigger strong verification**.
- Measured lesson: the sensor anomaly **alone** has only ~62% precision and ~10% collateral → **never trigger aggressive actions on its own** (feeding fakes/cutting network/banning); it may only participate as a bonus term in a combined verdict.

---

## Grading → response (feeds active defense)

| Confidence tier | Strongest permitted response |
|--------|--------------|
| **L3 high confidence** (injection+disguise / root+tampering / malicious accessibility+clustering) | Feed fake data, cut the key interface's network, intercept (this tier only) |
| **L2 medium confidence** (root only / framework without disguise / single-signal emulator / app cloning) | Feature degradation, forced server-side re-verification, silent tagging |
| **L1 low confidence** (plain adb/vpn/proxy/mock / single sensor) | Silent reporting only, no client-side action |

> Aggressive actions (feed fakes/cut network/intercept) are permitted at L3 only, and must be gradually rollable, one-click reversible, and precisely scoped to a device cluster — **better to under-defend than to wrongly harm a real user**.

---

## For auditing: grading-reasonableness checklist

- [ ] Is "detected Hook/LSPosed/injection" judged directly as high-risk red? (It should be suspected, unless there is disguise corroboration.)
- [ ] Is fingerprint cross-layer inconsistency correctly judged as high risk?
- [ ] Is a sensor / single environment toggle used on its own to drive aggressive action? (It should not be.)
- [ ] Is there "≥2 medium → high" accumulation logic?
- [ ] Are except_error / placeholder values silently swallowed? (They should enter WATCH.)
- [ ] Are aggressive responses limited to L3 and gradually rollable/reversible?
