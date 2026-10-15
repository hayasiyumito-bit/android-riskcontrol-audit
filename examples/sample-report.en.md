# Example: Device Risk-Control Detection Coverage Audit Report for an App (sample)

> This is a **fictional sample** illustrating what a report produced by the `SKILL.md` workflow looks like. The target app uses the placeholder name `com.example.app`.

## 1. State overview
- Covered: Root (path/package name), emulator (properties), Hook (maps name matching), location (mock provider).
- Partially covered: fingerprint (Java `Build` only, no cross-layer check).
- Missing: in-process integrity, cross-layer ground-truth reads, cloud-phone sensors, hardware attestation, server-side backstop.
- Primary layers relied on: **almost entirely the Java layer**; native is just one shallow-detection .so; no server-side cross-check.

## 2. Coverage matrix
| Dimension | Status | Which layer | Which evasion breaks it | Severity |
|------|------|---------|----------------|--------|
| Root | partial | Java | Shamiko hides paths/packages → fails; no socket/namespace/attestation | high |
| Hook | partial | Java/Native | Framework randomizes names → name matching fails; no rwx/CRC/integrity | high |
| Emulator | yes | Java | Bypassed by newer ARM cloud phones | medium |
| Cloud phone | no | — | No sensor/soft-render/container detection | high |
| Fingerprint spoofing | partial | Java | Reads only Build, no file/native cross-check → device tampering fully evades | critical |
| In-process integrity | no | — | Arbitrary dex/so injection goes unnoticed | high |
| Cross-layer ground truth | no | — | No way to cross-check mount/property spoofing | high |
| Location | partial | Java | Only checks mock; GMS fusion / server-side consistency missing | high |

## 3. Gap list (by priority)
1. **[critical] Structural**: no Play Integrity, no server-side backstop — client self-checks always lose to an injector. → Integrate STRONG_INTEGRITY (server-side nonce verification) + a server-side behavior/graph backstop.
2. **[critical] Fingerprint has no cross-layer check**: reads only Java `Build`, so one tampering change evades everything. → Add `getprop` subprocess / file-layer / property-area ground truth and cross-check against the Java layer; any inconsistency is high risk.
3. **[high] Names only**: Hook/Root rely entirely on name/path matching, defeated by a rename. → Switch to structural/behavioral criteria (rwx pages, text CRC, sockets, namespaces).
4. **[high] No in-process integrity**: → Enumerate classloader dexElements/native path provenance and cross-check against maps (and state its ceiling).
5. **[high] Location source blind spot**: only checks the mock provider, misses GMS fusion and server-side consistency. → Server-side IP↔timezone↔GPS cross-check.

## 4. .so / SDK findings
- Bundled `libxxx.so`: contains only root-path/qemu property strings, **no** svc direct read, no integrity verification, no cross-layer → shallow detection, a source of high gaps.
- No commercial risk-control SDK identified; traces of a hotfix framework detected → note: it is a legitimate false-positive source for "injection detection," so if in-process integrity detection is added later it must be disambiguated via an allowlist.

## 5. Grading-reasonableness issues
- "Detected su path" is judged high-risk red outright → should be downgraded to **suspected** (root only present, no disguise).
- No "≥2 medium → high" accumulation logic.
- Detection anomalies (read failures) are silently swallowed, not routed to WATCH.

## 6. Improvement roadmap
- **Now**: integrate Play Integrity + server-side nonce verification; add `getprop` subprocess cross-check for fingerprint.
- **Short term**: switch Root/Hook to structural/behavioral criteria; grading distinguishes conclusive/suspected + accumulation.
- **Mid-to-long term**: in-process integrity + server-side behavior/graph backstop; push the .so down to svc direct reads and integrity verification.

---
> Machine-readable results: see the accompanying filled-in `coverage.yaml` (status/where/notes per dimension).
