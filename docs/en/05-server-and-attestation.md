> **English** | [简体中文](../zh/05-server-and-attestation.md)

# The Real Line of Defense: Hardware Attestation + Server-Side

> This chapter is the "foundation" of the whole methodology. The previous four cover what the client can detect, how to find gaps, and how to grade;
> but the single most important question in an audit is: **does this app rely on client-side self-checks only?** If so, no matter how fine-grained the client is,
> it fundamentally cannot stop **an attacker who controls the process.**

---

## 1. Why client-side in-process self-checks will always lose

The attacker (root + injection/device-tampering) **fully controls the target process's memory and execution**. Any in-process data structure the client self-check reads — `Build` fields, `SystemProperties`, `/proc/self/maps`, the classloader's `dexElements`, `DexFile` fields — the attacker can:

- **reflectively forge** the read value (change `getName()` to a legitimate path);
- **physically remove** the trace (delete the injected dex element from the array, then hook `findClass` to fall back to loading from memory);
- **filter / feed fakes** to the detection function's inputs and outputs (hook libc `open/read` so maps/mountinfo read back a "clean" version).

This is not a poor implementation; it is a **structural ceiling**: in the attack-defense contest, every added in-process detection dimension can be matched by an added layer of forgery on the attacker's side; the defender's only advantage is "continuously adding orthogonal dimensions to raise cost," but it **can never be eliminated**.

> The audit conclusion must state this clearly, to avoid the false sense of security that "the client detection is thorough, so it is safe."

## 2. Two classes of defense "out of the attacker's reach"

### 1. Hardware-backed attestation

- The **Play Integrity API** `MEETS_STRONG_INTEGRITY` verdict is signed by the device's **TEE / StrongBox** with a hardware key; a root/tampered environment **cannot obtain** STRONG. Model and system integrity are vouched for by the hardware root of trust, which the spoofing layer cannot change.
- **Key Attestation** (Android Keystore) can prove the key was generated in hardware, the device bootloader state, etc.
- Limits: some older models / custom ROMs cannot obtain STRONG (the coverage vs collateral boundary must be assessed); the verdict must be **verified server-side** (the verdict the client receives can itself be tampered with, so carry a nonce and verify the signature on the server).

### 2. Server-side behavioral risk control + graph

- **Operation cadence / behavioral sequence**: independent of the client, the attacker's automation cadence and abnormal timing are visible server-side.
- **Device-account association graph**: one device many accounts, bulk from the same IP, device-fingerprint clustering — cross-device, cross-time consistency that no amount of clean client-side spoofing can evade.
- **Multi-dimensional consistency cross-check**: the client-reported `file_* vs java_*`, the Integrity verdict, and location ↔ IP ↔ timezone are re-cross-checked server-side; client signals serve only as reference (they can be tampered with).
- **Shadow ban**: for high-confidence attack sessions, return normally but do not record, keep feeding fakes, and strike by association, without revealing "you were detected" on the device.

## 3. The correct role of client-side detection

Client-side detection **is not useless**; its value is:

1. **Raise cost / prolong the contest**: force the attacker to invest on every upgrade, lowering the cost/benefit of industrialized abuse.
2. **Provide intelligence**: report device-side signals (even if forgeable) as **one input** to the server's aggregate score, not as the final verdict.
3. **Trigger graded responses**: low confidence only tags; high confidence (ideally with attestation/server-side corroboration) drives aggressive action.

In one sentence: **the client is responsible for "raising the bar + stopping losses + intelligence," while the final risk verdict and the approval of high-value operations rest with the server (+ hardware attestation).**

## 4. Audit checklist (the "gaps" this chapter maps to)

Verify each item against the target app:

- [ ] Does it integrate **Play Integrity** and use `MEETS_STRONG_INTEGRITY` as a strong signal for high-value operations?
- [ ] Is the Integrity verdict **verified server-side with a nonce** (rather than trusting the client's self-report)?
- [ ] Are high-value / irreversible operations forced through **server-side re-verification** (one-time nonce + server-side signature)?
- [ ] Is there a server-side backstop of **device-account graph / behavioral cadence / location consistency**?
- [ ] Are device-side reports used only as **reference**, not as the final basis for a verdict?
- [ ] Is key logic / are keys **pushed down to the server or hardware**, so the device does not hold the full key?

> If most of the above are "no," then no matter how many boxes the client detection checklist ticks, the overall risk control is still **structurally insufficient** — this is the highest-priority conclusion in an audit.

---

## References

- Play Integrity API (Google official docs): device integrity verdicts and server-side verification.
- Android Key Attestation: hardware key attestation.
- For public material on device fingerprinting and anti-fraud graphs, see the citations at the end of each document in `reference/`.
