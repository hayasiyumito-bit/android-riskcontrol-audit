> **English** | [简体中文](../zh/02-evasion-vs-detection.md)

# Evasion Techniques → Required Detections (the basis for finding gaps)

> Defensive perspective: we list the attacker's **known evasion techniques** and "therefore what you should detect." When auditing an app, check each one for a corresponding detection; anything missing is a **gap**.
> Each entry gives: the evasion technique (what the attacker does) → the required detection → whether that detection can be evaded further (the arms-race direction).

---

## A. Root hiding (Shamiko / denylist)

- **Evasion**: the denylist unmounts the magisk mount for the target app and hides the `su` paths and Magisk packages, so every "check paths/package names" detection fails.
- **What you should detect**:
  1. `.magisk` / `zygisk` sockets in `/proc/net/unix` (daemon-communication traces the denylist cannot hide).
  2. mount namespace / PID namespace consistency, mount anomalies in `/proc/self/mountinfo`.
  3. **Play Integrity `MEETS_STRONG_INTEGRITY`** (hardware-backed; a rooted environment cannot obtain it).
  4. Cross-layer check: the sepolicy layer (SELinux policy, which userspace cannot forge) detects Magisk while the surface probes report "not detected" → **the inconsistency itself** is a strong signal.
- **Arms-race direction**: pure path/package detection will always be bypassed; socket/namespace can be countered by stronger hiding modules; **only hardware attestation is the endgame**.

## B. Hook framework renaming / randomization

- **Evasion**: rename `libfrida`/`libxposed`/in-house `.so` to a random name and strip the signature from thread names and VMA names, so "match maps/threads by name" fails.
- **What you should detect (structure/behavior, not names)**:
  1. **rwx (writable + executable) pages** in `/proc/self/maps`, W^X violations (inline-hook trampolines / patched code pages).
  2. **Byte-by-byte code integrity**: compare the in-memory code pages of libc / key libraries against the on-disk `.so` original; an inline patch changes function bytes, which restoring the permission bits cannot hide.
  3. Use **inline-svc (raw syscall) to read maps directly** and compare against the libc read: if libc reads back "clean" while svc can see it → someone hooked libc open/read.
- **Arms-race direction**: on newer systems such as A17 some native hook engines fail, so attacks shift to pure Java/ART hooks + mounts; detection must correspondingly move lower and go cross-layer.

## C. Thread names / VMA names announcing themselves

- **Evasion** (also a **detection blind spot**): thread names the injector creates in the host process (landing in `/proc/self/task/*/comm`, truncated to 15 chars) or anonymous VMA names, if they contain framework signature words, will be caught by scanning comm/maps → a mature injector strips the signature.
- **What you should detect**: scan `/proc/self/task/*/comm` and anonymous-segment names in maps for known framework/tool signature words (as a **suspicion** signal, not a standalone high-risk verdict; see grading).
- **Note**: this is a **name-based** detection, defeated by a rename → it can only feed a "watch list," not serve as conclusive proof. You can maintain a "signature table of common hook/tampering apps seen in the wild" to feed the suspicion channel.

## D. code_cache hot-load injection + file deletion

- **Evasion**: the injector drops the module `.so`/`.dex` (even a full copy of the APK) into the host's **own `code_cache`** and loads it; after loading it **deletes the file** (unlink), so "scan my own code_cache for foreign files" finds nothing.
- **What you should detect**:
  1. `dalvik-classes*.dex extracted from <...app-private code_cache...>` in `/proc/self/maps`: the VMA name ART assigns to the dex segment **contains the source path and survives deletion**. A legitimate secondary dex comes from base.apk in the install dir `/data/app`, never from a random jar in code_cache.
  2. An executable `.so` file mapping landing in `code_cache` (excluding ART's legitimate oat).
  3. **Keep the criterion neutral**: key on **behavior / directory structure** such as `code_cache` (the Android-standard writable code directory), not on a specific framework name / subdirectory name — so renaming and deletion are both ineffective.
- **Arms-race direction**: see the next entry (the attacker will tamper with classloader metadata so maps/enumeration no longer match).

## E. Classloader metadata tampering (hiding the injected dex/so)

- **Evasion (the fundamental weakness of in-process self-checks)**: the injector controls this process's memory and can reflectively tamper with the host classloader's `pathList`:
  - remove `nativeLibraryPathElements` pointing to a writable directory (the `.so` is already loaded, so the path can go);
  - clear the source name of the injected dex element / disguise it as the host base.apk / **physically remove that element** (combined with hooking `findClass` to fall back to loading from the in-memory DexFile), so "enumerate dexElements for foreign/duplicate/empty-name/abnormal-count" all find nothing.
- **What you should detect (each an arms-race escalation)**:
  1. dex in `dexElements` with a source outside the install directory → foreign injection.
  2. The dexFile genuinely exists but `getName()` is empty → the source name was wiped = tampering.
  3. Duplicate same-name dex, `dexElements` count greater than expected (base.apk + real splits) → forged/surplus elements.
  4. **Cross-layer check**: maps contains a dex segment extracted from code_cache, but the classloader enumeration shows no corresponding source → the two layers do not match = metadata was tampered (the attacker finds it very hard to forge maps and the classloader consistently at the same time).
- **Fundamental realization (must be written into the audit conclusion)**: all of the above are **in-process self-checks**. The injector fully controls this process; it can forge any read path such as `Field.get`/`findClass`, or make an element "physically not exist." **Client-side in-process integrity will always lose to an injector** — it can only raise cost / prolong the contest, and **must not be the sole line of defense**. What actually stops the attack is:
  - **Play Integrity STRONG_INTEGRITY** (hardware-backed, outside the injector's process control);
  - **Server-side behavioral risk control + device-account graph + multi-dimensional consistency**.
  If an audit finds an app with **only** client-side in-process self-checks and no hardware attestation or server-side backstop → that is the single largest structural gap.

## F. Fingerprint spoofing done "consistently across all layers"

- **Evasion**: mature tampering spoofs the Java `Build`, `SystemProperties`, the `getprop` subprocess, the property area, and the `/system/build.prop` file layer **all into the same consistent target model**, so "cross-layer inconsistency" catches nothing.
- **What you should detect**:
  1. Insist on multi-channel cross-checking (Java `Build` vs `getprop` subprocess vs on-disk property-area ground truth vs build.prop file); any inconsistency is high risk.
  2. Obtain ground truth via **subprocess / svc direct read / file layer** (bypassing in-process hooks).
  3. **Hard constraints beyond consistency**: build.prop mtime, file_stat inode/time, and the intrinsic correspondence between model ↔ hardware ↔ CPU abi (e.g. the model claims Samsung but hardware=tegu (Pixel)).
  4. **Hardware attestation**: the STRONG_INTEGRITY model/integrity verdict is issued by the TEE, out of reach of the spoofing layer.
- **Arms-race direction**: once the attacker perfects consistency, a single client-side snapshot struggles to catch it → rely on "continuously adding orthogonal cross-check dimensions" to raise cost + server-side cross-time/cross-device consistency.

## G. Property/file spoofing: the mount layer (bypassing in-process hooks)

- **Evasion**: within the target process's mount namespace, bind-mount a fake `build.prop` / fake `getprop`, so even the file layer and subprocess reads return fakes, while in-process hooks cannot reach it.
- **What you should detect**: in `/proc/self/mountinfo`, system-critical files (build.prop, /system/bin/getprop, etc.) have become standalone bind-mount mount points — this never happens on a normal device. Read mountinfo **directly via svc** (the libc read may be filtered).
- **Note**: mount spoofing is **tampering evidence** (not merely "a tool present"), so it is conclusive high risk; but the attacker will filter mountinfo reads → counter with a direct svc read.

## H. Location: GMS fused-location bypass

- **Evasion / blind spot**: when only the target app's location APIs are hooked, **the GMS fused-location coordinate is computed inside the `com.google.android.gms` process** and fed to map-type apps over the GMS binder, bypassing the app-side hook; a spoofer only needs to spoof the app side to believe it succeeded, but this GMS path is missed.
- **What you should detect**:
  1. Coordinate consistency should be checked at the **system-service provider source** or on the **server**, not trusted solely from the app-side response.
  2. IP geolocation ↔ timezone ↔ GPS three-way consistency (server-side, the most robust).
  3. Physical self-consistency of raw GNSS / motion sensors with the "claimed location" (speed, altitude, satellite visibility).

## I. Detection countered by "feeding fakes / throwing exceptions"

- **Evasion**: the adversarial module makes the detection function always return "clean," or intercepts it into throwing an exception / returning a placeholder value.
- **What you should detect (meta-signals)**: detection fields returning `except_error` in bulk, core fields returning placeholders at scale (`6666`/empty), low-layer signals hitting while aggregate labels are all zero — these **adversarial traces themselves** should enter WATCH / manual review, never be silently swallowed.

---

## "Gap" priority during an audit

1. **Structural absence (highest)**: client-side self-checks only, no Play Integrity hardware attestation / no server-side backstop → the root cause in section E; the client will always lose.
2. **Missing cross-layer checks**: reading only the Java layer, no subprocess/svc/file-layer cross-check → F/G/dimension 10.
3. **Names, not behavior**: hard-matching framework names/paths, defeated by a rename → B/C/D.
4. **Fusion/source blind spots**: location hooks only the app side (misses GMS), root only checks paths (misses socket/namespace) → H/A.
5. **Adversarial traces swallowed**: no alert on except_error/placeholder values → I.
