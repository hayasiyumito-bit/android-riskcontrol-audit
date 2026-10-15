#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
.so 能力画像:提取 JNI 导出符号 + 检测/反调试/绕过 特征字符串,反推这个 .so 在做什么检测。

核心用纯标准库(扫 ELF 内可打印字符串 + 正则),无需 nm/readelf;
若系统有 nm/llvm-nm,额外补一份动态符号表(可选)。纯只读、不执行 .so。

用法:
    python so_symbols.py lib*.so [lib2.so ...]
"""
import re
import shutil
import subprocess
import sys

# 可打印字符串(ASCII,长度>=4),近似 `strings`
_STR = re.compile(rb"[\x20-\x7e]{4,}")
# JNI 导出:Java_包_类_方法
_JNI = re.compile(r"\bJava_[A-Za-z0-9_]+")

# 特征词 → 该 .so 可能覆盖的检测维度(防御视角)
SIGNATURES = {
    "root/magisk": ["magisk", "zygisk", "kernelsu", "/su", "superuser", "/proc/net/unix", "ksud", "apatch"],
    "hook/注入": ["frida", "xposed", "lsposed", "substrate", "gum-js-loop", "riru", "dobby", "shadowhook", "whale"],
    "maps/完整性": ["/proc/self/maps", "dalvik-classes", "code_cache", "libart", "/proc/self/task"],
    "跨层真值(绕hook)": ["/system/build.prop", "/system/bin/getprop", "__properties__", "openat", "svc"],
    "模拟器/云机": ["qemu", "goldfish", "ranchu", "/dev/qemu_pipe", "houdini", "ndk_translation", "swiftshader", "/proc/1/cgroup"],
    "反调试": ["ptrace", "TracerPid", "/proc/self/status", "anti_debug", "PTRACE_TRACEME"],
    "代码完整性": ["CRC", "checksum", "signature", "/proc/self/maps", ".text"],
    "指纹/属性": ["ro.build", "fingerprint", "getprop", "SystemProperties"],
    "mount/命名空间": ["/proc/self/mountinfo", "/proc/self/mounts", "mountinfo", "setns"],
}


def extract_strings(path: str) -> list[str]:
    with open(path, "rb") as f:
        blob = f.read()
    return [m.group().decode("ascii", "ignore") for m in _STR.finditer(blob)]


def nm_dynsyms(path: str) -> list[str]:
    tool = shutil.which("llvm-nm") or shutil.which("nm")
    if not tool:
        return []
    try:
        out = subprocess.run([tool, "-D", "--defined-only", path],
                             capture_output=True, text=True, timeout=30)
        syms = []
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[1] in ("T", "t", "W", "w"):
                syms.append(parts[2])
        return syms
    except Exception:
        return []


def profile_one(path: str):
    strings = extract_strings(path)
    joined = "\n".join(strings)
    low = joined.lower()

    jni = sorted(set(_JNI.findall(joined)))
    hits = {}
    for dim, keys in SIGNATURES.items():
        found = sorted({k for k in keys if k.lower() in low})
        if found:
            hits[dim] = found
    syms = nm_dynsyms(path)

    print(f"\n=== {path} ===")
    print(f"字符串数:{len(strings)} | 动态符号(nm):{len(syms) if syms else '不可用(无 nm)'}")
    if jni:
        print(f"JNI 导出({len(jni)}):")
        for s in jni[:40]:
            print(f"    {s}")
        if len(jni) > 40:
            print(f"    ... 还有 {len(jni) - 40} 个")
    else:
        print("JNI 导出:无(可能不是 JNI 库 / 已混淆符号)")
    if hits:
        print("命中的检测维度特征(防御视角:该 .so 可能在检测这些):")
        for dim, found in hits.items():
            print(f"    [{dim}] {found}")
    else:
        print("未命中已知检测特征(浅检测 / 纯业务 / 高度混淆)")
    # 覆盖缺口提示
    covered = set(hits.keys())
    gaps = [d for d in SIGNATURES if d not in covered]
    if gaps:
        print(f"该 .so 未见以下维度特征(可能的遗漏,需结合全局判断):{gaps}")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    for p in sys.argv[1:]:
        try:
            profile_one(p)
        except Exception as e:
            print(f"[!] {p}: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
