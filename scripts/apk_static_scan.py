#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APK 静态扫描:列出 .so / dex / 组件 / 权限 / 签名概况,供覆盖度审查使用。

只依赖标准库(zipfile)即可跑出 .so/dex/资源清单;若安装了 androguard,
额外解析包名/权限/组件(可选)。纯只读、不执行 APK 内任何代码。

用法:
    python apk_static_scan.py app.apk [-o out/scan.json] [--extract-libs out/libs]
"""
import argparse
import hashlib
import json
import os
import re
import sys
import zipfile


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def scan_zip(apk_path: str, extract_libs: str | None):
    info = {
        "apk": os.path.abspath(apk_path),
        "size": os.path.getsize(apk_path),
        "libs": [],          # [{path, abi, name, size, sha256}]
        "dex": [],           # [classes*.dex names]
        "abis": [],
        "has_signature": False,
        "native_lib_count": 0,
        "assets_notable": [],
    }
    abis = set()
    with zipfile.ZipFile(apk_path) as z:
        for zi in z.infolist():
            name = zi.filename
            if name.startswith("lib/") and name.endswith(".so"):
                parts = name.split("/")
                abi = parts[1] if len(parts) > 2 else "?"
                abis.add(abi)
                data = z.read(name)
                entry = {
                    "path": name,
                    "abi": abi,
                    "name": parts[-1],
                    "size": len(data),
                    "sha256": sha256(data),
                }
                info["libs"].append(entry)
                if extract_libs:
                    os.makedirs(extract_libs, exist_ok=True)
                    # 落盘时用 abi 前缀避免同名覆盖
                    out = os.path.join(extract_libs, f"{abi}__{parts[-1]}")
                    with open(out, "wb") as f:
                        f.write(data)
            elif re.fullmatch(r"classes\d*\.dex", name):
                info["dex"].append(name)
            elif name.startswith("META-INF/") and name.upper().endswith((".RSA", ".DSA", ".EC")):
                info["has_signature"] = True
            elif name.startswith("assets/") and any(
                k in name.lower() for k in ("tinker", "sophix", "patch", "plugin", "robust")
            ):
                info["assets_notable"].append(name)
    info["abis"] = sorted(abis)
    info["native_lib_count"] = len(info["libs"])
    info["dex_count"] = len(info["dex"])
    return info


def try_androguard(apk_path: str):
    """可选:用 androguard 解析包名/权限/组件。未安装则返回 None。"""
    try:
        from androguard.core.apk import APK  # type: ignore
    except Exception:
        try:
            from androguard.core.bytecodes.apk import APK  # type: ignore
        except Exception:
            return None
    try:
        a = APK(apk_path)
        return {
            "package": a.get_package(),
            "min_sdk": a.get_min_sdk_version(),
            "target_sdk": a.get_target_sdk_version(),
            "permissions": sorted(a.get_permissions()),
            "activities": a.get_activities()[:50],
            "services": a.get_services()[:50],
            "receivers": a.get_receivers()[:50],
        }
    except Exception as e:  # pragma: no cover
        return {"error": f"androguard failed: {e}"}


def main():
    ap = argparse.ArgumentParser(description="APK 静态扫描(.so/dex/SDK/权限)")
    ap.add_argument("apk")
    ap.add_argument("-o", "--out", help="输出 json 路径(默认打印到 stdout)")
    ap.add_argument("--extract-libs", help="把 .so 解到该目录,供 so_symbols.py 用")
    args = ap.parse_args()

    if not zipfile.is_zipfile(args.apk):
        print(f"[!] 不是有效 APK/zip: {args.apk}", file=sys.stderr)
        sys.exit(2)

    result = scan_zip(args.apk, args.extract_libs)
    ag = try_androguard(args.apk)
    result["manifest"] = ag if ag is not None else {"note": "androguard 未安装,跳过权限/组件解析"}

    out = json.dumps(result, ensure_ascii=False, indent=2)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"[+] 写入 {args.out}:{result['native_lib_count']} 个 .so / "
              f"{result['dex_count']} 个 dex / abis={result['abis']}")
    else:
        print(out)


if __name__ == "__main__":
    main()
