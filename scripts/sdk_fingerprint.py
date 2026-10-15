#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
识别 APK 内置的风控/反欺诈/加固/热修复 SDK —— 按 .so 名、资源路径、dex 内类路径的特征。

目的:核实"接了哪些 SDK、它们负责什么",以及哪些是注入检测的**合法误报源**(热修复/插件化/加固)。
特征表为公开可见的通用线索,非穷举;识别到后请结合该 SDK 公开文档核对其实际检测维度。

用法:
    python sdk_fingerprint.py app.apk
"""
import re
import sys
import zipfile

# 类别 -> [正则特征](匹配 zip 内条目名,含 lib/、assets/、dex 内路径近似)
# 说明:dex 内类路径无法直接从 zip 名看到,这里对 lib/.so 名与资源路径做匹配;
# 若要深入到类名,配合反编译(apktool/jadx)后再 grep 本表的 class 特征。
CATEGORIES = {
    "加固壳(影响静态分析)": [
        r"lib(jiagu|shell|shella|shellx|secexe|secmain|DexHelper|preverify\d?)\.so",
        r"libnesec\.so", r"libtup\.so", r"libmobisec\.so", r"libexec(main|protect)\.so",
        r"libnqshield\.so", r"libapssec\.so", r"libkmsnativeext\.so", r"libNSaferOnly\.so",
    ],
    "热修复/插件化(注入检测的合法误报源)": [
        r"assets/.*tinker", r"lib.*tinker.*\.so", r"assets/.*sophix", r"lib.*sophix.*\.so",
        r"assets/.*/robust", r"assets/.*replugin", r"assets/.*shadow", r"assets/.*VirtualApp",
        r"lib.*patch.*\.so",
    ],
    "风控/反欺诈/设备指纹(需核对实际能力)": [
        # 通用线索:名字含 risk/sec/fraud/device/fp/shield/guard/safe 的 native 库
        r"lib.*(risk|antifraud|fraud|shield|safeguard|devicefp|deviceid|fingerprint).*\.so",
        r"lib(secsdk|dusec|dfp|dfsdk|ses)\.so",
    ],
    "反调试/完整性(自保护)": [
        r"lib.*(antidebug|checksum|integrity|verify).*\.so",
    ],
    "统计/推送(隐私合规关注)": [
        r"assets/.*(umeng|jpush|getui|xinge|mipush)", r"lib.*(umeng|jpush|getui).*\.so",
    ],
}


def scan(apk: str):
    names = []
    with zipfile.ZipFile(apk) as z:
        names = z.namelist()
    results = {}
    for cat, pats in CATEGORIES.items():
        hits = set()
        for pat in pats:
            rx = re.compile(pat, re.IGNORECASE)
            for n in names:
                if rx.search(n):
                    hits.add(n)
        if hits:
            results[cat] = sorted(hits)
    return results, len(names)


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    apk = sys.argv[1]
    if not zipfile.is_zipfile(apk):
        print(f"[!] 不是有效 APK: {apk}", file=sys.stderr)
        sys.exit(2)
    results, total = scan(apk)
    print(f"扫描 {apk}(共 {total} 个条目)")
    if not results:
        print("未按通用特征识别到已知 SDK(可能名字被改/高度混淆,建议反编译后按类名二次核对)。")
        return
    for cat, hits in results.items():
        print(f"\n[{cat}]")
        for h in hits:
            print(f"    {h}")
    if "热修复/插件化(注入检测的合法误报源)" in results:
        print("\n⚠️ 注意:检测到热修复/插件化 —— 它们会从数据目录加载 dex,"
              "是'code_cache 注入检测'的合法误报源;审查注入检测时须确认有'外来身份/异包'消歧,避免误伤本 App。")


if __name__ == "__main__":
    main()
