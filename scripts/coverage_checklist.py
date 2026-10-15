#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把静态扫描结果(apk_static_scan.py 的 scan.json)整理成一份**覆盖度审查报告骨架**(Markdown)。

12 个检测维度逐项列出,预填静态线索(.so/abi/SDK/权限),留出"是否覆盖/在哪一层/可被哪种绕过攻破"
给 AI 或人工填。配合 docs/ 与 prompts/AI审查提示词.md 使用。

用法:
    python coverage_checklist.py out/scan.json [-o out/coverage.md]
"""
import argparse
import json
import os

DIMENSIONS = [
    ("1. Root/Magisk/KernelSU/APatch", "su/magisk 路径+包、/proc/net/unix socket、namespace、Play Integrity"),
    ("2. Hook/注入框架", "maps 特征、rwx 页、text CRC、classloader 完整性、签名校验"),
    ("3. 模拟器(QEMU/x86)", "qemu 属性/节点、翻译层、标识占位"),
    ("4. 云手机(redroid)", "传感器缺失、软渲 GPU、容器痕迹、服务器 CPU"),
    ("5. 改机/指纹伪装", "★Java vs Native/文件 跨层交叉、属性多通道、build.prop mtime"),
    ("6. Hook 作恶链", "框架+注入+伪装 三要素"),
    ("7. 群控/自动化", "恶意无障碍+聚类、ADB-TCP、群控端口"),
    ("8. 翻新/改串/一机多号/多开", "mainboard_tag+串号、频繁新设备、duokai/virtualpath"),
    ("9. 进程内完整性(classloader)", "dexElements/nativeLib 外来来源、空名/重复/数量、maps 交叉"),
    ("10. 跨层真值读取", "getprop 子进程、svc 直读 maps/mountinfo、属性区磁盘真值"),
    ("11. 位置伪装", "mock provider、融合定位源头(GMS 盲点)、IP↔时区↔GPS、原始 GNSS"),
    ("12. 环境开关", "adb/usb/vpn/proxy/开发者选项(低危,叠加升级)"),
]

STRUCTURAL = [
    "是否接入 Play Integrity(MEETS_STRONG_INTEGRITY 硬件背书)?",
    "是否有服务端行为风控 / 设备-账号图谱 / 多维一致性兜底?",
    "判罚分级是否区分'确凿'与'怀疑'?单信号是否误判高危?",
    "是否有 ≥2 中危升高危 的累加逻辑?",
    "检测自身健康监控(except_error/占位值批量上升告警)?",
]


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def hints_from_scan(scan):
    lines = []
    libs = scan.get("libs", [])
    lines.append(f"- .so 数:{scan.get('native_lib_count', 0)},abis={scan.get('abis')},dex 数:{scan.get('dex_count', 0)}")
    if libs:
        names = sorted({l['name'] for l in libs})
        lines.append(f"- .so 清单:{', '.join(names[:40])}" + (" ..." if len(names) > 40 else ""))
    man = scan.get("manifest") or {}
    if isinstance(man, dict) and man.get("package"):
        lines.append(f"- 包名:{man.get('package')} | targetSdk={man.get('target_sdk')} | 权限数={len(man.get('permissions', []))}")
        perms = man.get("permissions", [])
        notable = [p for p in perms if any(k in p for k in
                   ("LOCATION", "PHONE_STATE", "READ_PRIVILEGED", "QUERY_ALL_PACKAGES", "SYSTEM_ALERT"))]
        if notable:
            lines.append(f"- 值得注意的权限:{notable}")
    else:
        lines.append("- (未解析 manifest:安装 androguard 可补权限/组件/包名)")
    return "\n".join(lines)


def build_report(scan):
    out = []
    out.append(f"# 设备风控检测覆盖度审查报告(骨架)\n")
    out.append(f"> 目标 APK:`{scan.get('apk')}`  体积:{scan.get('size')} 字节\n")
    out.append("## 静态线索\n")
    out.append(hints_from_scan(scan) + "\n")
    out.append("## 覆盖度矩阵(逐维填写)\n")
    out.append("| 维度 | 已覆盖? | 在哪一层 | 可被哪种绕过攻破 | 严重度 | 备注 |")
    out.append("|------|--------|---------|----------------|--------|------|")
    for name, hint in DIMENSIONS:
        out.append(f"| {name} | ☐ 有/部分/无 |  |  |  | 检点:{hint} |")
    out.append("\n## 结构性检查(最高优先级)\n")
    for q in STRUCTURAL:
        out.append(f"- ☐ {q}")
    out.append("\n## 遗漏清单(按优先级,审查后填写)\n")
    out.append("1. [严重] 结构性:…\n2. [高] 跨层交叉缺失:…\n3. [中] 只认名字:…\n")
    out.append("\n## 改进路线\n- 立刻 / 短期 / 中长期(含 Play Integrity + 服务端兜底 等结构项)\n")
    out.append("\n---\n> 对照 docs/02-绕过手法与对应检测.md 的 A~I 逐条核对;按 prompts/AI审查提示词.md 的工作流由 AI 产出最终结论。\n")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="生成覆盖度审查报告骨架")
    ap.add_argument("scan_json")
    ap.add_argument("-o", "--out")
    args = ap.parse_args()
    scan = load(args.scan_json)
    report = build_report(scan)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"[+] 报告骨架写入 {args.out}")
    else:
        print(report)


if __name__ == "__main__":
    main()
