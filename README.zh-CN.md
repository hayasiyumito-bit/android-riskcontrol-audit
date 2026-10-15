<!-- 语言 Language: [English](README.md) | **简体中文** -->

# Android 设备风控检测覆盖度审查套件

[English](README.md) | **简体中文**

> AI 辅助审查一个 Android App 的**设备风控 / 反欺诈检测**是否有**遗漏**。
> 面向 App 开发者、风控与安全团队 —— **仅防御用途**。

## 这是什么

现代 App 的设备风控 SDK 需要识别高风险环境:Root/Magisk、Hook/注入框架(Frida/Xposed/LSPosed)、模拟器、云手机、改机/指纹伪装、群控、多开、翻新改串等。攻击方会不断用新**绕过**手法规避这些检测。

本套件把「有哪些检测维度、每个维度有哪些已知绕过、对应应该检测什么、怎么分级判罚」整理成一套**知识库 + 清单 + Python 脚本**,让 AI(或人工)拿着它审查一个目标 App:

- **检查 App 自身代码**:它的检测覆盖了哪些维度?判罚分级是否合理?
- **检查引入的 .so / 第三方 SDK**:它们实际提供哪些检测?有没有"接了却留了口子"?
- **找遗漏**:对照「绕过手法 → 应检测项」清单,指出哪些攻击向量当前检测不到。

产出:一份**检测覆盖度审查报告**(每维度 已覆盖 / 部分 / 缺失 + 优先级建议)。

## 不是什么

- ❌ 不是绕过/对抗工具,不含任何规避检测或伪造设备指纹的代码。
- ❌ 不替你写风控 SDK,只审查覆盖度、指出缺口。
- 知识库里的「绕过手法」一律以**防御视角**描述:*攻击方会这么做 → 因此你应该检测这个*。

## 给 AI 助手

- **`SKILL.md`** — 把审查流程做成技能(Claude / Cursor 等 AI 的入口)。
- **`AGENTS.md`** — 本仓库给 AI 助手的规则。
- **`checklist/coverage.yaml`** — 机器可读的 12 维 + 结构性检查清单,供填写。

## 目录

```
SKILL.md                    # AI 审查工作流(技能)
AGENTS.md                   # 给 AI 助手的规则
checklist/coverage.yaml     # 机器可读覆盖度检查清单
docs/
  en/ 01..05                # English knowledge base
  zh/ 01..05                # 中文知识库
prompts/
  audit-prompt.en.md        # 审查提示词(英文)
  audit-prompt.zh.md        # 审查提示词(中文)
scripts/
  apk_static_scan.py        # APK 静态扫描:权限/组件/.so/SDK
  so_symbols.py             # .so 能力画像:JNI 导出 + 检测特征
  sdk_fingerprint.py        # 识别内置的风控/加固/热修复 SDK
  coverage_checklist.py     # scan.json → 覆盖度报告骨架
examples/sample-report.md   # 审查报告样例
reference/                  # 风控分级方法论文档(中文)
```

知识库:
- `docs/*/01-detection-dimensions` — 全部检测维度(root/hook/模拟器/云机/指纹/注入/位置/完整性…)。
- `docs/*/02-evasion-vs-detection` — **核心**:绕过手法 → 应检测项(找遗漏的依据)。
- `docs/*/03-risk-grading` — 风险分级模型(信号确定性 × 作恶链完整度)。
- `docs/*/04-so-sdk-audit` — 审查引入的 .so / 第三方 SDK。
- `docs/*/05-server-and-attestation` — 真正的防线:硬件背书 + 服务端。

## 快速开始

```bash
pip install -r scripts/requirements.txt       # androguard 可选
# 1) 静态扫一个 APK → .so/SDK/权限清单
python scripts/apk_static_scan.py target.apk -o out/scan.json --extract-libs out/libs
# 2) 每个 .so 的能力画像(JNI 导出 + 检测特征)
python scripts/so_symbols.py out/libs/*.so
# 3) 识别内置风控/加固/热修复 SDK
python scripts/sdk_fingerprint.py target.apk
# 4) 覆盖度报告骨架
python scripts/coverage_checklist.py out/scan.json -o out/coverage.md
```

然后把 `out/` + `docs/` + `checklist/coverage.yaml` 交给 AI,按 `SKILL.md` 产出覆盖度报告。

## 配套对照检测 App(可选)

有一个开源的**设备信息采集 / 检测对照 App**(包名 `com.android.device`),把大量检测项做成可在真机上运行、实时出判罚结论的参考实现,适合验证"某个检测项在真机上到底能不能抓到"。

- 项目地址:https://github.com/hayasiyumito-bit/deviceinfo_collect

> 两个项目相互独立;该 App 仅作为检测项的可运行参考。

## 范围与合规

- 用途限定:**对自己拥有或已获授权的 App 做防御性检测覆盖度审查。**
- 不含、不产出任何绕过检测或伪造设备指纹的能力。
- 知识来源为公开的风控/反欺诈检测研究(见各文档文末引用)。
