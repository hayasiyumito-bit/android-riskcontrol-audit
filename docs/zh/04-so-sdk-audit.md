> [English](../en/04-so-sdk-audit.md) | **简体中文**

# .so 与第三方 SDK 审查

> App 的风控能力往往一半在自己代码、一半在引入的 **.so 和第三方 SDK**。审查时常见误区是"接了某风控 SDK 就当安全了",但要核实它**实际提供哪些检测**、有没有留口子。

---

## 一、审查引入的 .so 真实能力

用 `scripts/so_symbols.py` 提取每个 .so 的导出符号 + 字符串特征,判断它在做什么:

| 看什么 | 说明 |
|--------|------|
| **导出 JNI 符号**(`Java_...`) | 反推它对 Java 暴露了哪些检测方法(如 `...getMagiskNativeProbe`、`...getInlineSvcMapsProbe`) |
| **字符串特征** | 是否含 `/proc/self/maps`、`/proc/net/unix`、`magisk`、`qemu`、`frida`、`ptrace`、`su` 等 → 它检测哪些维度 |
| **syscall / inline-svc 痕迹** | 有没有绕过 libc 直读(`svc #0`、裸 openat/read)→ 是否具备"绕 hook 取真值"能力 |
| **反调试** | `ptrace`、`TracerPid`、`/proc/self/status` → 自保护 |
| **代码完整性** | 是否做 .text CRC / 签名校验 |
| **缺失项** | 对照 [01-检测维度清单.md](01-检测维度清单.md),这个 .so 没覆盖哪些维度 |

**要点**:很多"风控 SDK"只做了属性/路径层的浅检测,**没有**跨层交叉、svc 直读、classloader 完整性 → 这些就是 .so 层的遗漏。

---

## 二、识别已知风控 / 反欺诈 SDK

用 `scripts/sdk_fingerprint.py` 按**包名前缀 / .so 名 / 类名**识别内置的商用风控 SDK(示例特征,非穷举):

| SDK 类别 | 识别特征(示例) | 典型能力 |
|---------|----------------|---------|
| 设备指纹 / 反欺诈 | 特定 so 名 / 包前缀(各厂不同) | 设备指纹、Root/模拟器/Hook 检测、风险评分 |
| 加固壳 | `libDexHelper`、`libjiagu`、`libshell`、`libpreverify` 等 | 代码保护(不是风控,但影响静态审查) |
| 热修复 / 插件化 | Tinker / Sophix / RePlugin 的类/文件 | **会从数据目录加载 dex** → 注入检测的合法误报源 |
| 推送 / 统计 | 采集设备标识 | 隐私合规关注点 |

识别出 SDK 后:
1. 查该 SDK 公开文档/版本,核对它**声称**的检测维度;
2. 对照清单,它**没覆盖**的维度就是整体遗漏;
3. 若存在加固壳,注意静态分析受限,需结合动态/运行时验证。

---

## 三、"接了 SDK = 安全"的常见坑

- **只接了指纹采集,没接风险判罚**:SDK 只上报原始参数,判罚逻辑在服务端 —— 若服务端规则缺失(如底层信号命中但标签全 0),等于白采。
- **版本过旧**:老版本 SDK 的检测对新绕过手法(新型 ARM 云机、A14+ 的新注入方式)覆盖不足。
- **初始化时机 / 作用域不对**:风控 SDK 在关键业务之后才初始化,或没覆盖所有进程 → 留窗口。
- **过度依赖单层**:只有 Java 层检测,native/服务端缺位 → 见 [02 的 E/F 节](02-绕过手法与对应检测.md)。
- **检测自身无健康监控**:SDK 被 hook 喂假后无感知(except_error 不告警)。

---

## 四、静态审查流程(配合脚本)

```bash
# 1) 解包 + 清单:权限、组件、.so 列表、dex 数量
python scripts/apk_static_scan.py target.apk -o out/scan.json

# 2) 每个 .so 的能力画像
for so in out/libs/*.so; do python scripts/so_symbols.py "$so"; done

# 3) 识别内置风控/加固/热修复 SDK
python scripts/sdk_fingerprint.py target.apk

# 4) 覆盖度清单 → 报告(哪些维度有检测、哪些缺)
python scripts/coverage_checklist.py out/scan.json -o out/coverage.md
```

然后把 `out/` 的结果连同本目录文档交给 AI,按 [prompts/AI审查提示词.md](../prompts/AI审查提示词.md) 产出结论。

> 静态只能看到"有没有这些能力的痕迹";**能不能真的抓到**需在真机上验证(可用配套的对照采集 App 作参考实现)。
