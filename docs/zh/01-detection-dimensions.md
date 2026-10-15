> [English](../en/01-detection-dimensions.md) | **简体中文**

# 检测维度清单

审查一个 App 的设备风控时,逐个维度核对"是否有检测、检测在哪一层、能不能被简单绕过"。
每个维度给出:**信号**(怎么判)、**层级**(Java / Native / 系统服务 / 跨层)、**常见遗漏**。

> 判罚如何分级见 [03-风险分级模型.md](03-风险分级模型.md);每个维度的绕过手法与应检测项见 [02-绕过手法与对应检测.md](02-绕过手法与对应检测.md)。

---

## 1. Root / Magisk / KernelSU / APatch

| 信号 | 层 | 说明 |
|------|----|------|
| su 二进制路径、Magisk 路径/包、`which su` | Java/Native | 基础,易被 denylist 隐藏 |
| `/proc/net/unix` 里的 magisk/zygisk socket | Native | denylist 绕不过的强痕迹 |
| mount/namespace 不一致、`/proc/self/mountinfo` 挂载痕迹 | Native | Shamiko 隐藏后仍可查 |
| SELinux 为 Permissive/Disabled | Java/Native | 单点弱信号 |
| Play Integrity `MEETS_STRONG_INTEGRITY` | 服务端校验 | **最强**,硬件背书,root 伪造不了 |

**常见遗漏**:只查路径/包名(denylist 一隐藏就失效);不查 socket / namespace / Play Integrity。

## 2. Hook / 注入框架(Frida / Xposed / LSPosed / 自研)

| 信号 | 层 | 说明 |
|------|----|------|
| `/proc/self/maps` 含框架特征串、Frida 端口 27042/27043 | Native | 名字可改随机化 |
| 关键函数首字节 inline-hook、.text 段 CRC 校验 | Native | 抓 inline hook,改权限位也躲不过 |
| 非应用安装目录加载的可执行映射(dirty page) | Native | 注入 .so 的通用特征 |
| classloader 完整性:dexElements/nativeLibraryPathElements 里的外来来源 | Java(跨层) | 见维度 9 |
| 代码完整性:APK 签名 / DEX·SO 校验 | Java/Native | 防二次打包 |

**常见遗漏**:只按框架**名字**匹配(改名即废);不做结构/行为检测;不做 classloader 身份级完整性。

## 3. 模拟器(QEMU / Goldfish / x86 VM)

| 信号 | 说明 |
|------|------|
| `ro.kernel.qemu`、`ro.hardware`=goldfish/ranchu/vbox、sdk_gphone 机型 | 明显属性 |
| `/dev/qemu_pipe`、`/dev/socket/qemud`、genyd、`bluestacks.prop` | 专属节点 |
| x86 跑 ARM + 翻译层 libhoudini / libndk_translation | CPU 架构异常 |
| 标识占位值(getDeviceId 全 0、android_id 固定) | |

**常见遗漏**:只查属性,不查设备节点/翻译层;对新型 ARM 模拟器(非 x86)覆盖不足。

## 4. 云手机(redroid / Docker-ARM)

| 信号 | 说明 |
|------|------|
| 传感器缺失/全 0/长期零波动(无机身) | **最强判据**:没有真实硬件 |
| 无基带 radioVersion=unknown + SIM ABSENT | |
| GPU 软件渲染(SwiftShader / LLVMpipe / VirGL / virtio_gpu) | 容器无真实 GPU |
| `/proc/1/cgroup` 含 docker、overlayfs、`ro.kernel.qemu` | 容器痕迹 |
| 服务器 CPU(Ampere Altra / Graviton / Xeon / EPYC) | |

**常见遗漏**:传感器单条误报率高(实测精确率~62%、误伤~10%),**不能单独判罚**,须多信号融合。

## 5. 改机 / 设备指纹伪装(核心)

| 信号 | 说明 |
|------|------|
| **跨层指纹交叉不一致**:`file_* / native` 层 ≠ `Build`(Java)层 | **性价比最高、最难绕**,是定性关键 |
| 属性多通道不一致:getprop 子进程 / SystemProperties / JNI / 属性区磁盘真值 互相矛盾 | |
| build.prop 被改、`ro.debuggable=1`、`ro.build.tags=test-keys` | |
| build.prop mtime 异常(如固定 2009 年) | |

**常见遗漏**:只读 Java 层 `Build`(最易被 hook);不做 Java vs Native/文件 交叉;不读 `getprop` 子进程或直读 build.prop(攻击方的 `file_*` 真值手法)。详见维度 10。

## 6. Hook 作恶链(框架 + 注入 + 业务伪装)

框架存在 + 注入非应用路径 .so/.dex + 伪装业务/UA → 高危;仅框架存在 → 中。
**常见遗漏**:把"有框架"直接当高危(误伤热修复/加固);或反过来只看"有没有伪装"忽略注入本身。

## 7. 群控 / 自动化(ADB / 无障碍)

| 信号 | 说明 |
|------|------|
| 恶意无障碍服务 + 批量聚类 | |
| ADB 注入输入事件、ADB-TCP 5555 已连接、群控端口 | |
| `ro.debuggable=1` / `ro.adb.secure=0` | |

**常见遗漏**:adb keyevent 本身合法,须结合行为+聚类定性,不能单点硬封。

## 8. 翻新 / 改串 / 一机多号 / 多开

| 维度 | 信号 |
|------|------|
| 主板翻新 | mainboard_tag + 串号异常/清零 + 频繁"新设备" |
| 一机多号 | 同设备标识绑大量账号(服务端图谱) |
| 多开/分身 | duokai* 标记、virtualpath 异常、虚拟框架包(VirtualApp 等) |

## 9. 进程内完整性(classloader / 加载来源)★

现代注入把 .so/dex 塞进宿主进程后加载,留下进程内结构痕迹:

| 信号 | 说明 |
|------|------|
| classloader `dexElements` 里来自**非安装目录**(app 私有可写目录 `/data/data`、`/data/user`)的 dex | 合法代码只从只读安装目录 `/data/app` 加载 |
| `nativeLibraryPathElements` 指向可写目录 | 注入方 dlopen .so 的落脚处 |
| `/proc/self/maps` 里 `dalvik-classes*.dex extracted from <app 私有 code_cache>` | ART 起的 VMA 名,删盘也抹不掉 |
| dexElements 出现空名 / 同名重复 / 数量 > 应有 | 有人篡改了 classloader 元数据 |

**常见遗漏**:完全不做进程内完整性自检;或只靠单一维度(攻击方能逐个绕,要多维交叉)。
**重要认知**:进程内自检对**掌控本进程的注入方**本质防不住(注入方可反射伪造/移除任何进程内结构);它只能抬成本,**最终防线是硬件背书(Play Integrity STRONG_INTEGRITY)+ 服务端行为/图谱**。

## 10. 跨层真值读取(攻击方的 file_* 手法)★

攻击方为了拿"真机值"做交叉,会绕开进程内 hook 从底层读:

| 真值通道 | 读到什么 | 对应你要检测什么 |
|---------|---------|----------------|
| fork+exec `/system/bin/getprop` 子进程 | 独立进程读属性,绕过本进程 Java hook | 你也该用同样手法取真值做交叉 |
| 直读 `/system/build.prop` 文件 | 文件层真值 | |
| inline-svc(raw syscall)直读 `/proc/self/maps`、`/proc/self/mountinfo` | 绕过 libc open/read 的 hook | 用 svc 直读对比 libc 读,不一致=被过滤 |
| 直接解析 `/dev/__properties__` 磁盘 trie | 属性区真值 vs 进程内 `__system_property_get` | |

**常见遗漏**:所有读取都走 Java/libc(都在 hook 射程内);不用子进程/svc/文件层做交叉。

## 11. 位置伪装

| 信号 | 层 | 说明 |
|------|----|------|
| `isFromMockProvider` / 测试 provider | Java | 基础,易绕 |
| LocationManager + 融合定位(FusedLocationProvider)输出一致性 | Java/服务端 | |
| **GMS 融合定位绕过**:坐标在 GMS 进程算,需在系统服务 provider 源头或服务端核对 | 系统服务 | 只 hook app 侧会漏 |
| 原始 GNSS(GnssMeasurement / NMEA)高精度反推 | | 伪装方会屏蔽原始 GNSS |
| IP 归属 ↔ 时区 ↔ GPS 三者一致性 | 服务端 | |

**常见遗漏**:只查 mock provider;不核对 IP/时区/GPS 一致性(服务端最稳)。

## 12. 环境开关(低风险,叠加才升级)

ADB 调试、USB 调试、VPN、代理、开发者选项、数据目录可访问 —— 单点低危,≥2 叠加或配合高危维度升级。

---

## 检测自身健康度(审查必看)

- 检测字段批量返回 `except_error`(检测抛异常)= 疑似被对抗绕过 → 应单独告警、进人工。
- 核心字段大面积返回占位值(如 `6666` / 空)= 信息被屏蔽 → 弱可疑信号。
- 底层信号命中但服务端综合标签全 0 = 疑似漏判/规则链断 → 复核。
