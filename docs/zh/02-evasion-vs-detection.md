> [English](../en/02-evasion-vs-detection.md) | **简体中文**

# 绕过手法 → 对应检测项(找遗漏的依据)

> 防御视角:列出攻击方**已知的绕过手法**,以及"因此你应该检测什么"。审查一个 App 时,逐条核对它有没有对应检测;没有的就是**遗漏**。
> 每条给出:绕过手法(攻击方怎么做)→ 应检测项 → 该检测能不能被进一步绕过(军备升级方向)。

---

## A. Root 隐藏(Shamiko / denylist)

- **绕过**:denylist 对目标 App 卸载 magisk 挂载、隐藏 su 路径与 Magisk 包,使"查路径/包名"全部失效。
- **应检测**:
  1. `/proc/net/unix` 里的 `.magisk` / `zygisk` socket(denylist 绕不过的守护进程通信痕迹)。
  2. mount namespace / PID namespace 一致性、`/proc/self/mountinfo` 里的挂载异常。
  3. **Play Integrity `MEETS_STRONG_INTEGRITY`**(硬件背书,root 环境拿不到)。
  4. 跨层交叉:sepolicy 层(SELinux policy,userspace 伪造不了)检出 Magisk,但表层探针报"未检出" → 这个**不一致本身**就是强信号。
- **军备方向**:纯路径/包名检测必被绕;socket/namespace 可被更强隐藏模块对抗;**只有硬件背书是终局**。

## B. Hook 框架改名 / 随机化

- **绕过**:把 `libfrida`/`libxposed`/自研 .so 改成随机名,线程名、VMA 名去特征,使"按名字匹配 maps/线程"失效。
- **应检测(结构/行为,不认名字)**:
  1. `/proc/self/maps` 的 **rwx(可写可执行)页**、W^X 违规(inline-hook 蹦床/被 patch 的代码页)。
  2. **代码完整性逐字节核对**:把 libc/关键库的内存代码页与磁盘 .so 原文比对,inline 补丁改的是函数字节,改回权限位也躲不过。
  3. 用 **inline-svc(raw syscall)直读 maps**,对比 libc 读:若 libc 读被过滤成"干净"而 svc 看得见 → 有人 hook 了 libc open/read。
- **军备方向**:A17 等新系统上部分 native hook 引擎失效,攻击会转向纯 Java/ART hook + 挂载;检测需相应下沉+跨层。

## C. 线程名 / VMA 名 自报家门

- **绕过**(也是**检测盲点**):注入方在宿主进程里建的线程名(落进 `/proc/self/task/*/comm`,15 字符截断)或 VMA 匿名名若带框架特征词,会被扫 comm/maps 发现 → 成熟注入方会去特征。
- **应检测**:扫 `/proc/self/task/*/comm` 与 maps 匿名段名里的已知框架/工具特征词(作为**怀疑**信号,不单独判高危,见分级)。
- **注意**:这是**名字型**检测,改名即失效 → 只能进"怀疑名单",不能作为确凿铁证。可维护一张"市面常见 hook/改机行为 App 特征表"喂进怀疑通道。

## D. code_cache 热加载注入 + 删盘

- **绕过**:注入方把模块 .so/.dex(甚至整份 APK 副本)落到宿主**自己的 `code_cache`** 再加载;加载完**删盘**(unlink),使"扫自己 code_cache 找外来文件"查不到。
- **应检测**:
  1. `/proc/self/maps` 里 `dalvik-classes*.dex extracted from <...app 私有 code_cache...>`:ART 给 dex 段起的 VMA 名**含来源路径,删盘也抹不掉**。合法二级 dex 的来源是安装目录 `/data/app` 的 base.apk,不会是 code_cache 里的随机 jar。
  2. 可执行 .so 文件映射落在 `code_cache`(排除 ART 合法 oat)。
  3. **判据要中立**:键 `code_cache`(Android 标准可写代码目录)这类**行为/目录结构**,不键具体框架名/子目录名 —— 改名、删盘都无效。
- **军备方向**:见下一条(攻击方会篡改 classloader 元数据让 maps/枚举对不上)。

## E. classloader 元数据篡改(隐藏注入 dex/so)

- **绕过(进程内自检的根本弱点)**:注入方掌控本进程内存,可反射篡改宿主 classloader 的 `pathList`:
  - 移除指向可写目录的 `nativeLibraryPathElements`(.so 已加载,路径可去);
  - 把注入 dex 元素的源名清空 / 伪装成宿主 base.apk / **物理移除该元素**(配合 hook `findClass` 从内存 DexFile 兜底加载),使"枚举 dexElements 找外来/重复/空名/数量异常"全部查不到。
- **应检测(逐个军备升级)**:
  1. `dexElements` 里来自非安装目录的 dex 源 → 外来注入。
  2. dexFile 真实存在但 `getName()` 为空 → 源名被抹 = 篡改。
  3. 同名重复 dex、`dexElements` 数量 > 应有(base.apk + 真实 splits) → 伪造/多余元素。
  4. **跨层交叉**:`maps` 里有从 code_cache 解压的 dex 段,但 classloader 枚举里找不到对应来源 → 两层对不上 = 元数据被篡改(攻击方很难同时把 maps 和 classloader 伪造一致)。
- **根本认知(务必写进审查结论)**:以上都是**进程内自检**。注入方完全掌控本进程,`Field.get`/`findClass` 等任何读取路径它都能伪造或让元素"物理不存在"。**客户端进程内完整性对注入方必败** —— 它只能抬成本/拖对抗,**不能作为唯一防线**。真正能挡住的是:
  - **Play Integrity STRONG_INTEGRITY**(硬件背书,在注入方进程控制之外);
  - **服务端行为风控 + 设备-账号图谱 + 多维一致性**。
  审查时若发现一个 App **只有**客户端进程内自检、没有硬件背书或服务端兜底 → 这是最大的结构性遗漏。

## F. 指纹伪装做到"全层一致"

- **绕过**:成熟改机会把 Java `Build`、`SystemProperties`、`getprop` 子进程、属性区、`/system/build.prop` 文件层**全部伪装成一致的目标机型**,使"跨层交叉不一致"抓不到。
- **应检测**:
  1. 坚持多通道交叉(Java `Build` vs `getprop` 子进程 vs 属性区磁盘真值 vs build.prop 文件),任一不一致即高危。
  2. 用**子进程 / svc 直读 / 文件层**取真值(绕开进程内 hook)。
  3. **一致性之外的硬约束**:build.prop mtime、file_stat inode/时间、机型↔硬件↔CPU abi 的内在对应关系(如机型声称三星但 hardware=tegu(Pixel))。
  4. **硬件背书**:STRONG_INTEGRITY 的机型/完整性裁决由 TEE 出,伪装层够不到。
- **军备方向**:攻击方把一致性做到极致后,客户端单快照难抓 → 靠"不断增加正交的交叉维度"抬成本 + 服务端跨时间/跨设备一致性。

## G. 属性/文件伪装:挂载层(绕过进程内 hook)

- **绕过**:在目标进程的 mount namespace 内 bind-mount 假 `build.prop` / 假 `getprop`,使文件层与子进程读也变假、且进程内 hook 够不到。
- **应检测**:`/proc/self/mountinfo` 里系统关键文件(build.prop、/system/bin/getprop 等)成了独立 bind-mount 挂载点 —— 正常机上绝不会。用 **svc 直读 mountinfo**(libc 读可能被过滤)。
- **注意**:挂载伪装是**篡改证据**(不是单纯"有工具"),属高危确凿;但攻击方会过滤 mountinfo 读取 → 用 svc 直读对抗。

## H. 位置:GMS 融合定位绕过

- **绕过/盲点**:只 hook 目标 App 侧的定位 API 时,**GMS 融合定位的坐标在 `com.google.android.gms` 进程里算**,经 GMS binder 喂给地图类 App,绕过 app 侧 hook;伪装方只需伪装 app 侧就以为成了,但 GMS 这条链漏了。
- **应检测**:
  1. 坐标一致性应在**系统服务 provider 源头**或**服务端**核对,而非只信 app 侧回包。
  2. IP 归属 ↔ 时区 ↔ GPS 三者一致性(服务端,最稳)。
  3. 原始 GNSS / 运动传感器与"声称位置"的物理自洽(速度、海拔、卫星可见性)。

## I. 检测被"喂假 / 抛异常"对抗

- **绕过**:对抗模块让检测函数恒返回"干净",或拦成抛异常 / 占位值。
- **应检测(元信号)**:检测字段批量 `except_error`、核心字段大面积占位(`6666`/空)、底层信号命中但综合标签全 0 —— 这些**对抗痕迹本身**进 WATCH / 人工复核,别无声吞掉。

---

## 审查时的"遗漏"优先级

1. **结构性缺失(最高)**:只有客户端自检,无 Play Integrity 硬件背书 / 无服务端兜底 → E 节根因,客户端必败。
2. **跨层交叉缺失**:只读 Java 层、不做子进程/svc/文件层交叉 → F/G/维度10。
3. **只认名字不认行为**:框架名/路径硬匹配,改名即废 → B/C/D。
4. **融合/源头盲点**:位置只 hook app 侧(漏 GMS)、root 只查路径(漏 socket/namespace) → H/A。
5. **对抗痕迹被吞**:except_error/占位值不告警 → I。
