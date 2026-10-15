# 示例:某 App 设备风控检测覆盖度审查报告(样例)

> 这是一份**虚构样例**,用来示范 `SKILL.md` 工作流产出的报告长什么样。目标 App 名为占位 `com.example.app`。
> A fictional sample showing the report shape produced by the `SKILL.md` workflow.

## 一、现状概览
- 已覆盖:Root(路径/包名)、模拟器(属性)、Hook(maps 名字匹配)、位置(mock provider)。
- 部分覆盖:指纹(仅 Java `Build`,无跨层交叉)。
- 缺失:进程内完整性、跨层真值读取、云手机传感器、硬件背书、服务端兜底。
- 主要依赖层:**几乎全在 Java 层**;native 仅一个浅检测 .so;无服务端交叉。

## 二、覆盖度矩阵
| 维度 | 状态 | 在哪一层 | 可被哪种绕过攻破 | 严重度 |
|------|------|---------|----------------|--------|
| Root | 部分 | Java | Shamiko 隐藏路径/包 → 失效;无 socket/namespace/attestation | high |
| Hook | 部分 | Java/Native | 框架改随机名 → 名字匹配失效;无 rwx/CRC/完整性 | high |
| 模拟器 | 有 | Java | 新型 ARM 云机绕过 | medium |
| 云手机 | 无 | — | 无传感器/软渲/容器检测 | high |
| 指纹伪装 | 部分 | Java | 只读 Build,无 file/native 交叉 → 改机全绕 | critical |
| 进程内完整性 | 无 | — | 任意 dex/so 注入无感 | high |
| 跨层真值 | 无 | — | 挂载/属性伪装无从交叉 | high |
| 位置 | 部分 | Java | 只查 mock,GMS 融合/服务端一致性缺失 | high |

## 三、遗漏清单(按优先级)
1. **[critical] 结构性**:无 Play Integrity、无服务端兜底 —— 客户端自检对注入方必败。→ 接入 STRONG_INTEGRITY(服务端带 nonce 验签)+ 服务端行为/图谱兜底。
2. **[critical] 指纹无跨层交叉**:只读 Java `Build`,改机一改全绕。→ 增加 `getprop` 子进程 / 文件层 / 属性区 真值,与 Java 层交叉;不一致即高危。
3. **[high] 只认名字**:Hook/Root 全靠名字/路径匹配,改名即废。→ 改结构/行为判据(rwx 页、text CRC、socket、namespace)。
4. **[high] 无进程内完整性**:→ 枚举 classloader dexElements/native 路径来源,maps 交叉(并说明其上限)。
5. **[high] 位置源头盲点**:只查 mock provider,漏 GMS 融合与服务端一致性。→ 服务端 IP↔时区↔GPS 交叉。

## 四、.so / SDK 发现
- 内置 `libxxx.so`:仅含 root 路径/qemu 属性字符串,**无** svc 直读、无完整性校验、无跨层 → 浅检测,属 high 遗漏来源。
- 未识别到商用风控 SDK;检测到热修复框架痕迹 → 注意:它是"注入检测"的合法误报源,若将来加进程内完整性检测,需对其做白名单消歧。

## 五、分级合理性问题
- "检测到 su 路径"直接判高危红 → 应降为**怀疑**(仅 root 存在,无伪装)。
- 无"≥2 中危升高危"累加逻辑。
- 检测异常(读取失败)被无声吞掉,未进 WATCH。

## 六、改进路线
- **立刻**:接 Play Integrity + 服务端 nonce 验签;指纹加 `getprop` 子进程交叉。
- **短期**:Root/Hook 改结构/行为判据;分级区分确凿/怀疑 + 累加。
- **中长期**:进程内完整性 + 服务端行为/图谱兜底;.so 下沉 svc 直读与完整性校验。

---
> 机器可读结果:见随附填好的 `coverage.yaml`(每维 status/where/notes)。
