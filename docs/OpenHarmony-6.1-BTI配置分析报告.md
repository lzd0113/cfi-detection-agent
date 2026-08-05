# OpenHarmony 6.1 源码 BTI 配置分析报告

> 分析路径:`E:\open_harmony_6.1\OpenHarmony-v6.1-Release\OpenHarmony`
> 分析日期:2026-07-27

## 一、概述

BTI(Branch Target Identification,分支目标识别)是 ARMv8.5-A 引入的安全特性,用于缓解 JOP(Jump-Oriented Programming)等控制流劫持攻击。编译器通过在合法间接跳转目标处插入 BTI 指令(着陆垫),CPU 仅允许跳转到这些标记位置,从而阻止攻击者跳转到任意代码中间执行。

本报告梳理 OpenHarmony 6.1 Release 源码中与 BTI 相关的所有配置点,说明其启用条件、生效范围与实际使用情况。

---

## 二、BTI 相关配置点分布

| 序号 | 文件 | 作用层级 | 关键行 |
| :--- | :--- | :--- | :--- |
| 1 | `build/config/security/security_config.gni` | 全局能力开关 | 21, 44–50 |
| 2 | `build/templates/cxx/cxx.gni` | 编译模板实现(4 处对称逻辑) | 328–426, 1062–1154, 1617–1713, 1938–2034 |
| 3 | `third_party/musl/musl_template.gni` | musl libc 强制启用 | 532–534, 674–679 |
| 4 | `vendor/hihope/*/security_config/sanitizer_check_list.gni` | 易混淆项(非 BTI) | 345–346 等 |

---

## 三、详细分析

### 1. 全局能力开关

**文件**:`build/config/security/security_config.gni`

```gn
declare_args() {
  support_branch_protector_bti = false   # 第 21 行,默认关闭
}
# bti is supported in armv8.5       # 第 44 行注释
if (target_cpu == "arm64" && is_ohos && is_standard_system && !is_mingw) {
  if (use_pac_ret) {
    support_branch_protector_pac_ret = true   # PAC(ARMv8.3)
  }
  support_branch_protector_bti = true          # 第 49 行,arm64 标准系统自动开启
}
```

**启用条件**:
- `target_cpu == "arm64"`
- `is_ohos == true`(目标平台为 OHOS)
- `is_standard_system == true`(标准系统)
- `!is_mingw`(非 Windows 交叉编译宿主)

满足上述条件时,`support_branch_protector_bti` 被置为 `true`,表示该工具链/平台**具备** BTI 能力。注意:此处仅声明"能力可用",并不自动给所有目标加上 BTI 编译标志。

同时开启的还有 PAC-RET(Pointer Authentication,ARMv8.3),二者常组合使用。

---

### 2. 编译模板实现

**文件**:`build/templates/cxx/cxx.gni`

该文件对 4 类目标模板(`ohos_*` 系列)实现了相同的分支保护逻辑,对称出现 4 次:
- 第 328–426 行
- 第 1062–1154 行
- 第 1617–1713 行
- 第 1938–2034 行

#### 2.1 参数白名单

`branch_protector_frt` 被列入 `forward_variables_from` 白名单(cxx.gni:291、1002、1571、1902),组件可在 BUILD.gn 中通过该参数按需触发 BTI。

#### 2.2 判定与编译标志注入逻辑

```gn
pac_ret = false
bti = false
if (defined(invoker.branch_protector_frt)) {
  if (invoker.branch_protector_frt == "bti" &&
      support_branch_protector_bti) {
    bti = true
  }
}

if (bti && pac_ret) {
  cflags  += [ "-mbranch-protection=pac-ret+leaf+b-key+bti" ]
  ldflags += [ "-Wl,-z,force-bti" ]
} else if (bti && !pac_ret) {
  cflags  += [ "-mbranch-protection=bti" ]
  ldflags += [ "-Wl,-z,force-bti" ]
} else if (!bti && pac_ret) {
  cflags  += [ "-mbranch-protection=pac-ret+leaf+b-key" ]
}
```

**关键说明**:
- BTI 实际生效需同时满足两个条件:
  1. 全局 `support_branch_protector_bti == true`(arm64 标准系统自动满足);
  2. 目标显式传入 `branch_protector_frt = "bti"`。
- 编译标志组合:
  - BTI + PAC-RET:`-mbranch-protection=pac-ret+leaf+b-key+bti`
  - 仅 BTI:`-mbranch-protection=bti`
- 链接标志:`-Wl,-z,force-bti`(强制所有输入对象启用 BTI 标记)

#### 2.3 实际使用情况

对全仓库 `*.gn` / `*.gni` 文件检索 `branch_protector_frt = "bti"` 的显式赋值:

| 检索模式 | 命中结果 |
| :--- | :--- |
| `branch_protector_frt\s*=\s*"bti"` | 0 处 |
| `branch_protector_frt\s*=`(任意赋值) | 0 处(仅模板内的 `==` 比较命中) |

**结论**:在 OpenHarmony 6.1 Release 源码中,没有任何业务组件 BUILD.gn 显式设置 `branch_protector_frt = "bti"`。该参数仅作为机制预留,业务侧尚未启用。

---

### 3. musl libc 强制启用

**文件**:`third_party/musl/musl_template.gni`

这是仓库内**唯一真正打了 BTI 编译标志**的位置。

#### 3.1 宏定义(第 532–534 行)

```gn
if (musl_arch == "aarch64") {
  defines += [ "BTI_SUPPORT" ]
}
```
在 aarch64 架构下定义 `BTI_SUPPORT` 宏,供 musl 源码条件编译使用。

#### 3.2 编译标志(第 674–679 行)

```gn
if (musl_arch == "aarch64") {
  cflags += [
    "-mbranch-protection=bti",
    "-mmark-bti-property",
  ]
}
asmflags = cflags
```
- `-mbranch-protection=bti`:启用 BTI 分支保护
- `-mmark-bti-property`:在 ELF 对象上标记 BTI 属性(供链接器识别)
- `asmflags = cflags`:汇编代码同样应用上述标志

**作用**:musl C 库在 aarch64 下无条件启用 BTI,确保动态链接器与基础运行时具备 BTI 保护,为后续启用 BTI 的可执行文件提供基础支撑。

---

### 4. 易混淆匹配项(非 BTI 安全特性)

检索 BTI 关键字时出现的部分结果与"分支目标识别"无关,需排除:

| 文件 | 内容 | 实际含义 |
| :--- | :--- | :--- |
| `vendor/hihope/*/security_config/sanitizer_check_list.gni` | `btipc_static`、`btipc_service` | **蓝牙 IPC** 模块名 |
| `foundation/multimedia/image_framework/.../image_*.gni` | `libtiff`、`has_libtiff` | **TIFF 图像库**,字段名包含子串 "bti" |

以上均非 BTI 安全特性,分析时应予剔除。

---

## 四、BTI 启用链路总览

```
┌─────────────────────────────────────────────────────────────┐
│ build/config/security/security_config.gni                   │
│   support_branch_protector_bti = true  (arm64 + 标准系统)    │
└───────────────────────┬─────────────────────────────────────┘
                        │ 能力可用
                        ▼
┌─────────────────────────────────────────────────────────────┐
│ build/templates/cxx/cxx.gni  (4 处对称逻辑)                 │
│   需要 target 传入 branch_protector_frt = "bti" 才注入:      │
│     cflags  += -mbranch-protection=...bti                   │
│     ldflags += -Wl,-z,force-bti                             │
│   ⚠ 仓库内无任何组件 BUILD.gn 显式设置该参数 → 业务侧未启用 │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ third_party/musl/musl_template.gni  (aarch64 无条件启用)    │
│   defines += "BTI_SUPPORT"                                  │
│   cflags  += -mbranch-protection=bti  -mmark-bti-property   │
│   ✅ 仓库内唯一真正应用 BTI 编译标志的位置                  │
└─────────────────────────────────────────────────────────────┘
```

---

## 五、结论与建议

### 5.1 现状结论

1. **机制完备**:OpenHarmony 6.1 构建系统已具备完整的 BTI 支持链路,含全局开关、模板注入、musl libc 强制启用三层。
2. **业务未启用**:业务组件层没有任何 BUILD.gn 通过 `branch_protector_frt = "bti"` 显式启用 BTI,即 BTI 在应用/Native 业务代码层面**实际未生效**。
3. **基础库已保护**:musl C 库在 aarch64 下无条件启用 BTI,运行时基础层具备保护能力。

### 5.2 启用建议(若需全量开启 BTI)

- **方案 A(按需启用)**:在高安全等级组件的 BUILD.gn 目标中显式添加 `branch_protector_frt = "bti"`,粒度可控。
- **方案 B(全量默认开启)**:在 `cxx.gni` 模板中将 `bti` 默认值改为依赖 `support_branch_protector_bti` 自动置 `true`(需评估兼容性,部分含手写汇编/非标准跳转的目标可能因 BTI 触发异常)。
- **配套验证**:启用后需检查
  - 内核是否使能 BTI(`SCTLR_ELx.BT` 位);
  - 链接器对 `-Wl,-z,force-bti` 的支持版本;
  - 含内联汇编的目标是否正确标注着陆垫(`bti c` / `bti jc`),避免运行时 SIGILL。

---

## 六、参考文件清单

| 文件 | 行号 | 说明 |
| :--- | :--- | :--- |
| `build/config/security/security_config.gni` | 21, 44–50 | 全局 BTI 能力开关 |
| `build/templates/cxx/cxx.gni` | 291, 328–426 | 模板参数白名单与 BTI 注入逻辑(块1) |
| `build/templates/cxx/cxx.gni` | 1002, 1062–1154 | 模板参数白名单与 BTI 注入逻辑(块2) |
| `build/templates/cxx/cxx.gni` | 1571, 1617–1713 | 模板参数白名单与 BTI 注入逻辑(块3) |
| `build/templates/cxx/cxx.gni` | 1902, 1938–2034 | 模板参数白名单与 BTI 注入逻辑(块4) |
| `third_party/musl/musl_template.gni` | 532–534 | musl BTI_SUPPORT 宏定义 |
| `third_party/musl/musl_template.gni` | 674–679 | musl BTI 编译标志注入 |
