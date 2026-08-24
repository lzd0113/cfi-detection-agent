---
name: cfi-detection
description: Use when the user wants to detect CFI/PAC/BTI on OpenHarmony .so libraries, query detection results, search functions, or analyze security risks. 触发关键词：CFI 检测、控制流完整性、PAC、BTI、虚函数调用、间接调用、未保护函数、保护率、检测报告、ROP、JOP、安全风险。
---

# OpenHarmony CFI 安全检测领域知识

## 检测的三大安全特性

### 前向 CFI（LLVM CFI）
LLVM 编译期安全插桩：为每个需要保护的函数生成 `func.cfi`（含类型检查的插桩版本）与 `func`（原始函数体）。间接调用通过 `__cfi_slowpath` 校验目标类型，阻断控制流劫持。防护 vtable hijacking、type confusion、间接调用劫持。

### 后向 CFI（PAC）
ARMv8.3 指针认证：函数入口用 PACIBSP 签名返回地址，函数返回用 AUTIBSP/RETAA 验证。防护 ROP（返回地址篡改）。仅 AArch64。

### 前向 CFI（BTI）
ARMv8.5 分支目标标识：函数入口插入 BTI 指令，间接跳转到非 BTI 地址触发异常。防护 JOP（跳转劫持）。仅 AArch64。

## 5 个检测维度

| 维度 | 工具 | 内容 |
|------|------|------|
| .so 级 | check_cfi_enabled | 检查 `__cfi_check` 符号是否定义 |
| 函数级 | classify_functions | func.cfi→受保护; __cfi*→基础设施; 无.cfi→未保护 |
| 调用点 | scan_call_sites | vcall(虚函数)/icall(间接调用) + ±48字节 slowpath CFI 判定 |
| PAC | analyze_pac_bti | 函数级 PACIASP/AUTIBSP 分类: protected/sign_only/no_pac |
| BTI | analyze_pac_bti | 函数入口 BTI 指令覆盖率 |

## 7 种检测模式（均已并行化）

| 模式 | 工具 | 包含维度 | 耗时(v6.1, 2953.so) |
|------|------|---------|---------------------|
| 完整检测 | run_cfi_detection | 全部 | ~2 分钟 |
| .so 级 | detect_so_level | 仅 CFI 开关 | ~26 秒 |
| 函数级 | detect_functions | .so+函数 | ~1.5 分钟 |
| vcall | detect_vcall | .so+函数+vcall | ~1.5 分钟 |
| icall | detect_icall | .so+函数+icall | ~1.5 分钟 |
| PAC | detect_pac | .so+函数+PAC | ~2 分钟 |
| BTI | detect_bti | .so+函数+BTI | ~2 分钟 |

32 位 ARM (v4.1) 的 PAC/BTI 检测会自动跳过（ARMv8.5-A 专属）。

## 21 个 Agent 工具

### 检测工具（7 个）
run_cfi_detection, detect_so_level, detect_functions, detect_vcall, detect_icall, detect_pac, detect_bti

### 查询工具（6 个）
query_summary, query_no_cfi_so, query_functions, search_functions, query_modules, query_sql

### 服务/元工具（8 个）
regenerate_report, start_report_service, stop_report_service, propose_plan, reflect_check, list_history, compare_changes, generate_changes_excel

## 工具使用指引

- 用户要"完整检测 + 全套报告" → `run_cfi_detection`（lib_dir, mode=full）
- 用户只要"快速看哪些 .so 没开 CFI" → `detect_so_level`（最快，不生成报告）
- 用户问"函数保护率" → `detect_functions`
- 用户问"vcall/icall/PAC/BTI 保护率" → 对应 `detect_vcall/icall/pac/bti`
- 已有检测结果时查询 → `query_summary`/`query_modules`/`query_no_cfi_so`/`search_functions`/`query_sql`
- 用户要"搜某函数受没受保护" → `search_functions`（关键词≥2字符，点击可看出现在哪些 .so 中）
- 用户要"对比两次检测变化" → `list_history` → `compare_changes` → `generate_changes_excel`
- 检测后自动调用 `reflect_check` 获取风险评估
- 用户要"重新生成报告" → `regenerate_report`（html/app）
- 用户要"启动/停止服务" → `start_report_service`/`stop_report_service`

## reflect_check 风险评估

检测后调用 `reflect_check` 自动评估安全风险：
- CFI 覆盖率 < 30% → 高风险
- PAC 覆盖率 < 30% → 高风险（ROP 防护薄弱）
- BTI 覆盖率 < 10% → 高风险（JOP 防护薄弱）
- vcall 调用点 > 1000 且 CFI 覆盖率 < 30% → 中风险（虚表劫持）
- icall 调用点 > 100 且 CFI 覆盖率 < 30% → 中风险（间接调用劫持）
- PAC sign_only 比例 > 30% → 中风险（签名未验证）
- .so CFI 覆盖率 < 50% → 中风险

返回 risk_level（高/中/低）、risk_count、risk_assessment（具体风险项 + 修复建议）。

## 关键技术参数

- 指令集：ARM 32-bit Thumb（BLX + LDR 窗口 20 字节）+ AArch64（BLR + LDR 窗口 48 字节）
- CFI 保护判定：调用点 ±48 字节 slowpath 调用（bisect O(n log n) 查找）
- 并行检测：ProcessPoolExecutor 多核并行
- 输入必须用 `lib.unstripped/`（strip 后 `__cfi_check` 丢失）

## 输出文件

| 文件 | 说明 |
|------|------|
| cfi_detection.sqlite | 结果数据库（6 表 7 索引 + snapshot_meta 元数据表） |
| index.html | 前端报告（ECharts 饼图 + 函数搜索 + 位置弹窗 + 动态列） |
| data.js | 嵌入式数据（summary + modules） |
| echarts.min.js | 图表库 |
| app.py | Flask API（6 路由） |
| cfi_detection_report.xlsx | Excel 报告（4 Sheet） |
| 查看报告.pyw | 一键启动器（自动启服务 + 开浏览器） |

## 模块风险等级

- **高风险**（无 CFI）：security（密钥管理）、account（账户认证）、tee（可信执行环境）、useriam（生物特征）
- **中风险**：arkui、arkcompiler、communication、multimedia、distributeddatamgr、bundlemanager、graphic、hdf
- **低风险**：thirdparty（预编译无法修改）、xts、testfwk（非生产代码）
