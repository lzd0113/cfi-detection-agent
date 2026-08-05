---
name: cfi-detection
description: Use when the user wants to detect CFI (Control-Flow Integrity) on OpenHarmony .so libraries, ask about CFI coverage, protected/unprotected functions, vcall/icall, or query CFI detection results. 触发关键词：CFI 检测、控制流完整性、.so、虚函数调用、间接调用、未保护函数、保护率、检测报告。
---

# OpenHarmony CFI 安全检测领域知识

## CFI 是什么

CFI（Control-Flow Integrity，控制流完整性）是 LLVM 编译期安全插桩：为每个需要保护的函数生成 `func.cfi`（含类型检查的插桩版本）与 `func`（原始函数体）。所有间接调用指向 `.cfi` 版本。运行时通过 `__cfi_slowpath` 校验目标类型，阻断控制流劫持。

## 检测三个维度

- **.so 级**：是否开启 CFI（存在已定义的 `__cfi_check` 符号，`st_value != 0`）
- **函数级**：`func.cfi` → 受保护；`__cfi*`/`.L.cfi*` → CFI 基础设施；只有原始体无 `.cfi` 版本 → 真正未保护
- **调用点级**：vcall（虚函数调用，间接调用前有 LDR 加载 vtable 指针）；icall（非 vtable 间接调用）。调用点 ±48 字节内有 `__cfi_slowpath` 调用 → 有 CFI 保护。自动识别架构：ARM 32-bit Thumb（BLX Rn + 20 字节 LDR 窗口）或 AArch64（BLR Xn + 48 字节 LDR 窗口）

## 10 个 Skill（已封装为 Agent 工具，无需手写算法）

1. .so 级检测（查 `__cfi_check`） 2. 函数级分类 3. vcall 检测 4. icall 检测
5. 函数名 demangle（c++filt 批量，50000/批） 6. SQLite 生成（5 表 3 索引）
7. Flask REST API（端口 5000，CORS 全开） 8. HTML 前端（ECharts 饼图 + fetch 懒加载）
9. Excel 报告（4 Sheet，分组折叠，条件着色） 10. 后台启动服务 + .bat

## 工具使用指引

- 用户要"完整检测 + 生成全套报告" → `run_cfi_detection`（lib_dir + mode=full/fast）。full≈3分钟产出 SQLite/HTML/Excel，fast≈1分钟仅 .so 级
- 用户只要"快速看哪些 .so 没开 CFI" → `detect_so_level`（仅 Skill 1，最快，不生成报告，只返回统计）
- 用户问"函数保护率 / 哪些函数没保护" → `detect_functions`（Skill 2，只出统计）
- 用户问"vcall 保护率" → `detect_vcall`（Skill 3，只出统计）
- 用户问"icall 保护率" → `detect_icall`（Skill 4，只出统计）
- 用户问"哪些没开 CFI"（已有检测结果库时）→ `query_no_cfi_so`（按 module 过滤，读 SQLite）
- 用户问"某函数受没受保护/搜函数" → `search_functions`（关键词≥2字符）
- 用户要"重新生成报告页面" → `regenerate_report`（html/app）
- 用户要"直接 SQL 查库" → MCP 工具 `mcp_list_tables`/`mcp_describe_table`/`mcp_query`
- 用户要"启动/停止报告服务" → `start_report_service`/`stop_report_service`
- 用户问"总体怎么样" → `query_summary` 或 `query_modules`
- 用户要"对比两次检测/看哪些 .so 开了 CFI 变化" → 先 `list_history` 看历史存档，再 `compare_changes(version_a=存档名)` 对比当前（结果存 changes 表），最后 `generate_changes_excel` 生成变化对照 Excel（开启CFI 绿/关闭CFI 红）
- 用户要"自检检测结果合理性" → `reflect_check`（对 summary 做字段一致性/保护率范围校验）

## 关键技术参数

- 支持指令集：ARM 32-bit Thumb（小端序半字）+ AArch64（32 位定长，自动检测 `elf.get_machine_arch()`）
- vcall LDR 扫描窗口：Thumb=BLX 前 20 字节（10 半字）；AArch64=BLR 前 48 字节（12 条指令）
- CFI 保护判定窗口：调用点 ±48 字节
- slowpath PLT 偏移：`.plt + 32 + index × 16`（两种架构相同）
- 重定位表：Thumb 用 `.rel.plt`，AArch64 用 `.rela.plt`（均已支持）
- 输入必须用 `lib.unstripped/`（strip 后 `__cfi_check` 会丢失）

## 输出文件（生成到 output_dir/cfi_detection_output 或 output_dir）

| 文件 | 说明 |
|------|------|
| cfi_detection.sqlite | 结果数据库（summary/modules/so_files/name_table/so_functions） |
| index.html | 直接双击在浏览器查看（检测时已后台启动 Flask 服务，端口 5000；若服务未跑则双击 启动服务.bat） |
| app.py | Flask API，启动后访问 http://localhost:5000 |
| cfi_function_report.xlsx | 4 Sheet 离线报告 |
| 启动服务.bat / 停止服务.bat | 服务启停 |

## 模块名映射（路径第一段 → 中文名）

ability=应用能力管理 account=账户管理 ai=人工智能 arkui=方舟UI引擎
bundlemanager=包管理 commonlibrary=公共基础库 communication=通信
distributeddatamgr=分布式数据管理 filemanagement=文件管理 graphic=图形
hdf=HDF驱动框架 hiviewdfx=可靠性与可观测性 multimedia=多媒体
notification=通知与事件 powermgr=电源管理 security=安全
startup=系统启动 telephony=电话服务 thirdparty=第三方库
usb=USB管理 web=Web引擎 window=窗口管理 （完整表见 SQLite modules.desc）
