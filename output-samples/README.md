# 检测结果示例

本目录包含 CFI Agent 的实际检测输出样本，供查看检测效果。

## 目录说明

### so_level_4.1/ — .so 级检测（OpenHarmony 4.1，32 位 ARM）
- 1868 个 .so 文件，CFI 开启率 37.3%
- 包含完整 SQLite（692KB，可启动 Flask API 体验交互功能）
- 双击 `index.html` 查看 HTML 报告

### full_6.1/ — 完整检测（OpenHarmony 6.1，64 位 AArch64）
- 2953 个 .so 文件，全维度检测（CFI + 函数级 + vcall + icall + PAC + BTI）
- 不含 SQLite（1.3GB 太大），HTML 报告可查看总体统计和模块列表
- 交互功能需 SQLite 支持，此处不可用

## 查看 HTML 报告

直接用浏览器打开 `index.html` 即可查看：
- 总体统计卡片 + 饼图
- 模块列表（可展开）
- .so 详情（点击查看函数列表）

## 查看 Excel 报告

用 Excel/WPS 打开 `cfi_function_report.xlsx`：
- 总体统计
- 模块与 .so 详情
- 无 CFI 的 .so 列表
- 预编译厂商库
