# OpenHarmony CFI 安全检测 Agent

LLM 驱动的 CFI（控制流完整性）安全检测工具，支持 OpenHarmony 未 strip 的 .so 库集合的全维度安全分析。

## 功能

- **.so 级 CFI 检测**：通过 `__cfi_check` 符号快速判断 CFI 是否开启
- **函数级分类**：将函数分为 CFI 保护 / 基础设施 / 未保护三类
- **vcall/icall 检测**：扫描间接调用点（BLR），分类虚函数调用 vs 间接调用，统计 CFI 覆盖率
- **PAC 检测**：ARM Pointer Authentication 签名/认证覆盖率（AArch64）
- **BTI 检测**：Branch Target Identification 指令覆盖率（AArch64）
- **完整检测**：一次性执行全部维度，生成全套报告

## 快速开始

```bash
# 安装依赖
pip install pyelftools openpyxl flask httpx typer rich prompt_toolkit cxxfilt

# 配置大模型（首次运行自动引导）
python -m cfi_agent

# 或指定配置文件
python -m cfi_agent --config path/to/config.yaml
```

启动后用自然语言描述需求：

```
你> 对 E:/lib.unstripped_6.1 做完整 CFI 检测
你> 查一下哪些 .so 没开 CFI
你> 搜一下 CheckWant 这个函数受没受保护
你> 对 E:/lib.unstripped_4.1 只做 vcall 检测
```

## 检测模式

| 模式 | 工具 | 内容 | 耗时 |
|------|------|------|------|
| 完整检测 | `run_cfi_detection` | .so级 + 函数级 + vcall + icall + PAC + BTI | ~2-4 分钟 |
| .so 级 | `detect_so_level` | 仅查 CFI 开关，最快 | ~10 秒 |
| 函数级 | `detect_functions` | .so级 + 函数分类 | ~1-3 分钟 |
| vcall | `detect_vcall` | .so级 + 函数级 + vcall | ~1-3 分钟 |
| icall | `detect_icall` | .so级 + 函数级 + icall | ~1-3 分钟 |
| PAC | `detect_pac` | .so级 + 函数级 + PAC | ~1-3 分钟 |
| BTI | `detect_bti` | .so级 + 函数级 + BTI | ~1-3 分钟 |

所有检测均已**并行化**（ProcessPoolExecutor，多核处理）。

## 输出

每次检测在 `output/` 下生成时间戳目录：

```
output/full_20260811_143000/
├── cfi_detection.sqlite    # SQLite 数据库（全部检测结果）
├── index.html              # 前端报告（ECharts 可视化）
├── data.js                 # 嵌入式数据
├── app.py                  # Flask API 服务
├── echarts.min.js          # 图表库
├── cfi_detection_report.xlsx # Excel 报告（4 个 Sheet）
└── 查看报告.pyw            # 一键启动器
```

双击 `查看报告.pyw` 自动启动 Flask 服务并打开浏览器。

## 报告内容

### HTML 报告
- 总体统计卡片 + 饼图（.so 覆盖率、函数保护率、vcall/icall/PAC/BTI 覆盖率）
- 模块列表（可展开，含 mini 饼图）
- .so 详情（点击展开函数列表弹窗）
- 函数搜索（点击查看出现位置，显示 CFI/PAC/BTI 三维度状态）

### Excel 报告
- 总体统计
- 模块与 .so 详情（含 vcall/icall/PAC/BTI 列）
- 无 CFI 的 .so 列表
- 预编译厂商库

### SQLite 数据库
5 张表：`summary`、`modules`、`so_files`、`name_table`、`so_functions`，7 个索引，支持 API 查询。

## 架构

```
cfi_agent/
├── agent.py              # Agent 编排（系统提示、消息循环、MCP 集成）
├── cli.py                # Typer CLI + REPL + 斜杠命令
├── config.py             # YAML 配置加载
├── llm.py                # OpenAI 兼容 HTTP 客户端（流式 + 工具调用 + 重试）
├── mcp_client.py         # MCP 同步客户端
├── tools/                # 工具包（拆分为 4 个模块）
│   ├── __init__.py       # build_registry 组装入口
│   ├── registry.py       # Tool/ToolRegistry + 共享工具
│   ├── detect_tools.py   # 检测工具（7 种检测模式）
│   ├── query_tools.py    # 查询工具（summary/modules/functions/search/sql）
│   └── service_tools.py  # 服务管理 + 元工具（plan/reflect/history/compare）
├── engine/
│   ├── detection.py      # ELF 解析 + ARM/AArch64 指令解码 + 并行检测
│   ├── demangle.py       # c++filt 批量 demangle + 模块聚合
│   ├── db.py             # SQLite 建库（含 snapshot_meta 元数据表）
│   ├── excel_report.py   # openpyxl 4-Sheet 报告
│   ├── html_report.py    # HTML 模板复制
│   ├── api_server.py     # Flask app 模板生成
│   ├── report_utils.py   # 统一报告生成函数
│   ├── service.py        # 进程服务管理
│   ├── app_template.py   # Flask API 服务模板
│   ├── template.html     # 前端报告模板
│   └── constants.py      # 模块描述 + 厂商库列表
└── mcp_servers/
    └── sqlite_server.py  # MCP SQLite 查询服务
```

## CLI 命令

| 命令 | 说明 |
|------|------|
| `/` | 显示命令列表 |
| `/model` | 查看当前模型（`/model <名称>` 可切换） |
| `/tools` | 列出可用工具 |
| `/mcp` | 重连 MCP sqlite 服务 |
| `/setup` | 重新配置大模型与 API key |
| `/clear` | 清除输出目录 |
| `/reset` | 清空对话历史 |
| `/quit` | 退出 |

## 支持的大模型

OpenAI 兼容接口（`/v1/chat/completions`），含流式输出和工具调用：

| 标签 | 模型 ID | 环境变量 |
|------|---------|---------|
| DeepSeek | `deepseek/deepseek-chat` | `DEEPSEEK_API_KEY` |
| 通义千问 | `qwen/qwen-plus` | `DASHSCOPE_API_KEY` |
| OpenAI | `openai/gpt-4o-mini` | `OPENAI_API_KEY` |
| Moonshot Kimi | `moonshot/moonshot-v1-8k` | `MOONSHOT_API_KEY` |
| 智谱 GLM | `zhipu/glm-4` | `ZHIPU_API_KEY` |
| 硅基流动 | `siliconflow/Qwen/Qwen2.5-7B-Instruct` | `SILICONFLOW_API_KEY` |
| 本地 Ollama | `ollama` | 无需 key |

通过 `/setup` 命令配置模型和 API Key，或用 `/model <名称>` 在运行时切换。

## 技术细节

### 检测引擎
- **ELF 解析**：pyelftools，支持 ARM 32-bit Thumb 和 AArch64
- **指令解码**：BL/BLX（Thumb）、BL（AArch64）、BLR、BTI、PAC*SP、AUT*SP、RETAA/RETAB
- **CFI 匹配**：bisect 二分查找 slowpath 调用（O(n log n)）
- **vcall 分类**：BLR 寄存器回溯 + LDR 基址寄存器分析
- **并行化**：ProcessPoolExecutor，所有检测模式均支持

### 系统提示设计
- 工具选择优先级：查询 > 快速 .so 级 > 完整检测
- 检测前列出工具清单
- 检测后自动自检（reflect_check）
- 耗时实时显示（含预计剩余时间）

## License

MIT
