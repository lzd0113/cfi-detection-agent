# OpenHarmony CFI 安全检测 Agent

LLM 驱动的 CFI（控制流完整性）安全检测工具，支持 OpenHarmony 未 strip 的 .so 库集合的全维度安全分析。覆盖前向 CFI（LLVM CFI + BTI）与后向 CFI（PAC），支持 ARM 32-bit Thumb 和 AArch64 双架构，通过自然语言对话即可触发检测、查询结果、生成报告。

## 快速开始（3 步）

### 第 1 步：下载

```bash
git clone https://github.com/Star-Shield-Security/2026-intern-scan-agents.git
cd 2026-intern-scan-agents
```

或直接在 GitHub 页面点 **Code → Download ZIP**，解压即可。

### 第 2 步：启动

**Windows**：双击 `cfi.bat`

首次运行会自动安装依赖（约 1 分钟），然后弹出大模型选择列表：

```
选择大模型：
  1. DeepSeek (deepseek-chat)
  2. 通义千问 (qwen-plus)
  3. OpenAI (gpt-4o-mini)
  4. Moonshot Kimi (moonshot-v1-8k)
  5. 智谱 GLM (glm-4)
  6. 硅基流动 (Qwen2.5-7B)
  7. 本地 Ollama (无需 key)

输入编号: 1
粘贴 API Key: sk-xxxxxxxx
✓ 配置完成
```

输入编号选模型，粘贴对应平台的 API Key，自动保存到 `.env` 和 `config.yaml`，下次启动免配置。

> **没有 API Key？** 推荐 [DeepSeek](https://platform.deepseek.com/)（免费额度多、价格便宜）。也可用本地 [Ollama](https://ollama.com/)（选 7，完全免费）。

### 第 3 步：对话检测

启动后直接用自然语言描述需求：

```
你> 对 E:/lib.unstripped_6.1 做完整 CFI 检测
你> 查一下哪些 .so 没开 CFI
你> 搜一下 CheckWant 这个函数受没受保护
你> 对 E:/lib.unstripped_4.1 只做 vcall 检测
```

> **输入目录说明**：需要传入未 strip 的 .so 集合路径（编译产物 `lib.unstripped/` 目录）。strip 后的 .so 会丢失 `__cfi_check` 符号，无法检测。

## 检测模式

| 模式 | 对话示例 | 内容 | 耗时(2953.so) |
|------|---------|------|-------------|
| 完整检测 | "做完整检测" | .so级 + 函数级 + vcall + icall + PAC + BTI | ~2 分钟 |
| .so 级 | "快速看哪些没开 CFI" | 仅查 CFI 开关，最快 | ~26 秒 |
| 函数级 | "看函数保护率" | + 函数分类 | ~1.5 分钟 |
| vcall | "做 vcall 检测" | + 虚函数调用覆盖率 | ~1.5 分钟 |
| icall | "做 icall 检测" | + 间接调用覆盖率 | ~1.5 分钟 |
| PAC | "做 PAC 检测" | + 返回地址签名/认证（仅 64 位） | ~2 分钟 |
| BTI | "做 BTI 检测" | + 分支目标标识（仅 64 位） | ~2 分钟 |

> **32 位 vs 64 位**：PAC/BTI 是 AArch64 专属特性。如果 .so 集合全是 32 位 ARM，PAC/BTI 检测会自动跳过并提示"不适用"。

## 输出产物

每次检测在 `output/` 下生成时间戳目录：

```
output/full_20260811_143000/
├── cfi_detection.sqlite      # SQLite 数据库（6 表 7 索引）
├── index.html                 # 前端报告（ECharts 可视化）
├── data.js                    # 嵌入式数据（静态展示用）
├── echarts.min.js             # 图表库
├── app.py                     # Flask API 服务
├── cfi_detection_report.xlsx  # Excel 报告（4 个 Sheet）
└── 查看报告.pyw               # 一键启动器（自动启服务+开浏览器）
```

### 查看报告

- **双击 `查看报告.pyw`**：自动启动 Flask 服务并打开浏览器
- **直接双击 `index.html`**：静态查看总体统计和模块列表（交互功能需 Flask 服务）
- **打开 `cfi_detection_report.xlsx`**：用 Excel/WPS 查看 4 个 Sheet

### HTML 报告功能

- 总体统计卡片 + 覆盖率环形图（.so / 函数 / vcall / icall / PAC / BTI）
- 模块列表（可展开，含 mini 饼图 + CFI/保护率 badge）
- .so 详情（点击展开函数列表弹窗，显示 mangled_count 标记）
- 函数搜索（输入关键词 → 点击查看出现位置 → CFI/PAC/BTI 三维度状态）
- 动态列（按检测维度自动显示 CFI/PAC/BTI 列）

### Excel 报告（4 Sheet）

| Sheet | 内容 |
|-------|------|
| 总体统计 | .so 总数、CFI 开启/未开启、函数保护率、vcall/icall/PAC/BTI 覆盖率 |
| 模块与.so详情 | 按模块分组折叠，含每项计数和保护率 |
| 无CFI的.so | 所有 cfi_enabled=0 的 .so，红色标注 |
| 预编译厂商库 | Mali GPU / RGA / Rockchip MPP / RKAIQ（闭源驱动） |

### SQLite 数据库

6 张表 + 7 个索引：

| 表 | 内容 | 行数级 |
|----|------|--------|
| summary | 检测总体统计 | 1 行 |
| modules | 按模块聚合统计 | ~54 行 |
| so_files | 每个 .so 的详细数据 | ~2953 行 |
| name_table | 去重后的 demangled 函数名 | 百万级 |
| so_functions | 函数与 .so 的关联表 | 百万级 |
| snapshot_meta | 检测快照元数据（类型/时间/维度） | 1 行 |

## CLI 命令

在对话中随时输入斜杠命令：

| 命令 | 说明 |
|------|------|
| `/` | 显示命令列表 |
| `/model` | 查看当前模型（`/model deepseek/deepseek-chat` 可切换） |
| `/tools` | 列出 21 个可用工具 |
| `/setup` | 重新配置大模型与 API Key |
| `/mcp` | 安装并连接 MCP SQLite 服务 |
| `/clear` | 清除输出目录 |
| `/reset` | 清空对话历史 |
| `/quit` | 退出 |

## 支持的大模型

OpenAI 兼容接口（`/v1/chat/completions`），支持流式输出和工具调用：

| 平台 | 模型 ID | 环境变量 | 获取 Key |
|------|---------|---------|---------|
| DeepSeek | `deepseek/deepseek-chat` | `DEEPSEEK_API_KEY` | platform.deepseek.com |
| 通义千问 | `qwen/qwen-plus` | `DASHSCOPE_API_KEY` | dashscope.aliyun.com |
| OpenAI | `openai/gpt-4o-mini` | `OPENAI_API_KEY` | platform.openai.com |
| Moonshot Kimi | `moonshot/moonshot-v1-8k` | `MOONSHOT_API_KEY` | platform.moonshot.cn |
| 智谱 GLM | `zhipu/glm-4` | `ZHIPU_API_KEY` | open.bigmodel.cn |
| 硅基流动 | `siliconflow/Qwen/Qwen2.5-7B-Instruct` | `SILICONFLOW_API_KEY` | siliconflow.cn |
| 本地 Ollama | `ollama` | 无需 key | ollama.com（先 `ollama serve`） |

首次运行 `cfi.bat` 会自动引导选择，也可以之后用 `/setup` 或 `/model` 切换。

## 5 个检测维度

| 维度 | 防护的攻击 | 检测方法 | 架构 |
|------|-----------|---------|------|
| .so 级 | 整体安全基线 | 检测 `__cfi_check` 符号 | 32位+64位 |
| 函数级 | vtable hijacking / 间接调用劫持 | 查 `.cfi` 后缀符号分类 | 32位+64位 |
| vcall | 虚函数调用劫持 | BLR 扫描 + 寄存器回溯 + slowpath 判定 | 32位+64位 |
| icall | 间接调用劫持 | 同 vcall，分类不同 | 32位+64位 |
| PAC | ROP（返回地址篡改） | HINT 指令扫描 + 函数级 sign/auth 分类 | 仅 AArch64 |
| BTI | JOP（跳转劫持） | 函数入口 BTI 指令检查 | 仅 AArch64 |

## Agent 架构

```
cfi_agent/
├── cfi.bat                    # Windows 一键启动
├── config.yaml                # 配置文件（模型/输入目录）
├── agent.py                   # Agent 编排（系统提示 + 消息循环 + 工具调度）
├── cli.py                     # CLI 交互（Typer + rich + prompt_toolkit）
├── llm.py                     # LLM 客户端（流式输出 + 工具调用 + 指数退避重试）
├── mcp_client.py              # MCP 客户端（标准化工具协议，可选）
├── tools/                     # 工具包（21 个工具）
│   ├── __init__.py            # 组装入口
│   ├── registry.py            # ToolRegistry 基类
│   ├── detect_tools.py        # 7 个检测工具
│   ├── query_tools.py         # 6 个查询工具
│   └── service_tools.py       # 8 个服务/元工具
├── engine/                    # 检测引擎 + 报告生成
│   ├── detection.py           # ELF 解析 + 指令解码 + 并行检测
│   ├── demangle.py            # c++filt 批量 demangle
│   ├── report_utils.py        # 统一报告生成
│   ├── db.py                  # SQLite 建库（6 表 7 索引）
│   ├── excel_report.py        # Excel 报告（4 Sheet）
│   ├── template.html         # 前端报告模板（ECharts）
│   ├── app_template.py        # Flask API 模板
│   ├── html_report.py         # HTML 模板复制
│   ├── api_server.py          # Flask 模板生成
│   ├── service.py             # 进程服务管理
│   └── constants.py           # 模块描述 + 厂商库
├── knowledge/                 # 安全知识库（加载到系统提示）
│   ├── cfi_principles.md      # CFI 原理与编译选项
│   ├── attack_vectors.md      # ROP/JOP/vtable hijacking 攻击向量
│   ├── risk_assessment.md     # 风险分级标准
│   ├── arm_security.md        # PAC/BTI 原理
│   ├── android_experience.md  # 安卓部署经验
│   └── module_risk_profile.md # 模块风险画像
├── mcp_servers/
│   └── sqlite_server.py       # MCP SQLite 查询服务（可选）
├── skills/
│   └── cfi-detection/SKILL.md # Skill 定义
├── docs/                      # 技术文档
└── 答辩材料/                  # PPT + 演示视频 + 报告
```

## 21 个 Agent 工具

### 检测工具（7 个）
| 工具 | 说明 |
|------|------|
| `run_cfi_detection` | 完整检测全流程（全维度 + 全套报告） |
| `detect_so_level` | 仅 .so 级检测（最快摸底） |
| `detect_functions` | .so 级 + 函数分类 |
| `detect_vcall` | + 虚函数调用覆盖率 |
| `detect_icall` | + 间接调用覆盖率 |
| `detect_pac` | + PAC 签名/认证覆盖率（仅 64 位） |
| `detect_bti` | + BTI 分支目标覆盖率（仅 64 位） |

### 查询工具（6 个）
| 工具 | 说明 |
|------|------|
| `query_summary` | 查总体统计 |
| `query_modules` | 查模块覆盖概览 |
| `query_no_cfi_so` | 查未开 CFI 的 .so 列表 |
| `query_functions` | 查某 .so 的函数列表 |
| `search_functions` | 按关键词搜索函数名 |
| `query_sql` | 执行任意 SELECT 查询 |

### 服务/元工具（8 个）
| 工具 | 说明 |
|------|------|
| `propose_plan` | 先规划后执行（适配低性能模型） |
| `reflect_check` | 自检 + 风险评估（7 条规则，高/中/低风险） |
| `regenerate_report` | 重新生成报告（不重跑检测） |
| `start_report_service` | 启动 Flask Web 服务 |
| `stop_report_service` | 停止 Flask 服务 |
| `list_history` | 列出历史检测存档 |
| `compare_changes` | 对比两次检测变化 |
| `generate_changes_excel` | 生成变化对照 Excel |

## 技术细节

- **ELF 解析**：pyelftools，支持 ARM 32-bit Thumb 和 AArch64
- **指令解码**：BL/BLX（Thumb）、BL（AArch64）、BLR、BTI、PAC*SP、AUT*SP、RETAA/RETAB
- **CFI 匹配**：bisect 二分查找 slowpath 调用（O(n log n)）
- **vcall 分类**：BLR 寄存器回溯 + LDR 基址寄存器分析
- **并行化**：ProcessPoolExecutor 多核并行，所有检测模式均支持
- **SQLite 优化**：先插数据后建索引（快 10 倍）
- **安全知识库**：6 个 markdown 文件（10KB）加载到系统提示，检测后自动风险评估
- **LLM 重试**：429/500/502/503 指数退避重试，网络错误不重试
- **SQL 注入防护**：SELECT 限制 + 多语句拦截 + 白名单校验

## License

MIT
