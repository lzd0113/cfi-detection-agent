import json
import os

from .config import (
    load_config, get_llm_config, get_defaults, get_skill_paths, get_references,
)
from .llm import LLMClient
from .tools import build_registry
from .mcp_client import create_sqlite_client, mcp_tools_to_agent
from .skills import load_skills, build_skill_context
from .references import build_reference_context

MAX_TOOL_RESULT = 8000


class Agent:
    def __init__(self, config_path=None, model_override=None, on_log=None, on_progress=None):
        self.config_path = config_path
        cfg = load_config(config_path)
        self.cfg = cfg

        llm_cfg = get_llm_config(cfg)
        if model_override:
            llm_cfg['model'] = model_override
        self.llm = LLMClient.from_config(llm_cfg)

        self.defaults = get_defaults(cfg)
        self.registry = build_registry(defaults=self.defaults, on_log=on_log, on_progress=on_progress)

        self.skills = load_skills(get_skill_paths(cfg))
        self.references = get_references(cfg)
        self.mcp_client = None

        self.messages = []
        self._reset_messages()
        self._connect_mcp()

    def _reset_messages(self):
        self.messages = [{"role": "system", "content": self._system_prompt()}]

    def _system_prompt(self):
        parts = [
            "你是 OpenHarmony CFI 安全检测 Agent，帮助用户对 OpenHarmony 系统的 .so 共享库集合执行 CFI（控制流完整性）安全检测并解读结果。",
            "",
            "你的工作方式：通过工具完成实际工作——执行检测、查询结果、生成报告、管理服务。绝不要臆造检测结果或函数名，必须调用工具获取真实数据后再回答用户。",
            "",
            "检测算法本身是确定性的（pyelftools 解析 ELF + ARM 32-bit Thumb 指令解码），你的职责是：理解用户意图 → 选择并调用合适工具 → 传参 → 解读返回结果给用户。检测耗时较长（full≈3分钟），调用 run_cfi_detection 前可告知用户预计耗时。",
            "",
            "工具选择原则（重要，务必遵守）：查询/分析类需求（如\"哪些没开CFI\"\"某模块情况\"\"某函数是否受保护\"\"总体统计\"\"对比变化\"）优先用 query_* 工具查已有 SQLite（秒回，不跑检测）；若返回\"未找到数据库\"说明尚未检测，再用 detect_so_level（快速 .so 级，不生成报告）。只有用户明确要\"执行检测\"\"跑一遍\"\"生成全套报告\"才用 run_cfi_detection（full 全流程+SQLite/HTML/Excel，约3分钟）。切勿把查询需求当成完整检测。",
            "回答用户时用中文。涉及数值时直接引用工具返回的统计。",
            "规划优先：对完整检测或需要调用多个 detect_* 工具的组合检测任务，先用 propose_plan 工具提出执行计划（目标 + 步骤 + 每步用哪个工具 + 原因）供用户确认，用户批准后再依次执行；对单维度快速查询（如只看 vcall 保护率、搜某函数、查总体统计）可直接调用对应工具，不必先规划。",
            "组合调用：用户要多个维度时（如\"分析 .so 级和函数级\"\"看 vcall 和 icall 情况\"），可依次调用多个 detect_* 工具组合，每次调用结果会回传给你，你结合全部结果综合回答。简单 2-3 个工具组合可直接调用，不必每次都走 propose_plan。",
            "维度包含（重要）：detect_functions 已含 .so 级检测（不需先调 detect_so_level）；detect_vcall/icall 已含 .so 级 + 函数级检测（不需先调 detect_so_level/detect_functions）。调用一个 detect_functions/vcall/icall 即一次性输出该维度及更低维度的完整结果。只在用户明确只要 .so 级摸底（不要函数/调用点）时才用 detect_so_level。",
            "反思自检：完整检测后调用 reflect_check 工具对 summary 做合理性校验（so总数一致性、保护率范围、有调用点却无保护等），发现异常向用户提示，确保结果可信。",
        ]
        sc = build_skill_context(self.skills)
        if sc:
            parts.append("")
            parts.append(sc)
        rc = build_reference_context(self.references)
        if rc:
            parts.append("")
            parts.append(rc)
        parts.append("")
        parts.append("可用工具见本次请求的 tools 参数。若用户请求超出工具能力，明确说明并引导用户使用可用工具。")
        return "\n".join(parts)

    def _connect_mcp(self):
        output_dir = self.defaults.get('output_dir')
        if not output_dir:
            return
        try:
            os.makedirs(output_dir, exist_ok=True)
        except Exception:
            pass
        db_path = os.path.join(output_dir, 'cfi_detection.sqlite')
        client = create_sqlite_client(db_path)
        if client and client.connected:
            self.mcp_client = client
            for name, tool in mcp_tools_to_agent(client).items():
                self.registry.tools[name] = tool
        elif client:
            self.mcp_client = client

    def reconnect_mcp(self):
        if self.mcp_client:
            try:
                self.mcp_client.close()
            except Exception:
                pass
            self.mcp_client = None
        for name in list(self.registry.tools.keys()):
            if name.startswith('mcp_'):
                del self.registry.tools[name]
        self._connect_mcp()

    @property
    def model(self):
        return self.llm.model

    def set_model(self, model):
        self.llm.model = model

    def reload_llm(self):
        self.cfg = load_config(self.config_path)
        llm_cfg = get_llm_config(self.cfg)
        self.llm = LLMClient.from_config(llm_cfg)

    def list_tools(self):
        return [(t.name, t.description) for t in self.registry.tools.values()]

    def reset(self):
        self._reset_messages()

    def chat(self, user_input, on_text=None, on_plan=None):
        self.messages.append({"role": "user", "content": user_input})
        ran_detection = False
        while True:
            content, tool_calls = self.llm.chat(
                self.messages, tools=self.registry.schemas(), on_text=on_text,
            )
            assistant = {"role": "assistant", "content": content or None}
            if tool_calls:
                assistant["tool_calls"] = tool_calls
            self.messages.append(assistant)

            if not tool_calls:
                if ran_detection:
                    self.reconnect_mcp()
                return content or ""

            for tc in tool_calls:
                name = tc["function"]["name"]
                args = tc["function"]["arguments"]
                if name == "run_cfi_detection":
                    ran_detection = True
                if name == "propose_plan" and on_plan:
                    parsed = json.loads(args) if isinstance(args, str) else args
                    approved = on_plan(parsed)
                    result = json.dumps({"approved": approved,
                                         "message": "用户已批准，请按计划依次调用工具执行" if approved
                                         else "用户未批准，请询问用户调整需求或停止"},
                                        ensure_ascii=False)
                else:
                    result = self.registry.call(name, args)
                if len(result) > MAX_TOOL_RESULT:
                    result = result[:MAX_TOOL_RESULT] + f"\n...[结果已截断，原始长度 {len(result)} 字符]"
                self.messages.append({
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "content": result,
                })
