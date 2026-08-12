from .registry import Tool, ToolRegistry


def build_registry(defaults=None, extra_tools=None, on_log=None, on_progress=None) -> ToolRegistry:
    reg = ToolRegistry(defaults=defaults or {})
    reg.on_log = on_log
    reg.on_progress = on_progress

    from .detect_tools import register_detect_tools
    from .query_tools import register_query_tools
    from .service_tools import register_service_tools

    register_detect_tools(reg)
    register_query_tools(reg)
    register_service_tools(reg)

    if extra_tools:
        for name, tool in extra_tools.items():
            reg.tools[name] = tool

    return reg
