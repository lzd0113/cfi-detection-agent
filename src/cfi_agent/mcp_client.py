import asyncio
import threading
import json
from typing import Optional

from .tools import Tool

_MCP_AVAILABLE = True
try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
except Exception:
    ClientSession = None
    StdioServerParameters = None
    stdio_client = None
    _MCP_AVAILABLE = False


class MCPClient:
    """同步接口的 MCP client：后台线程维持持久 stdio session。"""

    def __init__(self, command, args=None, env=None, db_alias=None):
        if not _MCP_AVAILABLE:
            raise RuntimeError("mcp SDK 未安装，无法连接 MCP server。请 pip install mcp")
        self.params = StdioServerParameters(command=command, args=args or [], env=env)
        self.db_alias = db_alias
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._session = None
        self._stack = None
        self._session_ctx = None
        self._ready = threading.Event()
        self._error = None
        self._stop = asyncio.Event()
        self._thread.start()
        self._ready.wait(timeout=30)

    def _run(self):
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self._main())
        except Exception as e:
            self._error = e
            self._ready.set()

    async def _main(self):
        try:
            self._stack = stdio_client(self.params)
            read, write = await self._stack.__aenter__()
            self._session_ctx = ClientSession(read, write)
            self._session = await self._session_ctx.__aenter__()
            await self._session.initialize()
            self._ready.set()
            await self._stop.wait()
        except Exception as e:
            self._error = e
            self._ready.set()

    @property
    def connected(self):
        return self._session is not None

    @property
    def error(self):
        return self._error

    def _submit(self, coro, timeout=60):
        if not self._session:
            raise RuntimeError(f"MCP 未连接: {self._error}")
        fut = asyncio.run_coroutine_threadsafe(coro, self.loop)
        return fut.result(timeout=timeout)

    def list_tools(self):
        result = self._submit(self._session.list_tools())
        return result.tools

    def call_tool(self, name, arguments):
        result = self._submit(self._session.call_tool(name, arguments or {}))
        texts = []
        for c in result.content:
            if hasattr(c, "text"):
                texts.append(c.text)
        return "\n".join(texts)

    def close(self):
        try:
            self.loop.call_soon_threadsafe(self._stop.set)
        except Exception:
            pass


def create_sqlite_client(db_path, python_exe=None) -> Optional[MCPClient]:
    import sys
    if not _MCP_AVAILABLE:
        print("MCP SDK 未安装，跳过 sqlite MCP 连接（agent 仍可用本地查询工具）")
        return None
    command = python_exe or sys.executable
    args = ["-m", "cfi_agent.mcp_servers.sqlite_server", "--db", db_path]
    try:
        return MCPClient(command=command, args=args, db_alias="sqlite")
    except Exception as e:
        print(f"MCP sqlite 连接失败: {e}")
        return None


def mcp_tools_to_agent(client: MCPClient) -> dict:
    tools = {}
    if not client or not client.connected:
        return tools
    try:
        mcp_tools = client.list_tools()
    except Exception as e:
        print(f"枚举 MCP 工具失败: {e}")
        return tools

    for t in mcp_tools:
        name = f"mcp_{t.name}"
        params = getattr(t, "inputSchema", None) or {"type": "object", "properties": {}}
        desc = getattr(t, "description", "") or ""
        prefix = "[SQLite MCP] " if client.db_alias == "sqlite" else "[MCP] "

        def make_handler(tool_name):
            def handler(**kwargs):
                try:
                    return client.call_tool(tool_name, kwargs)
                except Exception as e:
                    return f"MCP 工具调用出错: {e}"
            return handler

        tools[name] = Tool(name, prefix + desc, params, make_handler(t.name))
    return tools
