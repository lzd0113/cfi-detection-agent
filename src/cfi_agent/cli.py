import os
import sys
import shutil
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer, Completion

from .agent import Agent
from .setup import is_configured, run_setup, MODELS, _update_config_model, _write_env
from .config import PROVIDERS, find_project_root

app = typer.Typer(no_args_is_help=True, add_completion=False)
console = Console()

SLASH_COMMANDS = [
    ("/help", "显示帮助与示例"),
    ("/model", "查看当前模型（/model <名称> 可切换）"),
    ("/tools", "列出可用工具"),
    ("/mcp", "重连 MCP sqlite 服务"),
    ("/setup", "重新配置大模型与 API key"),
    ("/clear", "清空输出目录 output（检测结果）"),
    ("/reset", "清空对话历史"),
    ("/quit", "退出"),
]


class SlashCompleter(Completer):
    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        parts = text.split(' ', 1)
        if len(parts) == 1:
            for cmd, desc in SLASH_COMMANDS:
                if cmd.startswith(parts[0]):
                    yield Completion(cmd, start_position=-len(parts[0]), display_meta=desc)
        elif parts[0] == '/model' and len(text.split(' ')) == 2:
            cur = text.split(' ')[1]
            for label, model, _ in MODELS:
                if model.startswith(cur) or cur == '':
                    yield Completion(model, start_position=-len(cur), display=label)


def _print_slash_commands():
    t = Table(title="可用命令（输入 / 自动弹出，可点选）", show_header=True, header_style="bold cyan")
    t.add_column("命令", style="bold", width=24)
    t.add_column("说明")
    t.add_row("/", "弹出本命令列表")
    for c, d in SLASH_COMMANDS:
        t.add_row(c, d)
    console.print(t)


def _show_model(agent):
    llm = agent.llm
    has_key = bool(llm.api_key and llm.api_key != 'EMPTY')
    console.print(Panel.fit(
        f"当前模型: [cyan]{llm.model}[/cyan]\n"
        f"API 端点: [dim]{llm.base_url}[/dim]\n"
        f"API Key: {'[green]已配置[/green]' if has_key else '[red]未配置（用 /setup 配置）[/red]'}",
        title="当前模型", border_style="cyan",
    ))


def _print_help(agent):
    _print_slash_commands()
    console.print("\n[dim]直接用自然语言描述需求即可，例如：[/dim]")
    console.print("  [green]对 E:/lib.unstripped_4.1 做完整 CFI 检测[/green]")
    console.print("  [green]查一下哪些 .so 没开 CFI[/green]")
    console.print("  [green]搜一下 ConvertErrCode 这个函数受没受保护[/green]")


@app.command()
def main(
    config: str = typer.Option(None, "--config", "-c", help="config.yaml 路径"),
    model: str = typer.Option(None, "--model", "-m", help="覆盖 config 里的模型"),
):
    """OpenHarmony CFI 安全检测 Agent — LLM 驱动、MCP 集成、CLI 交互"""
    if not is_configured(config):
        run_setup(config)
    try:
        agent = Agent(config_path=config, model_override=model, on_log=lambda m: print(m, flush=True))
    except Exception as e:
        console.print(f"[red]Agent 初始化失败: {e}[/red]")
        raise typer.Exit(1)

    console.print(Panel.fit(
        "[bold]OpenHarmony CFI 安全检测 Agent[/bold]\n"
        f"模型: [cyan]{agent.model}[/cyan]   "
        f"默认输入: [dim]{agent.defaults.get('lib_dir') or '未设'}[/dim]   "
        f"输出: [dim]{agent.defaults.get('output_dir') or '未设'}[/dim]\n"
        "输入 [bold green]/[/bold green] 随时查看命令（可点选），自然语言描述需求即可。",
        border_style="cyan",
    ))
    _print_help(agent)

    session = None
    try:
        session = PromptSession(completer=SlashCompleter(), complete_while_typing=True)
    except Exception:
        pass

    while True:
        try:
            if session is not None:
                user = session.prompt("\n你> ").strip()
            else:
                user = input("\n你> ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            break
        except Exception:
            session = None
            console.print("[dim](输入补全不可用，已切换普通输入；输入 / 查看命令)[/dim]")
            continue
        if not user:
            continue
        if user in ("/quit", "/exit", "quit", "exit"):
            break
        if user in ("/", "/?"):
            _print_slash_commands()
            continue
        if user == "/help":
            _print_help(agent)
            continue
        if user == "/model":
            _show_model(agent)
            continue
        if user.startswith("/model "):
            new_model = user[len("/model "):].strip()
            given = [m for _, m, _ in MODELS]
            if new_model in given:
                root = find_project_root(config and str(Path(config).parent))
                _update_config_model(root, new_model)
                provider = new_model.split('/')[0]
                env_var = PROVIDERS.get(provider, (None, 'OPENAI_API_KEY'))[1]
                if not os.environ.get(env_var):
                    key = input(f"输入 {provider} 的 API Key (回车跳过): ").strip()
                    if key:
                        _write_env(root, env_var, key)
                        os.environ[env_var] = key
                agent.reload_llm()
                agent.reset()
                console.print(f"[green]已切换模型: {agent.model}[/green] [dim](已清空对话历史，避免上下文混淆)[/dim]")
            else:
                console.print(f"[red]不支持的模型: {new_model}[/red]")
                console.print("可用模型：")
                for label, m, _ in MODELS:
                    console.print(f"  [cyan]{m}[/cyan]  ({label})")
                console.print("或输入 [green]/model[/green] 弹菜单选择")
            continue
        if user == "/tools":
            t = Table(show_header=True, header_style="bold cyan")
            t.add_column("工具", style="bold")
            t.add_column("说明")
            for name, desc in agent.list_tools():
                t.add_row(name, desc[:80])
            console.print(t)
            continue
        if user == "/mcp":
            agent.reconnect_mcp()
            connected = agent.mcp_client and agent.mcp_client.connected
            console.print(f"MCP sqlite: {'[green]已连接[/green]' if connected else '[red]未连接[/red]'}")
            continue
        if user == "/setup":
            run_setup(config)
            agent.reload_llm()
            agent.reset()
            console.print(f"[green]当前模型: {agent.model}[/green] [dim](已清空对话历史)[/dim]")
            continue
        if user == "/clear":
            od = agent.defaults.get('output_dir') or './output'
            if not os.path.isdir(od):
                console.print(f"[yellow]输出目录不存在: {od}[/yellow]")
                continue
            items = os.listdir(od)
            if not items:
                console.print(f"[green]{od} 已是空的[/green]")
                continue
            console.print(f"将清空 [cyan]{od}[/cyan]，含 {len(items)} 项：")
            for it in items[:12]:
                console.print(f"  {it}")
            if len(items) > 12:
                console.print(f"  ...等共 {len(items)} 项")
            ans = input("确认清空？(y/n，默认 n): ").strip().lower()
            if ans == 'y':
                # Stop Flask service first — it locks the output directory
                from .engine.service import stop_service
                stop_service()
                for it in items:
                    p = os.path.join(od, it)
                    try:
                        if os.path.isdir(p):
                            shutil.rmtree(p)
                        else:
                            os.remove(p)
                    except Exception as e:
                        console.print(f"[red]删除失败 {it}: {e}[/red]")
                console.print(f"[green]已清空 {od}[/green]")
            else:
                console.print("[yellow]已取消[/yellow]")
            continue
        if user == "/reset":
            agent.reset()
            console.print("[green]已清空对话历史[/green]")
            continue

        def on_text(piece):
            sys.stdout.write(piece)
            sys.stdout.flush()

        def on_plan(plan):
            goal = plan.get('goal', '')
            steps = plan.get('steps', [])
            console.print(Panel(f"[bold]目标[/bold]: {goal}", title="检测计划", border_style="yellow"))
            t = Table(show_header=True, header_style="bold yellow")
            t.add_column("步", width=4)
            t.add_column("操作")
            t.add_column("工具", style="cyan")
            t.add_column("原因", style="dim")
            for s in steps:
                t.add_row(str(s.get('step', '')), s.get('action', ''), s.get('tool', ''), s.get('reason', ''))
            console.print(t)
            ans = input("\n是否执行此计划？(y/n，默认 y): ").strip().lower()
            if ans == 'n':
                console.print("[red]已拒绝，可重新描述需求[/red]")
                return False
            console.print("[green]已批准，开始执行...[/green]\n")
            return True

        console.print()
        try:
            agent.chat(user, on_text=on_text, on_plan=on_plan)
        except Exception as e:
            msg = str(e)
            if '401' in msg or 'api key' in msg.lower() or 'unauthorized' in msg.lower() or '认证' in msg:
                console.print(f"\n[red]LLM 认证失败：API key 无效或已过期[/red] → 用 [green]/setup[/green] 重新配置 [cyan]{agent.model}[/cyan] 的 key")
            elif 'timeout' in msg.lower() or 'timed out' in msg.lower() or '网络' in msg or 'connect' in msg.lower():
                console.print(f"\n[red]网络错误: {e}[/red] → 检查网络或用 [green]/model[/green] 换模型")
            else:
                console.print(f"\n[red]处理出错: {e}[/red]")
        console.print()

    try:
        agent.reconnect_mcp()
    except Exception:
        pass
    console.print("[dim]再见[/dim]")


if __name__ == "__main__":
    main()
