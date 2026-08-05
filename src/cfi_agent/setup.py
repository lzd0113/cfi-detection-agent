import os
import re
from pathlib import Path
from rich.console import Console

from .config import find_project_root, load_config, get_llm_config, PROVIDERS

console = Console()

MODELS = [
    ("DeepSeek (deepseek-chat)", "deepseek/deepseek-chat", "DEEPSEEK_API_KEY"),
    ("通义千问 (qwen-plus)", "qwen/qwen-plus", "DASHSCOPE_API_KEY"),
    ("OpenAI (gpt-4o-mini)", "openai/gpt-4o-mini", "OPENAI_API_KEY"),
    ("Moonshot Kimi (moonshot-v1-8k)", "moonshot/moonshot-v1-8k", "MOONSHOT_API_KEY"),
    ("智谱 GLM (glm-4)", "zhipu/glm-4", "ZHIPU_API_KEY"),
    ("硅基流动 (Qwen2.5-7B)", "siliconflow/Qwen/Qwen2.5-7B-Instruct", "SILICONFLOW_API_KEY"),
    ("本地 Ollama (无需 key)", "ollama", None),
]


def is_configured(config_path=None):
    cfg = load_config(config_path)
    llm = cfg.get('llm', {}) or {}
    raw = llm.get('model', 'openai/gpt-4o-mini')
    if '/' in raw:
        provider = raw.split('/', 1)[0]
        if provider in PROVIDERS:
            env_var = PROVIDERS[provider][1]
            return bool(os.environ.get(env_var))
    return any(os.environ.get(env) for _, env in PROVIDERS.values())


def _write_env(root, env_var, key):
    env_path = Path(root) / '.env'
    lines = []
    found = False
    if env_path.exists():
        for line in env_path.read_text(encoding='utf-8').splitlines():
            if line.startswith(env_var + '='):
                lines.append(f'{env_var}={key}')
                found = True
            else:
                lines.append(line)
    if not found:
        lines.append(f'{env_var}={key}')
    env_path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def _update_config_model(root, model):
    cfg_path = Path(root) / 'config.yaml'
    text = cfg_path.read_text(encoding='utf-8')
    new = re.sub(r'^(\s*model:\s*).*$', r'\g<1>' + model, text, flags=re.M)
    cfg_path.write_text(new, encoding='utf-8')


def select_model(config_path=None):
    root = find_project_root(config_path and str(Path(config_path).parent))
    console.print("\n选择大模型：")
    for i, (label, _, _) in enumerate(MODELS, 1):
        console.print(f"  [green]{i}[/green]. {label}")
    console.print()
    while True:
        choice = input("输入编号: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(MODELS):
            break
        console.print("[red]无效输入，请重输[/red]")
    label, model, env_var = MODELS[int(choice) - 1]

    if env_var is None:
        console.print("\n选择本地 Ollama（请先运行 `ollama serve`）")
        local_model = input("本地模型名(如 qwen2.5:7b，回车默认 llama3): ").strip() or 'llama3'
        model = f'ollama/{local_model}'
        _update_config_model(root, model)
        os.environ['OPENAI_API_KEY'] = 'ollama'
        _write_env(root, 'OPENAI_API_KEY', 'ollama')
        return model

    console.print(f"\n你选择了 [cyan]{label}[/cyan]")
    key = input("粘贴 API Key (回车保留已有): ").strip()
    if key:
        _write_env(root, env_var, key)
        os.environ[env_var] = key
    _update_config_model(root, model)
    return model


def run_setup(config_path=None):
    console.print("\n[bold cyan]═══ 配置大模型 ═══[/bold cyan]")
    model = select_model(config_path)
    console.print(f"\n[green]✓ 配置完成（model={model}）[/green]")
    console.print("[dim]下次启动自动使用此配置，更换可输入 /model 或 /setup[/dim]")
    return model
