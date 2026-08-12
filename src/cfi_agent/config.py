from pathlib import Path
import os

try:
    import yaml
except ImportError:
    yaml = None

from dotenv import load_dotenv


def find_project_root(start=None):
    p = Path(start or Path.cwd())
    for cand in [p, *p.parents]:
        if (cand / 'config.yaml').exists():
            return cand
    return Path.cwd()


def load_config(config_path=None):
    if config_path:
        root = Path(config_path).resolve().parent
    else:
        root = find_project_root()

    load_dotenv(root / '.env')

    cfg = {'_root': str(root)}
    yaml_path = root / 'config.yaml'
    if yaml and yaml_path.exists():
        with open(yaml_path, encoding='utf-8') as f:
            data = yaml.safe_load(f) or {}
        cfg.update(data)
    return cfg


PROVIDERS = {
    'openai': (None, 'OPENAI_API_KEY'),
    'deepseek': ('https://api.deepseek.com/v1', 'DEEPSEEK_API_KEY'),
    'qwen': ('https://dashscope.aliyuncs.com/compatible-mode/v1', 'DASHSCOPE_API_KEY'),
    'moonshot': ('https://api.moonshot.cn/v1', 'MOONSHOT_API_KEY'),
    'zhipu': ('https://open.bigmodel.cn/api/paas/v4', 'ZHIPU_API_KEY'),
    'siliconflow': ('https://api.siliconflow.cn/v1', 'SILICONFLOW_API_KEY'),
    'ollama': ('http://localhost:11434/v1', 'OPENAI_API_KEY'),
    'local': ('http://localhost:8000/v1', 'OPENAI_API_KEY'),
}


def get_llm_config(cfg):
    llm = cfg.get('llm', {}) or {}
    raw = llm.get('model', 'gpt-4o-mini')
    base_url = llm.get('base_url') or llm.get('api_base')
    temperature = llm.get('temperature', 0.3)
    api_key = None
    model = raw
    if '/' in raw:
        provider, model = raw.split('/', 1)
        if not base_url and provider in PROVIDERS:
            base_url, env = PROVIDERS[provider]
            api_key = os.environ.get(env)
    if not api_key:
        for _, env in PROVIDERS.values():
            v = os.environ.get(env)
            if v:
                api_key = v
                break
    return {
        'model': model,
        'api_base': base_url,
        'api_key': api_key,
        'temperature': temperature,
    }


def get_defaults(cfg):
    d = cfg.get('defaults', {}) or {}
    return {
        'lib_dir': d.get('lib_dir'),
        'output_dir': d.get('output_dir'),
    }


def get_skill_paths(cfg):
    root = cfg.get('_root', '.')
    paths = cfg.get('skills', {}).get('paths', ['skills'])
    return [str(Path(p) if Path(p).is_absolute() else Path(root) / p) for p in paths]


def get_references(cfg):
    return cfg.get('references', []) or []
