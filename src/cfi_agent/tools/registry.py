import os
import time
import json
import sqlite3

DB_FILENAME = 'cfi_detection.sqlite'


class Tool:
    def __init__(self, name, description, parameters, handler):
        self.name = name
        self.description = description
        self.parameters = parameters
        self.handler = handler

    def to_schema(self):
        return {
            'type': 'function',
            'function': {
                'name': self.name,
                'description': self.description,
                'parameters': self.parameters,
            },
        }


class ToolRegistry:
    def __init__(self, defaults=None):
        self.tools = {}
        self.defaults = defaults or {}
        self.on_log = None
        self.on_progress = None
        self.last_output_dir = None

    def add(self, name, description, parameters, handler):
        self.tools[name] = Tool(name, description, parameters, handler)

    def schemas(self):
        return [t.to_schema() for t in self.tools.values()]

    def call(self, name, arguments):
        if name not in self.tools:
            return f"错误：未知工具 '{name}'"
        try:
            if isinstance(arguments, str):
                args = json.loads(arguments) if arguments else {}
            else:
                args = arguments or {}
            args = self._apply_defaults(name, args)
            result = self.tools[name].handler(**args)
            if isinstance(result, (dict, list)):
                return json.dumps(result, ensure_ascii=False)
            return str(result)
        except Exception as e:
            return f"工具 '{name}' 执行出错: {e}"

    def _apply_defaults(self, name, args):
        if 'output_dir' in args and not args['output_dir']:
            if 'output_dir' in (self.defaults or {}):
                args['output_dir'] = self.defaults['output_dir']
        if 'lib_dir' in args and not args['lib_dir']:
            if 'lib_dir' in (self.defaults or {}):
                args['lib_dir'] = self.defaults['lib_dir']
        return args


def _fmt_elapsed(seconds):
    seconds = int(seconds)
    h, s = divmod(seconds, 3600)
    m, s = divmod(s, 60)
    if h > 0:
        return f'{h}h{m:02d}m{s:02d}s'
    return f'{m:02d}m{s:02d}s'


def _make_timed_callbacks(original_log, original_progress):
    start_time = time.time()
    base_log = original_log or (lambda m: None)
    base_progress = original_progress or (lambda i, total, path: None)

    def timed_log(msg):
        elapsed = time.time() - start_time
        base_log(f'[{_fmt_elapsed(elapsed)}] {msg}')

    def timed_progress(i, total, path):
        base_progress(i, total, path)
        if total > 0 and i % 100 == 0 and i > 0:
            elapsed = time.time() - start_time
            rate = i / elapsed if elapsed > 0 else 0
            remaining = (total - i) / rate if rate > 0 else 0
            timed_log(f'进度: {i}/{total} ({i*100//total}%) — 预计剩余 {_fmt_elapsed(remaining)}')

    def finish():
        elapsed = time.time() - start_time
        timed_log(f'========== 检测完成，总耗时: {_fmt_elapsed(elapsed)} ==========')
        return elapsed

    return timed_log, timed_progress, finish


def _db_path(output_dir):
    return os.path.join(output_dir, DB_FILENAME)


def _connect(output_dir):
    p = _db_path(output_dir)
    if not os.path.exists(p):
        raise FileNotFoundError(f"未找到检测结果数据库: {p}。请先运行 CFI 检测。")
    conn = sqlite3.connect(p)
    conn.row_factory = sqlite3.Row
    return conn


def _truncate(items, limit=100):
    if len(items) <= limit:
        return items, len(items)
    return items[:limit], len(items)


def _auto_output_dir(kind, output_dir):
    from datetime import datetime
    base = output_dir or './output'
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    sub = os.path.join(base, f'{kind}_{ts}')
    os.makedirs(sub, exist_ok=True)
    return sub
