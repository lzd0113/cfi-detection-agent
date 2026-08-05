import os


def build_reference_context(refs):
    if not refs:
        return ''
    parts = ['## 参考目录（CFI 检测相关）']
    for r in refs:
        if isinstance(r, str):
            parts.append(f"- {r}")
        else:
            path = r.get('path', '')
            desc = r.get('description', '')
            exists = ''
            if path and os.path.isdir(path):
                try:
                    n = sum(1 for _ in os.scandir(path))
                    exists = f' (存在，含 {n} 项)'
                except Exception:
                    exists = ' (存在)'
            elif path and os.path.exists(path):
                exists = ' (存在)'
            parts.append(f"- {path}{exists}: {desc}" if desc else f"- {path}{exists}")
    return '\n'.join(parts)
