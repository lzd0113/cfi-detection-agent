import json
from typing import Callable, Optional

import httpx


class LLMClient:
    def __init__(self, model, api_key=None, api_base=None, temperature=0.3):
        self.model = model
        self.api_key = api_key or 'EMPTY'
        self.base_url = (api_base or 'https://api.openai.com/v1').rstrip('/')
        self.temperature = temperature
        self.client = httpx.Client(timeout=httpx.Timeout(300.0, connect=30.0))

    @classmethod
    def from_config(cls, llm_cfg):
        return cls(
            model=llm_cfg['model'],
            api_key=llm_cfg.get('api_key'),
            api_base=llm_cfg.get('api_base'),
            temperature=llm_cfg.get('temperature', 0.3),
        )

    def chat(self, messages, tools=None, on_text: Optional[Callable] = None, stream=True):
        body = {
            'model': self.model,
            'messages': messages,
            'temperature': self.temperature,
        }
        if tools:
            body['tools'] = tools
            body['tool_choice'] = 'auto'
        headers = {'Authorization': f'Bearer {self.api_key}', 'Content-Type': 'application/json'}
        url = self.base_url + '/chat/completions'
        if stream:
            return self._stream(url, body, headers, on_text)
        return self._non_stream(url, body, headers)

    def _stream(self, url, body, headers, on_text):
        body = dict(body)
        body['stream'] = True
        parts = []
        tool_acc = {}
        try:
            with self.client.stream('POST', url, json=body, headers=headers) as resp:
                if resp.status_code >= 400:
                    err = resp.read().decode('utf-8', errors='replace')
                    raise RuntimeError(f"LLM 请求失败 ({resp.status_code}): {err[:500]}")
                for line in resp.iter_lines():
                    if not line:
                        continue
                    if not line.startswith('data:'):
                        continue
                    data = line[5:].strip()
                    if data == '[DONE]':
                        break
                    try:
                        obj = json.loads(data)
                    except Exception:
                        continue
                    choices = obj.get('choices') or []
                    if not choices:
                        continue
                    delta = choices[0].get('delta', {}) or {}
                    piece = delta.get('content')
                    if piece:
                        parts.append(piece)
                        if on_text:
                            on_text(piece)
                    tcs = delta.get('tool_calls')
                    if tcs:
                        for tc in tcs:
                            idx = tc.get('index') or 0
                            slot = tool_acc.setdefault(idx, {'id': '', 'name': '', 'arguments': ''})
                            if tc.get('id'):
                                slot['id'] = tc['id']
                            fn = tc.get('function') or {}
                            if fn.get('name'):
                                slot['name'] = fn['name']
                            if fn.get('arguments'):
                                slot['arguments'] += fn['arguments']
        except httpx.HTTPError as e:
            raise RuntimeError(f"LLM 网络错误: {e}")

        content = ''.join(parts)
        tool_calls = []
        for idx in sorted(tool_acc.keys()):
            slot = tool_acc[idx]
            if not slot['name'] and not slot['arguments']:
                continue
            tool_calls.append({
                'id': slot['id'] or f'call_{idx}',
                'type': 'function',
                'function': {
                    'name': slot['name'],
                    'arguments': slot['arguments'] or '{}',
                },
            })
        return content, tool_calls

    def _non_stream(self, url, body, headers):
        r = self.client.post(url, json=body, headers=headers)
        if r.status_code >= 400:
            raise RuntimeError(f"LLM 请求失败 ({r.status_code}): {r.text[:500]}")
        obj = r.json()
        msg = obj['choices'][0]['message']
        content = msg.get('content') or ''
        tool_calls = []
        for i, tc in enumerate(msg.get('tool_calls') or []):
            fn = tc.get('function') or {}
            tool_calls.append({
                'id': tc.get('id') or f'call_{i}',
                'type': 'function',
                'function': {
                    'name': fn.get('name', ''),
                    'arguments': fn.get('arguments', '{}') or '{}',
                },
            })
        return content, tool_calls
