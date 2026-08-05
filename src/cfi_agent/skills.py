import re
from pathlib import Path


def parse_frontmatter(text):
    m = re.match(r'^---\n(.*?)\n---\n?(.*)$', text, re.S)
    if not m:
        return {}, text
    fm_text = m.group(1)
    body = m.group(2)
    fm = {}
    for line in fm_text.splitlines():
        if ':' in line:
            k, v = line.split(':', 1)
            fm[k.strip()] = v.strip()
    return fm, body


def load_skills(paths):
    skills = []
    for p in paths:
        base = Path(p)
        if not base.exists():
            continue
        for md in base.rglob('SKILL.md'):
            try:
                text = md.read_text(encoding='utf-8')
            except Exception:
                continue
            fm, body = parse_frontmatter(text)
            name = fm.get('name') or md.parent.name
            desc = fm.get('description', '')
            skills.append({
                'name': name,
                'description': desc,
                'body': body.strip(),
                'path': str(md),
            })
    return skills


def build_skill_context(skills):
    if not skills:
        return ''
    parts = ['## 可用 Skills（领域知识与触发条件）']
    for s in skills:
        parts.append(f"- {s['name']}: {s['description']}")
    parts.append('')
    for s in skills:
        if s['body']:
            parts.append(f"### Skill: {s['name']}")
            parts.append(s['body'])
            parts.append('')
    return '\n'.join(parts)
