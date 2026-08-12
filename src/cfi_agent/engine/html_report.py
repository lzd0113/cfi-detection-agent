import os

_TEMPLATE_FILE = os.path.join(os.path.dirname(__file__), 'template.html')


def generate_html(output_dir):
    with open(_TEMPLATE_FILE, 'r', encoding='utf-8') as f:
        _html = f.read()
    dst = os.path.join(output_dir, "index.html")
    with open(dst, "w", encoding="utf-8") as f:
        f.write(_html)
    print(f"前端页面已保存: {dst}")
    return dst
