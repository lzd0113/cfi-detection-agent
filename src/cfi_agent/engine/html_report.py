import os
import base64
import json

# Read the full HTML from the best existing output and encode
# This is done at import time to keep the file small
_BEST_HTML_PATH = None  # will be set at generate_html time if needed

# The base64 is stored in a separate file to avoid truncation
_B64_FILE = os.path.join(os.path.dirname(__file__), 'html_template.b64')

def _get_template():
    """Get HTML template from .b64 file or reconstruct."""
    if os.path.exists(_B64_FILE):
        with open(_B64_FILE, 'r') as f:
            return base64.b64decode(f.read().strip()).decode('utf-8')
    # Fallback: find any index.html in output dirs
    import glob
    candidates = sorted(glob.glob(os.path.join(os.path.dirname(__file__), '..', '..', 'output', '*', 'index.html')),
                        key=os.path.getsize, reverse=True)
    if candidates:
        with open(candidates[0], 'r', encoding='utf-8') as f:
            return f.read()
    return '<html><body>HTML template not found</body></html>'


def generate_html(output_dir, summary=None, modules=None):
    """Generate HTML report."""
    _html = _get_template()
    dst = os.path.join(output_dir, "index.html")
    with open(dst, "w", encoding="utf-8") as f:
        f.write(_html)
    print(f"前端页面已保存: {dst}")
    return dst


def save_template_from_html(html_path):
    """Save an existing HTML as the base64 template for future use."""
    with open(html_path, 'r', encoding='utf-8') as f:
        html = f.read()
    b64 = base64.b64encode(html.encode('utf-8')).decode('utf-8')
    with open(_B64_FILE, 'w') as f:
        f.write(b64)
    print(f"Template saved: {html_path} -> {_B64_FILE} ({len(b64)} bytes)")
