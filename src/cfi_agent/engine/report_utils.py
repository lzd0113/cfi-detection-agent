import os
import shutil
import json
import sqlite3
from datetime import datetime

from .db import generate_sqlite
from .html_report import generate_html
from .api_server import generate_app
from .excel_report import generate_excel
from .service import start_service, stop_service

_STRIP_KEYS = ('cfi_protected', 'truly_unprotected', 'cfi_infra',
               'pac_protected_list', 'pac_sign_only_list', 'pac_no_pac_list',
               'bti_with_list', 'bti_without_list')

_PYW_CONTENT = """\
# -*- coding: utf-8 -*-
import os, sys, subprocess, time, webbrowser, urllib.request
d = os.path.dirname(os.path.abspath(__file__))
def running():
    try:
        urllib.request.urlopen("http://127.0.0.1:5000/api/summary", timeout=2).read()
        return True
    except:
        return False
if not running():
    subprocess.Popen([sys.executable, "app.py"], cwd=d,
        creationflags=0x00000008|0x00000200|0x08000000,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(20):
        time.sleep(0.5)
        if running(): break
webbrowser.open("http://127.0.0.1:5000")
"""


def generate_reports(summary, module_list, name_table, output_dir, *,
                      include_calls=True, generate_pyw=False,
                      history_snapshot=False, history_type='unknown',
                      base_output_dir=None, start_web=False, log=None):
    """Generate all report artifacts: SQLite, HTML, data.js, app.py, Excel, .pyw, and start service.

    Args:
        summary: detection summary dict
        module_list: list of module dicts (from build_module_data or _build_*_full_data)
        name_table: list of demangled function names (empty list if no demangling)
        output_dir: output directory path (timestamped subdir)
        include_calls: whether Excel includes vcall/icall columns
        generate_pyw: whether to generate the 查看报告.pyw launcher
        history_snapshot: whether to save a DB copy to base_output_dir/history/
        history_type: detection type label for snapshot filename (e.g. 'full', 'vcall')
        base_output_dir: parent output dir for history/ (if None, uses output_dir's parent)
        start_web: whether to start the Flask service
        log: optional log callback
    """
    engine_dir = os.path.dirname(os.path.abspath(__file__))

    if log: log('========== 生成 SQLite ==========')
    generate_sqlite(summary, module_list, name_table, output_dir, detection_type=history_type)

    if log: log('========== 生成前端 HTML ==========')
    generate_html(output_dir)

    echarts_src = os.path.join(engine_dir, 'echarts.min.js')
    if os.path.exists(echarts_src):
        shutil.copy2(echarts_src, os.path.join(output_dir, 'echarts.min.js'))

    _path_to_id = {}
    _db_path = os.path.join(output_dir, 'cfi_detection.sqlite')
    if os.path.exists(_db_path):
        _conn = sqlite3.connect(_db_path)
        for _row in _conn.execute('SELECT id, path FROM so_files'):
            _path_to_id[_row[1]] = _row[0]
        _conn.close()

    _strip_mods = []
    for m in module_list:
        _m = {k: v for k, v in m.items() if k != 'so_files'}
        _m['so_files'] = []
        for so in m.get('so_files', []):
            _so = {k: v for k, v in so.items() if k not in _STRIP_KEYS}
            _so['id'] = _path_to_id.get(so.get('path', ''), 0)
            _m['so_files'].append(_so)
        _strip_mods.append(_m)

    with open(os.path.join(output_dir, 'data.js'), 'w', encoding='utf-8') as f:
        f.write('var EMBEDDED_DATA=' + json.dumps(
            {'summary': summary, 'modules': _strip_mods},
            ensure_ascii=False, default=str) + ';')

    if log: log('========== 生成 Flask API ==========')
    generate_app(output_dir)

    if log: log('========== 生成 Excel ==========')
    generate_excel(summary, module_list, output_dir, include_calls=include_calls)

    if history_snapshot:
        if log: log('========== 存档历史快照 ==========')
        db_file = os.path.join(output_dir, 'cfi_detection.sqlite')
        if os.path.exists(db_file):
            base = base_output_dir or os.path.dirname(output_dir)
            history_dir = os.path.join(base, 'history')
            os.makedirs(history_dir, exist_ok=True)
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            shutil.copy2(db_file, os.path.join(history_dir, f'cfi_{ts}_{history_type}.sqlite'))

    if generate_pyw:
        _pyw = os.path.join(output_dir, '查看报告.pyw')
        with open(_pyw, 'w', encoding='utf-8') as f:
            f.write(_PYW_CONTENT)
        if log: log('生成 查看报告.pyw 启动器')

    if start_web:
        if log: log('停止旧服务...')
        stop_service()
        if log: log('启动后端服务...')
        start_service(output_dir)
