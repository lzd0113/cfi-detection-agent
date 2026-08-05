import os
import shutil
from datetime import datetime

from .detection import ensure_pyelftools, run_detection
from .demangle import ensure_cxxfilt, build_module_data
from .db import generate_sqlite
from .html_report import generate_html
from .api_server import generate_app
from .excel_report import generate_excel
from .service import start_service, stop_service


def run_full_pipeline(lib_dir, output_dir, mode='full', progress=None, log=None, start_web=True):
    function_detail = (mode == 'full')
    os.makedirs(output_dir, exist_ok=True)

    ELFFile = ensure_pyelftools()
    cxxfilt_module = ensure_cxxfilt() if function_detail else None

    results, summary = run_detection(lib_dir, ELFFile, function_detail, progress=progress, log=log)
    modules, name_table = build_module_data(results, cxxfilt_module)

    if log:
        log('========== 生成 SQLite ==========')
    generate_sqlite(summary, modules, name_table, output_dir)

    if log:
        log('========== 生成前端 HTML ==========')
    generate_html(output_dir)
    # Copy echarts.min.js to output (local instead of CDN)
    import shutil
    import json as _json
    echarts_src = os.path.join(os.path.dirname(__file__), 'echarts.min.js')
    if os.path.exists(echarts_src):
        shutil.copy2(echarts_src, os.path.join(output_dir, 'echarts.min.js'))
    # Save summary + modules as data.js for offline viewing (no service needed for initial load)
    _strip_mods = []
    for m in modules:
        _m = {k: v for k, v in m.items() if k != 'so_files'}
        _m['so_files'] = [{k: v for k, v in so.items() if k not in ('cfi_protected','truly_unprotected','cfi_infra','pac_protected_list','pac_sign_only_list','pac_no_pac_list','bti_with_list','bti_without_list')} for so in m.get('so_files',[])]
        _strip_mods.append(_m)
    with open(os.path.join(output_dir, 'data.js'), 'w', encoding='utf-8') as f:
        f.write('var EMBEDDED_DATA=' + _json.dumps({'summary': summary, 'modules': _strip_mods}, ensure_ascii=False, default=str) + ';')
    if log:
        log('========== 生成 Flask API ==========')
    generate_app(output_dir)

    if log:
        log('========== 生成 Excel ==========')
    generate_excel(summary, modules, output_dir)

    if log:
        log('========== 存档历史快照 ==========')
    db_file = os.path.join(output_dir, 'cfi_detection.sqlite')
    if os.path.exists(db_file):
        history_dir = os.path.join(output_dir, 'history')
        os.makedirs(history_dir, exist_ok=True)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        shutil.copy2(db_file, os.path.join(history_dir, f'cfi_{ts}.sqlite'))

    if start_web:
        if log:
            log('停止旧服务...')
        stop_service()
        if log:
            log('启动后端服务...')
        start_service(output_dir)

    return summary, modules
