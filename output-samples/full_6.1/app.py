#!/usr/bin/env python3
"""CFI Detection Report - Flask API Server

Usage: python app.py
Then open http://localhost:5000 in browser.
"""

import os
import sqlite3
from flask import Flask, jsonify, send_file, request

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'cfi_detection.sqlite')

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Methods', 'GET, OPTIONS')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
    return response


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route('/echarts.min.js')
def echarts_js():
    return send_file(os.path.join(BASE_DIR, 'echarts.min.js'))

@app.route('/data.js')
def data_js():
    return send_file(os.path.join(BASE_DIR, 'data.js'))

@app.route('/')
def index():
    return send_file(os.path.join(BASE_DIR, 'index.html'))


@app.route('/api/summary')
def api_summary():
    conn = get_db()
    row = conn.execute('SELECT * FROM summary').fetchone()
    conn.close()
    return jsonify(dict(row))


@app.route('/api/modules')
def api_modules():
    conn = get_db()
    rows = conn.execute(
        'SELECT * FROM modules ORDER BY cfi_rate_percent DESC'
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route('/api/modules/<module>')
def api_module_detail(module):
    conn = get_db()
    mod = conn.execute(
        'SELECT * FROM modules WHERE module=?', (module,)
    ).fetchone()
    if not mod:
        conn.close()
        return jsonify({'error': 'module not found'}), 404
    so_files = conn.execute(
        '''SELECT * FROM so_files WHERE module=?
           ORDER BY cfi_enabled DESC, path''',
        (module,)
    ).fetchall()
    conn.close()
    return jsonify({'module': dict(mod), 'so_files': [dict(r) for r in so_files]})


@app.route('/api/so_files/<int:so_id>/functions')
def api_so_functions(so_id):
    func_type = request.args.get('type', '')
    conn = get_db()
    if func_type:
        rows = conn.execute(
            '''SELECT n.name, sf.mangled_count FROM so_functions sf
               JOIN name_table n ON sf.func_id = n.id
               WHERE sf.so_id=? AND sf.func_type=?''',
            (so_id, func_type)
        ).fetchall()
    else:
        rows = conn.execute(
            '''SELECT n.name, sf.func_type, sf.mangled_count FROM so_functions sf
               JOIN name_table n ON sf.func_id = n.id
               WHERE sf.so_id=?''',
            (so_id,)
        ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route('/api/no_cfi_so')
def api_no_cfi_so():
    conn = get_db()
    rows = conn.execute(
        'SELECT module, path FROM so_files WHERE cfi_enabled=0 ORDER BY module, path'
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route('/api/top_unprotected')
def api_top_unprotected():
    limit = request.args.get('limit', 20, type=int)
    conn = get_db()
    rows = conn.execute(
        '''SELECT path, module, truly_unprotected_count, cfi_protected_count
           FROM so_files WHERE cfi_enabled=1 AND truly_unprotected_count > 0
           ORDER BY truly_unprotected_count DESC LIMIT ?''',
        (limit,)
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route('/api/search')
def api_search():
    q = request.args.get('q', '')
    func_type = request.args.get('type', '')
    if not q or len(q) < 2:
        return jsonify([])
    conn = get_db()
    if func_type:
        rows = conn.execute(
            '''SELECT n.name, sf.func_type, so.path, so.module
               FROM so_functions sf
               JOIN name_table n ON sf.func_id = n.id
               JOIN so_files so ON sf.so_id = so.id
               WHERE n.name LIKE ? AND sf.func_type=?
               LIMIT 50''',
            (f'%{q}%', func_type)
        ).fetchall()
    else:
        rows = conn.execute(
            '''SELECT DISTINCT n.name FROM name_table n
               WHERE n.name LIKE ? LIMIT 50''',
            (f'%{q}%',)
        ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route('/api/function_locations')
def api_function_locations():
    name = request.args.get('name', '')
    if not name:
        return jsonify([])
    conn = get_db()
    rows = conn.execute(
        '''SELECT n.name, sf.func_type, sf.mangled_count, so.path, so.module, so.cfi_enabled
           FROM so_functions sf
           JOIN name_table n ON sf.func_id = n.id
           JOIN so_files so ON sf.so_id = so.id
           WHERE n.name = ?
           ORDER BY so.module, so.path''',
        (name,)
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

if __name__ == '__main__':
    print(f"\u6570\u636e\u5e93: {DB_PATH}")
    print(f"\u670d\u52a1\u5730\u5740: http://localhost:5000")
    print(f"\u6309 Ctrl+C \u9000\u51fa")
    app.run(debug=False, port=5000)
