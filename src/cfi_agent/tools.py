import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Callable, Optional

from .engine.pipeline import run_full_pipeline
from .engine.detection import ensure_pyelftools, run_so_level, run_functions, run_vcall, run_icall, run_detection, extract_module
from .engine.demangle import ensure_cxxfilt, build_module_data
from .engine.db import generate_sqlite
from .engine.html_report import generate_html
from .engine.api_server import generate_app
from .engine.service import start_service, stop_service, generate_bat_files
from .engine.excel_report import ensure_openpyxl, generate_excel
from .engine.constants import MODULE_DESC


DB_FILENAME = 'cfi_detection.sqlite'


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
        self.tools: dict[str, Tool] = {}
        self.defaults = defaults or {}
        self.on_log = None
        self.on_progress = None

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


def _gen_so_level_excel(results, output_dir):
    if not output_dir:
        return None
    try:
        os.makedirs(output_dir, exist_ok=True)
        Workbook, Font, PatternFill, Alignment, Border, Side = ensure_openpyxl()
        wb = Workbook()
        ws = wb.active
        ws.title = '.so级CFI检测'
        for col, h in enumerate(['序号', '模块', '.so路径', 'CFI状态'], 1):
            c = ws.cell(1, col, h)
            c.font = Font(bold=True, color='FFFFFF')
            c.fill = PatternFill(start_color='2563EB', end_color='2563EB', fill_type='solid')
            c.alignment = Alignment(horizontal='center')
        green = PatternFill(start_color='D1FAE5', end_color='D1FAE5', fill_type='solid')
        red = PatternFill(start_color='FEE2E2', end_color='FEE2E2', fill_type='solid')
        thin = Border(left=Side(style='thin', color='CBD5E1'), right=Side(style='thin', color='CBD5E1'), top=Side(style='thin', color='CBD5E1'), bottom=Side(style='thin', color='CBD5E1'))
        for i, r in enumerate(results, 2):
            ws.cell(i, 1, i - 1)
            ws.cell(i, 2, extract_module(r['path']))
            ws.cell(i, 3, r['path'])
            c = ws.cell(i, 4, '已开启' if r['cfi_enabled'] else '未开启')
            c.fill = green if r['cfi_enabled'] else red
            for col in range(1, 5):
                ws.cell(i, col).border = thin
        ws.column_dimensions['C'].width = 55
        out = os.path.join(output_dir, 'cfi_so_level_report.xlsx')
        wb.save(out)
        return out
    except Exception as e:
        return f'Excel 生成失败: {e}'


def _gen_stats_excel(title, stats, output_dir, filename):
    if not output_dir:
        return None
    try:
        os.makedirs(output_dir, exist_ok=True)
        Workbook, Font = ensure_openpyxl()[:2]
        wb = Workbook()
        ws = wb.active
        ws.title = title[:31]
        ws.cell(1, 1, title).font = Font(bold=True, size=14)
        ws.cell(2, 1, '指标').font = Font(bold=True)
        ws.cell(2, 2, '数值').font = Font(bold=True)
        for i, (k, v) in enumerate(stats.items(), 3):
            ws.cell(i, 1, k)
            ws.cell(i, 2, str(v))
        ws.column_dimensions['A'].width = 28
        out = os.path.join(output_dir, filename)
        wb.save(out)
        return out
    except Exception as e:
        return f'Excel 生成失败: {e}'


def _gen_simple_html(title, cards, table_headers, table_rows, output_dir, filename):
    if not output_dir:
        return None
    try:
        os.makedirs(output_dir, exist_ok=True)
        card_html = ''.join(
            f'<div class="card"><div class="num" style="color:{c}">{v}</div><div>{l}</div></div>'
            for l, v, c in cards
        )
        head = ''.join(f'<th>{h}</th>' for h in table_headers)
        body = ''
        for cells, cls in table_rows[:5000]:
            body += f'<tr class="{cls}">' if cls else '<tr>'
            body += ''.join(f'<td>{c}</td>' for c in cells) + '</tr>'
        html = f'''<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8"><title>{title}</title>
<style>body{{font-family:-apple-system,"Segoe UI",sans-serif;margin:24px;background:#f8fafc}}h1{{color:#1e40af}}.card{{display:inline-block;margin:8px;padding:14px 20px;border-radius:10px;background:#eef2ff;text-align:center;min-width:110px;box-shadow:0 1px 3px rgba(0,0,0,.08)}}.num{{font-size:24px;font-weight:bold}}table{{border-collapse:collapse;width:100%;margin-top:18px;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.06)}}th{{background:#2563eb;color:#fff;padding:9px;text-align:left}}td{{padding:7px 9px;border:1px solid #e2e8f0}}tr.red{{background:#fee2e2}}tr.green{{background:#d1fae5}}</style></head>
<body><h1>{title}</h1><div>{card_html}</div><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></body></html>'''
        out = os.path.join(output_dir, filename)
        with open(out, 'w', encoding='utf-8') as f:
            f.write(html)
        return out
    except Exception as e:
        return f'HTML 生成失败: {e}'


def _gen_kind_sqlite(table_name, columns, rows, output_dir, filename):
    if not output_dir:
        return None
    try:
        os.makedirs(output_dir, exist_ok=True)
        out = os.path.join(output_dir, filename)
        conn = sqlite3.connect(out)
        cols_def = ', '.join(f'{c} TEXT' for c in columns)
        conn.execute(f'DROP TABLE IF EXISTS {table_name}')
        conn.execute(f'CREATE TABLE {table_name} ({cols_def})')
        placeholders = ','.join('?' * len(columns))
        conn.executemany(f'INSERT INTO {table_name} VALUES ({placeholders})', rows)
        conn.commit()
        conn.close()
        return out
    except Exception as e:
        return f'SQLite 生成失败: {e}'


_DYNAMIC_APP_PY = """import os
import sqlite3
from flask import Flask, jsonify, request, send_file

app = Flask(__name__)
BASE = os.path.dirname(os.path.abspath(__file__))
DB = None
for _f in os.listdir(BASE):
    if _f.endswith('.sqlite'):
        DB = os.path.join(BASE, _f)
        break

@app.after_request
def _cors(r):
    r.headers['Access-Control-Allow-Origin'] = '*'
    r.headers['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
    return r

@app.route('/')
def _index():
    return send_file(os.path.join(BASE, 'index.html'))

@app.route('/api/tables')
def _tables():
    conn = sqlite3.connect(DB)
    t = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    conn.close()
    return jsonify(t)

@app.route('/api/query')
def _query():
    sql = request.args.get('sql', '')
    if not sql.strip().lower().startswith('select'):
        return jsonify({'error': 'select only'})
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    try:
        rows = [dict(r) for r in conn.execute(sql).fetchmany(500)]
        conn.close()
        return jsonify(rows)
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    print("DB:", DB)
    print("http://127.0.0.1:5000")
    print("Ctrl+C to quit")
    app.run(debug=False, port=5000)
"""

_DYNAMIC_INDEX_HTML = """<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8"><title>__TITLE__</title>
<style>body{font-family:-apple-system,"Segoe UI",sans-serif;margin:24px;background:#f8fafc}h1{color:#1e40af}h2{color:#1e3a8a;margin-top:24px;border-left:4px solid #2563eb;padding-left:8px}table{border-collapse:collapse;width:100%;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.06);margin-bottom:16px}th{background:#2563eb;color:#fff;padding:8px;text-align:left}td{padding:6px 8px;border:1px solid #e2e8f0}.err{color:#dc2626}</style></head>
<body><h1>__TITLE__</h1><div id="content">loading...</div>
<script>
const API='http://127.0.0.1:5000';
fetch(API+'/api/tables').then(r=>r.json()).then(tables=>{
  const c=document.getElementById('content');c.innerHTML='';
  Promise.all(tables.map(t=>fetch(API+'/api/query?sql='+encodeURIComponent('SELECT * FROM '+t+' LIMIT 200')).then(r=>r.json()).then(rows=>({t,rows})))).then(data=>{
    data.forEach(({t,rows})=>{
      const h2=document.createElement('h2');h2.textContent=t+' ('+(Array.isArray(rows)?rows.length:0)+' rows)';c.appendChild(h2);
      if(!Array.isArray(rows)||!rows.length){const p=document.createElement('p');p.textContent=(rows&&rows.error)||'no data';c.appendChild(p);return;}
      const tb=document.createElement('table');const tr=document.createElement('tr');Object.keys(rows[0]).forEach(k=>{const th=document.createElement('th');th.textContent=k;tr.appendChild(th)});tb.appendChild(tr);
      rows.forEach(r=>{const trow=document.createElement('tr');Object.values(r).forEach(v=>{const td=document.createElement('td');td.textContent=v;trow.appendChild(td)});tb.appendChild(trow)});c.appendChild(tb);
    });
  });
}).catch(e=>{document.getElementById('content').innerHTML='<p class="err">后端服务未启动，请双击 启动服务.bat</p>';});
</script></body></html>
"""


def _auto_output_dir(kind, output_dir):
    from datetime import datetime
    base = output_dir or './output'
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    sub = os.path.join(base, f'{kind}_{ts}')
    os.makedirs(sub, exist_ok=True)
    return sub


def _gen_dynamic_report(output_dir, title):
    if not output_dir:
        return None, None
    try:
        os.makedirs(output_dir, exist_ok=True)
        app_path = os.path.join(output_dir, 'app.py')
        with open(app_path, 'w', encoding='utf-8') as f:
            f.write(_DYNAMIC_APP_PY)
        html_path = os.path.join(output_dir, 'index.html')
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(_DYNAMIC_INDEX_HTML.replace('__TITLE__', title))
        generate_bat_files(output_dir)
        return app_path, html_path
    except Exception as e:
        return f'app/html 生成失败: {e}', None


_SO_LEVEL_HTML = """<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8"><title>.so 级 CFI 检测</title>
<script src="https://cdn.jsdelivr.net/npm/echarts@5.5.0/dist/echarts.min.js"></script>
<style>:root{--bg:#eef2f7;--card:#fff;--primary:#4f46e5;--green:#059669;--red:#dc2626;--blue:#2563eb;--text:#0f172a;--border:#e2e8f0}*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Inter',-apple-system,sans-serif;background:var(--bg);color:var(--text);line-height:1.6}.hero{background:linear-gradient(135deg,#1e1b4b,#312e81,#4338ca);color:#fff;padding:48px 20px 56px;text-align:center}.hero h1{font-size:2.2rem;font-weight:800;margin-bottom:8px}.hero p{opacity:.85}.container{max-width:1180px;margin:-32px auto 0;padding:0 20px 40px;position:relative;z-index:2}.section{background:var(--card);border-radius:14px;padding:28px;margin-bottom:20px;box-shadow:0 4px 6px rgba(0,0,0,.04)}.section h2{font-size:1.3rem;font-weight:700;margin-bottom:18px;display:flex;align-items:center;gap:8px}.section h2:before{content:'';display:inline-block;width:4px;height:22px;background:var(--primary);border-radius:4px}.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:14px;margin:20px 0}.stat{background:linear-gradient(135deg,#f8faff,#f1f5f9);border-radius:12px;padding:20px 14px;text-align:center;border:1px solid var(--border)}.stat .num{font-size:1.8rem;font-weight:800}.stat .lbl{font-size:.8rem;color:#64748b;margin-top:6px}.charts-row{display:flex;flex-wrap:wrap;gap:16px;justify-content:center;margin:24px 0}.chart-box{width:240px;height:260px}.module-block{background:var(--card);border-radius:12px;margin-bottom:10px;border:1px solid var(--border);overflow:hidden}.module-head{padding:14px 18px;cursor:pointer;display:flex;justify-content:space-between;align-items:center;background:linear-gradient(135deg,#f8faff,#f8faff)}.module-head h3{font-size:1.1rem;font-weight:700}.mod-stats{display:flex;gap:8px;flex-wrap:wrap;font-size:.82rem;color:#475569}.badge{display:inline-block;padding:3px 11px;border-radius:50px;font-size:.72rem;font-weight:600}.badge.green{background:#d1fae5;color:#065f46}.badge.red{background:#fee2e2;color:#991b1b}.module-content{padding:10px 18px;display:none}.mod-chart{width:110px;height:110px;flex-shrink:0}.so-section{margin-bottom:6px;border:1px solid var(--border);border-radius:10px;overflow:hidden}.so-header{padding:11px 16px;display:flex;justify-content:space-between;background:#f8faff}.so-path{font-family:'SF Mono',monospace;font-size:.83rem}.loading{text-align:center;padding:24px}.spinner{display:inline-block;width:30px;height:30px;border:3px solid #e2e8f0;border-top-color:var(--primary);border-radius:50%;animation:spin .7s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}</style></head>
<body><div class="hero"><h1>.so 级 CFI 检测</h1><p id="hero-sub">加载中...</p></div>
<div class="container"><div class="section"><h2>总体结果</h2><div id="stats" class="stats"><div class="loading"><div class="spinner"></div></div></div><div class="charts-row" id="pies"></div></div>
<div class="section"><h2>模块列表</h2><div id="modules"><div class="loading"><div class="spinner"></div></div></div></div></div>
<script>
const API='http://127.0.0.1:5000';
function makePie(id,pct,label,mini){let div=document.getElementById(id);if(!div){div=document.createElement('div');div.className='chart-box';div.id=id;document.getElementById('pies').appendChild(div);}const color=pct>=70?'#059669':(pct>=30?'#2563eb':'#dc2626');echarts.init(div).setOption({tooltip:{trigger:'item'},title:{text:Math.round(pct*10)/10+'%',subtext:mini?'':label,left:'center',top:'center',textStyle:{fontSize:mini?15:24,fontWeight:'bold',color:color}},series:[{type:'pie',radius:mini?['55%','75%']:['64%','82%'],center:['50%','50%'],silent:true,label:{show:false},labelLine:{show:false},data:[{value:pct,itemStyle:{color:color,borderRadius:8,borderColor:'#fff',borderWidth:3}},{value:100-pct,itemStyle:{color:'#f1f5f9',borderColor:'#fff',borderWidth:2}}],animationType:'scale',animationDuration:600}]});
}
const loadedMods=new Set();
async function init(){try{const s=await(await fetch(API+'/api/summary')).json();const rate=s.total_so>0?Math.round(s.cfi_enabled_so/s.total_so*100*10)/10:0;document.getElementById('hero-sub').textContent='共 '+s.total_so+' 个 .so，CFI 开启 '+s.cfi_enabled_so+'（'+rate+'%）';const items=[{n:s.total_so,l:'.so 总数',c:'#4f46e5'},{n:s.cfi_enabled_so,l:'CFI 已开启',c:'#059669'},{n:s.cfi_not_enabled_so,l:'CFI 未开启',c:'#dc2626'},{n:rate+'%',l:'.so 覆盖率',c:'#2563eb'}];document.getElementById('stats').innerHTML=items.map(s=>'<div class="stat"><div class="num" style="color:'+s.c+'">'+s.n+'</div><div class="lbl">'+s.l+'</div></div>').join('');makePie('p1',rate,'.so CFI 覆盖率');const mods=await(await fetch(API+'/api/modules')).json();document.getElementById('modules').innerHTML=mods.map((m,i)=>'<div class="module-block"><div class="module-head" onclick="toggleModule(\\''+m.module+'\\')"><h3>'+m.module+' <small style="color:#64748b;font-weight:400">'+(m.desc||'')+'</small></h3><div class="mod-stats"><span>.so: '+m.total_so+'</span><span class="badge green">CFI: '+m.cfi_enabled_so+'</span>'+(m.cfi_not_enabled_so>0?'<span class="badge red">未开: '+m.cfi_not_enabled_so+'</span>':'')+'</div><div id="mc_'+i+'" class="mod-chart"></div></div><div id="content_'+m.module+'" class="module-content"></div></div>').join('');mods.forEach((m,i)=>makePie('mc_'+i,m.cfi_rate_percent||0,'覆盖率',true));}catch(e){if(!window._r)window._r=0;window._r++;if(window._r<=5){document.querySelector('.container').innerHTML='<div class="section" style="text-align:center;padding:60px;"><div class="spinner"></div><p>服务启动中，请稍候...</p></div>';setTimeout(init,1500);return;}document.querySelector('.container').innerHTML='<div class="section" style="text-align:center;padding:60px;"><h2 style="border:none;">后端服务未启动</h2><p>请双击 启动服务.bat 启动后端服务</p><button onclick="location.reload()" style="margin-top:16px;padding:10px 28px;border:none;border-radius:8px;background:#4f46e5;color:#fff;cursor:pointer;">重试</button></div>';}}
async function toggleModule(m){const el=document.getElementById('content_'+m);if(el.style.display==='block'){el.style.display='none';return;}el.style.display='block';if(loadedMods.has(m))return;loadedMods.add(m);el.innerHTML='<div class="loading"><div class="spinner"></div></div>';try{const d=await(await fetch(API+'/api/modules/'+m)).json();el.innerHTML=(d.so_files||[]).map(so=>'<div class="so-section"><div class="so-header"><span class="so-path">'+so.path+'</span>'+(so.cfi_enabled?'<span class="badge green">CFI</span>':'<span class="badge red">NO CFI</span>')+'</div></div>').join('')||'<div style="padding:14px;color:#94a3b8;">无</div>';}catch(e){el.innerHTML='<div style="padding:14px;color:#94a3b8;">加载失败</div>';}}
init();
</script></body></html>
"""


def _gen_so_level_html(output_dir):
    try:
        out = os.path.join(output_dir, 'index.html')
        with open(out, 'w', encoding='utf-8') as f:
            f.write(_SO_LEVEL_HTML)
        return out
    except Exception as e:
        return f'HTML 生成失败: {e}'


_DIM_CSS = """:root{--bg:#eef2f7;--card:#fff;--primary:#4f46e5;--green:#059669;--red:#dc2626;--blue:#2563eb;--text:#0f172a;--border:#e2e8f0}*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Inter',-apple-system,sans-serif;background:var(--bg);color:var(--text);line-height:1.6}.hero{background:linear-gradient(135deg,#1e1b4b,#312e81,#4338ca);color:#fff;padding:48px 20px 56px;text-align:center}.hero h1{font-size:2.2rem;font-weight:800;margin-bottom:8px}.hero p{opacity:.85}.container{max-width:1180px;margin:-32px auto 0;padding:0 20px 40px;position:relative;z-index:2}.section{background:var(--card);border-radius:14px;padding:28px;margin-bottom:20px;box-shadow:0 4px 6px rgba(0,0,0,.04)}.section h2{font-size:1.3rem;font-weight:700;margin-bottom:18px;display:flex;align-items:center;gap:8px}.section h2:before{content:'';display:inline-block;width:4px;height:22px;background:var(--primary);border-radius:4px}.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:14px;margin:20px 0}.stat{background:linear-gradient(135deg,#f8faff,#f1f5f9);border-radius:12px;padding:20px 14px;text-align:center;border:1px solid var(--border)}.stat .num{font-size:1.8rem;font-weight:800}.stat .lbl{font-size:.8rem;color:#64748b;margin-top:6px}.charts-row{display:flex;flex-wrap:wrap;gap:16px;justify-content:center;margin:24px 0}.chart-box{width:240px;height:260px}.module-block{background:var(--card);border-radius:12px;margin-bottom:10px;border:1px solid var(--border);overflow:hidden}.module-head{padding:14px 18px;cursor:pointer;display:flex;justify-content:space-between;align-items:center;background:linear-gradient(135deg,#f8faff,#f8faff)}.module-head h3{font-size:1.1rem;font-weight:700}.mod-stats{display:flex;gap:8px;flex-wrap:wrap;font-size:.82rem;color:#475569}.badge{display:inline-block;padding:3px 11px;border-radius:50px;font-size:.72rem;font-weight:600;margin-left:4px}.badge.green{background:#d1fae5;color:#065f46}.badge.red{background:#fee2e2;color:#991b1b}.module-content{padding:10px 18px;display:none}.mod-chart{width:110px;height:110px;flex-shrink:0}.so-section{margin-bottom:6px;border:1px solid var(--border);border-radius:10px;overflow:hidden}.so-header{padding:11px 16px;display:flex;justify-content:space-between;align-items:center;background:#f8faff;flex-wrap:wrap;gap:4px}.so-path{font-family:'SF Mono',monospace;font-size:.83rem}.loading{text-align:center;padding:24px}.spinner{display:inline-block;width:30px;height:30px;border:3px solid #e2e8f0;border-top-color:var(--primary);border-radius:50%;animation:spin .7s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}"""


def _gen_dim_html(output_dir, title, sections, so_fields):
    import json as _j
    html = f"""<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8"><title>{title}</title>
<script src="https://cdn.jsdelivr.net/npm/echarts@5.5.0/dist/echarts.min.js"></script>
<style>{_DIM_CSS}</style></head>
<body><div class="hero"><h1>{title}</h1><p id="hero-sub">加载中...</p></div>
<div class="container"><div class="section"><h2>总体结果</h2><div id="stats"><div class="loading"><div class="spinner"></div></div></div><div class="charts-row" id="pies"></div></div>
<div class="section"><h2>模块列表</h2><div id="modules"><div class="loading"><div class="spinner"></div></div></div></div></div>
<script>
const API='http://127.0.0.1:5000';
const SECTIONS={_j.dumps(sections, ensure_ascii=False)};
const SO_FIELDS={_j.dumps(so_fields, ensure_ascii=False)};
function makePie(id,pct,label,mini){{const div=document.getElementById(id)||document.createElement('div');if(!div.id){{div.className='chart-box';div.id=id;document.getElementById('pies').appendChild(div);}}const color=pct>=70?'#059669':(pct>=30?'#2563eb':'#dc2626');echarts.init(div).setOption({{tooltip:{{trigger:'item'}},title:{{text:Math.round(pct*10)/10+'%',subtext:mini?'':label,left:'center',top:'center',textStyle:{{fontSize:mini?15:24,fontWeight:'bold',color:color}}}},series:[{{type:'pie',radius:mini?['55%','75%']:['64%','82%'],center:['50%','50%'],silent:true,label:{{show:false}},labelLine:{{show:false}},data:[{{value:pct,itemStyle:{{color:color,borderRadius:8,borderColor:'#fff',borderWidth:3}}}},{{value:100-pct,itemStyle:{{color:'#f1f5f9',borderColor:'#fff',borderWidth:2}}}}],animationType:'scale',animationDuration:600}}]}});}}
function calcRate(expr,s){{try{{return new Function('s','return '+expr)(s);}}catch(e){{return 0;}}}}
function modRate(sec,m){{if(sec.pie_label.includes('.so'))return m.cfi_rate_percent||0;if(sec.pie_label.includes('函数'))return (m.cfi_protected_count+m.truly_unprotected_count)>0?m.cfi_protected_count/(m.cfi_protected_count+m.truly_unprotected_count)*100:0;if(sec.pie_label.includes('vcall'))return m.vcall_cfi_rate||0;if(sec.pie_label.includes('icall'))return m.icall_cfi_rate||0;return 0;}}
const loadedMods=new Set();
async function init(){{try{{const s=await(await fetch(API+'/api/summary')).json();document.getElementById('hero-sub').textContent='共 '+s.total_so+' 个 .so，CFI 开启 '+s.cfi_enabled_so+'（'+(s.total_so>0?Math.round(s.cfi_enabled_so/s.total_so*100*10)/10:0)+'%）';let statsHtml='';SECTIONS.forEach((sec,si)=>{{const rate=calcRate(sec.pie_expr,s);statsHtml+='<div style="width:100%;margin:12px 0 4px;font-weight:700;color:#1e40af;">'+sec.title+'</div>';statsHtml+='<div style="display:flex;flex-wrap:nowrap;gap:10px;margin-bottom:12px;overflow-x:auto">'+sec.cards.map(c=>'<div class="stat" style="min-width:90px;flex-shrink:0"><div class="num" style="color:'+c[2]+'">'+(s[c[1]]??0)+'</div><div class="lbl">'+c[0]+'</div></div>').join('')+'</div>';makePie('p_'+si,rate,sec.pie_label);}});document.getElementById('stats').innerHTML=statsHtml;const mods=await(await fetch(API+'/api/modules')).json();document.getElementById('modules').innerHTML=mods.map((m,i)=>'<div class="module-block"><div class="module-head" onclick="toggleModule(\\''+m.module+'\\')"><div style="flex:1;min-width:0"><h3>'+m.module+' <small style="color:#64748b;font-weight:400">'+(m.desc||'')+'</small></h3><div class="mod-stats"><span>.so: '+m.total_so+'</span>'+SO_FIELDS.map(f=>'<span>'+f[0]+': '+(m[f[1]]||0)+'</span>').join('')+'</div></div>'+SECTIONS.map((sec,si)=>'<div id="mc_'+i+'_'+si+'" style="width:80px;height:80px;flex-shrink:0"></div>').join('')+'</div><div id="content_'+m.module+'" class="module-content"></div></div>').join('');mods.forEach((m,i)=>{{SECTIONS.forEach((sec,si)=>{{makePie('mc_'+i+'_'+si,modRate(sec,m),sec.pie_label,true);}});}});}}catch(e){{if(!window._r)window._r=0;window._r++;if(window._r<=5){{document.querySelector('.container').innerHTML='<div class="section" style="text-align:center;padding:60px;"><div class="spinner"></div><p>服务启动中，请稍候...</p></div>';setTimeout(init,1500);return;}}document.querySelector('.container').innerHTML='<div class="section" style="text-align:center;padding:60px;"><h2 style="border:none;">后端服务未启动</h2><p>请双击 启动服务.bat</p><button onclick="location.reload()" style="margin-top:16px;padding:10px 28px;border:none;border-radius:8px;background:#4f46e5;color:#fff;cursor:pointer;">重试</button></div>';}}}}
async function toggleModule(m){{const el=document.getElementById('content_'+m);if(el.style.display==='block'){{el.style.display='none';return;}}el.style.display='block';if(loadedMods.has(m))return;loadedMods.add(m);el.innerHTML='<div class="loading"><div class="spinner"></div></div>';try{{const d=await(await fetch(API+'/api/modules/'+m)).json();el.innerHTML=(d.so_files||[]).map(so=>'<div class="so-section"><div class="so-header"><span class="so-path">'+so.path+'</span>'+SO_FIELDS.map(f=>'<span class="badge '+(f[2]||'')+'">'+f[0]+': '+(so[f[1]]||0)+'</span>').join('')+'</div></div>').join('')||'<div style="padding:14px;color:#94a3b8;">无</div>';}}catch(e){{el.innerHTML='<div style="padding:14px;color:#94a3b8;">加载失败</div>';}}}}
init();
</script></body></html>"""
    try:
        out = os.path.join(output_dir, 'index.html')
        with open(out, 'w', encoding='utf-8') as f:
            f.write(html)
        return out
    except Exception as e:
        return f'HTML 生成失败: {e}'


def _build_so_level_full_data(results, summary):
    from collections import defaultdict
    modules_dict = defaultdict(lambda: {'so_files': [], 'cfi_enabled_so': 0, 'cfi_not_enabled_so': 0})
    for r in results:
        path = r['path']
        module = extract_module(path)
        m = modules_dict[module]
        m['so_files'].append({
            'path': path, 'cfi_enabled': int(r['cfi_enabled']),
            'cfi_protected_count': 0, 'cfi_infra_count': 0, 'truly_unprotected_count': 0, 'other_count': 0,
            'vcall_site_count': 0, 'vcall_cfi_count': 0, 'vcall_no_cfi_count': 0, 'vcall_cfi_rate': 0,
            'icall_site_count': 0, 'icall_cfi_count': 0, 'icall_no_cfi_count': 0, 'icall_cfi_rate': 0,
        })
        if r['cfi_enabled']:
            m['cfi_enabled_so'] += 1
        else:
            m['cfi_not_enabled_so'] += 1
    module_list = []
    for mod in sorted(modules_dict.keys()):
        m = modules_dict[mod]
        total = m['cfi_enabled_so'] + m['cfi_not_enabled_so']
        rate = round(m['cfi_enabled_so'] / total * 100, 1) if total else 0
        module_list.append({
            'module': mod, 'desc': MODULE_DESC.get(mod, ''), 'total_so': total,
            'cfi_enabled_so': m['cfi_enabled_so'], 'cfi_not_enabled_so': m['cfi_not_enabled_so'],
            'cfi_rate_percent': rate, 'cfi_protected_count': 0, 'cfi_infra_count': 0,
            'truly_unprotected_count': 0, 'other_count': 0,
            'vcall_site_count': 0, 'vcall_cfi_count': 0, 'vcall_no_cfi_count': 0, 'vcall_cfi_rate': 0,
            'icall_site_count': 0, 'icall_cfi_count': 0, 'icall_no_cfi_count': 0, 'icall_cfi_rate': 0,
            'so_files': m['so_files'],
        })
    full_summary = {
        'total_so': summary['total_so'], 'cfi_enabled_so': summary['cfi_enabled_so'],
        'cfi_not_enabled_so': summary['cfi_not_enabled_so'], 'function_detail': 0,
        'total_cfi_protected_funcs': 0, 'total_cfi_infra': 0, 'total_truly_unprotected': 0, 'total_other_funcs': 0,
        'total_vcall_sites': 0, 'total_vcall_cfi': 0, 'total_vcall_no_cfi': 0, 'total_vcall_cfi_rate': 0,
        'total_icall_sites': 0, 'total_icall_cfi': 0, 'total_icall_no_cfi': 0, 'total_icall_cfi_rate': 0,
    }
    return full_summary, module_list


def _build_functions_full_data(stats, per_so):
    from collections import defaultdict
    modules_dict = defaultdict(lambda: {'so_files': [], 'cfi_enabled_so': 0, 'cfi_not_enabled_so': 0,
                                         'cfi_protected_count': 0, 'truly_unprotected_count': 0, 'cfi_infra_count': 0})
    for p in per_so:
        m = modules_dict[p['module']]
        m['so_files'].append({
            'path': p['path'], 'cfi_enabled': p['cfi_enabled'],
            'cfi_protected_count': p['protected'], 'cfi_infra_count': p['infra'],
            'truly_unprotected_count': p['unprotected'], 'other_count': 0,
            'vcall_site_count': 0, 'vcall_cfi_count': 0, 'vcall_no_cfi_count': 0, 'vcall_cfi_rate': 0,
            'icall_site_count': 0, 'icall_cfi_count': 0, 'icall_no_cfi_count': 0, 'icall_cfi_rate': 0,
        })
        if p['cfi_enabled']:
            m['cfi_enabled_so'] += 1
        else:
            m['cfi_not_enabled_so'] += 1
        m['cfi_protected_count'] += p['protected']
        m['truly_unprotected_count'] += p['unprotected']
        m['cfi_infra_count'] += p['infra']
    module_list = []
    for mod in sorted(modules_dict.keys()):
        m = modules_dict[mod]
        total = m['cfi_enabled_so'] + m['cfi_not_enabled_so']
        module_list.append({
            'module': mod, 'desc': MODULE_DESC.get(mod, ''), 'total_so': total,
            'cfi_enabled_so': m['cfi_enabled_so'], 'cfi_not_enabled_so': m['cfi_not_enabled_so'],
            'cfi_rate_percent': round(m['cfi_enabled_so'] / total * 100, 1) if total else 0,
            'cfi_protected_count': m['cfi_protected_count'], 'cfi_infra_count': m['cfi_infra_count'],
            'truly_unprotected_count': m['truly_unprotected_count'], 'other_count': 0,
            'vcall_site_count': 0, 'vcall_cfi_count': 0, 'vcall_no_cfi_count': 0, 'vcall_cfi_rate': 0,
            'icall_site_count': 0, 'icall_cfi_count': 0, 'icall_no_cfi_count': 0, 'icall_cfi_rate': 0,
            'so_files': m['so_files'],
        })
    full_summary = {
        'total_so': stats['total_so'], 'cfi_enabled_so': stats['cfi_enabled_so'],
        'cfi_not_enabled_so': stats['cfi_not_enabled_so'], 'function_detail': 1,
        'total_cfi_protected_funcs': stats['cfi_protected_count'],
        'total_cfi_infra': stats['cfi_infra_count'],
        'total_truly_unprotected': stats['truly_unprotected_count'],
        'total_other_funcs': stats['other_count'],
        'total_vcall_sites': 0, 'total_vcall_cfi': 0, 'total_vcall_no_cfi': 0, 'total_vcall_cfi_rate': 0,
        'total_icall_sites': 0, 'total_icall_cfi': 0, 'total_icall_no_cfi': 0, 'total_icall_cfi_rate': 0,
    }
    return full_summary, module_list


def _build_calls_full_data(kind, stats, per_so):
    from collections import defaultdict
    modules_dict = defaultdict(lambda: {'so_files': [], 'cfi_enabled_so': 0, 'cfi_not_enabled_so': 0,
                                         'site': 0, 'cfi': 0, 'no_cfi': 0, 'prot': 0, 'unprot': 0, 'infra': 0})
    for p in per_so:
        m = modules_dict[p['module']]
        m['so_files'].append({
            'path': p['path'], 'cfi_enabled': p['cfi_enabled'],
            'cfi_protected_count': p['protected'], 'cfi_infra_count': p['infra'], 'truly_unprotected_count': p['unprotected'], 'other_count': 0,
            f'{kind}_site_count': p['site'], f'{kind}_cfi_count': p['cfi'], f'{kind}_no_cfi_count': p['no_cfi'],
            f'{kind}_cfi_rate': round(p['cfi'] / p['site'] * 100, 1) if p['site'] else 0,
            **{f'{"vcall" if kind == "icall" else "icall"}_site_count': 0, f'{"vcall" if kind == "icall" else "icall"}_cfi_count': 0, f'{"vcall" if kind == "icall" else "icall"}_no_cfi_count': 0, f'{"vcall" if kind == "icall" else "icall"}_cfi_rate': 0},
        })
        if p['cfi_enabled']:
            m['cfi_enabled_so'] += 1
        else:
            m['cfi_not_enabled_so'] += 1
        m['site'] += p['site']
        m['cfi'] += p['cfi']
        m['no_cfi'] += p['no_cfi']
        m['prot'] += p['protected']
        m['unprot'] += p['unprotected']
        m['infra'] += p['infra']
    other = 'icall' if kind == 'vcall' else 'vcall'
    module_list = []
    for mod in sorted(modules_dict.keys()):
        m = modules_dict[mod]
        total = m['cfi_enabled_so'] + m['cfi_not_enabled_so']
        module_list.append({
            'module': mod, 'desc': MODULE_DESC.get(mod, ''), 'total_so': total,
            'cfi_enabled_so': m['cfi_enabled_so'], 'cfi_not_enabled_so': m['cfi_not_enabled_so'],
            'cfi_rate_percent': round(m['cfi_enabled_so'] / total * 100, 1) if total else 0,
            'cfi_protected_count': m['prot'], 'cfi_infra_count': m['infra'], 'truly_unprotected_count': m['unprot'], 'other_count': 0,
            f'{kind}_site_count': m['site'], f'{kind}_cfi_count': m['cfi'], f'{kind}_no_cfi_count': m['no_cfi'],
            f'{kind}_cfi_rate': round(m['cfi'] / m['site'] * 100, 1) if m['site'] else 0,
            f'{other}_site_count': 0, f'{other}_cfi_count': 0, f'{other}_no_cfi_count': 0, f'{other}_cfi_rate': 0,
            'so_files': m['so_files'],
        })
    full_summary = {
        'total_so': stats['total_so'], 'cfi_enabled_so': stats['cfi_enabled_so'],
        'cfi_not_enabled_so': stats['cfi_not_enabled_so'], 'function_detail': 1,
        'total_cfi_protected_funcs': stats['total_cfi_protected_funcs'],
        'total_cfi_infra': stats['total_cfi_infra'],
        'total_truly_unprotected': stats['total_truly_unprotected'],
        'total_other_funcs': 0,
        f'total_{kind}_sites': stats[f'{kind}_site_count'], f'total_{kind}_cfi': stats[f'{kind}_cfi_count'],
        f'total_{kind}_no_cfi': stats[f'{kind}_no_cfi_count'], f'total_{kind}_cfi_rate': stats[f'{kind}_cfi_rate'],
        f'total_{other}_sites': 0, f'total_{other}_cfi': 0, f'total_{other}_no_cfi': 0, f'total_{other}_cfi_rate': 0,
    }
    return full_summary, module_list


def build_registry(defaults=None, extra_tools=None, on_log=None, on_progress=None) -> ToolRegistry:
    reg = ToolRegistry(defaults=defaults or {})
    reg.on_log = on_log
    reg.on_progress = on_progress

    def t_run_cfi_detection(lib_dir=None, mode='full', output_dir='', start_web=True):
        lib_dir = lib_dir or reg.defaults.get('lib_dir')
        if not lib_dir:
            return "错误：未提供 lib_dir，也无默认值"
        if not os.path.isdir(lib_dir):
            return f"错误：目录不存在 {lib_dir}"
        if mode not in ('full', 'fast'):
            mode = 'full'
        output_dir = _auto_output_dir('full', output_dir or reg.defaults.get('output_dir'))

        summary, modules = run_full_pipeline(
            lib_dir, output_dir, mode=mode,
            progress=reg.on_progress or (lambda i, total, path: None),
            log=reg.on_log or (lambda m: None),
            start_web=bool(start_web),
        )
        return {
            'status': '完成',
            'mode': mode,
            'output_dir': output_dir,
            'summary': {
                'total_so': summary['total_so'],
                'cfi_enabled_so': summary['cfi_enabled_so'],
                'cfi_not_enabled_so': summary['cfi_not_enabled_so'],
                'total_cfi_protected_funcs': summary.get('total_cfi_protected_funcs', 0),
                'total_truly_unprotected': summary.get('total_truly_unprotected', 0),
                'total_vcall_sites': summary.get('total_vcall_sites', 0),
                'vcall_cfi_rate': summary.get('total_vcall_cfi_rate', 0),
                'total_icall_sites': summary.get('total_icall_sites', 0),
                'icall_cfi_rate': summary.get('total_icall_cfi_rate', 0),
            },
            '提示': '已生成 SQLite/HTML/Excel/Flask 服务。可双击 output_dir 下 index.html 查看报告。',
        }

    reg.add(
        'run_cfi_detection',
        '对 OpenHarmony 未 strip 的 .so 集合执行 CFI 安全检测（Skill 1-10 全流程）。'
        '生成 SQLite 数据库、HTML 报告、Flask API、Excel 报告，并可选后台启动 Web 服务。'
        'mode=full 完整检测（.so级+函数级+vcall/icall），mode=fast 仅 .so 级。',
        {
            'type': 'object',
            'properties': {
                'lib_dir': {'type': 'string', 'description': 'lib.unstripped 目录路径（未 strip 的 .so 集合）'},
                'mode': {'type': 'string', 'enum': ['full', 'fast'], 'default': 'full'},
                'output_dir': {'type': 'string', 'description': '输出目录，留空用默认'},
                'start_web': {'type': 'boolean', 'default': True, 'description': '是否后台启动 Flask 报告服务'},
            },
            'required': ['lib_dir'],
        },
        t_run_cfi_detection,
    )

    def t_detect_so_level(lib_dir=None, limit=50, output_dir='', start_web=True):
        lib_dir = lib_dir or reg.defaults.get('lib_dir')
        if not lib_dir:
            return "错误：未提供 lib_dir，也无默认值"
        if not os.path.isdir(lib_dir):
            return f"错误：目录不存在 {lib_dir}"
        output_dir = _auto_output_dir('so_level', output_dir or reg.defaults.get('output_dir'))
        ELFFile = ensure_pyelftools()
        results, summary = run_so_level(lib_dir, ELFFile, log=reg.on_log or (lambda m: None))
        full_summary, module_list = _build_so_level_full_data(results, summary)
        generate_sqlite(full_summary, module_list, [], output_dir)
        _gen_so_level_html(output_dir)
        generate_app(output_dir)
        generate_excel(full_summary, module_list, output_dir)
        generate_bat_files(output_dir)
        if start_web:
            stop_service()
            start_service(output_dir)
        no_cfi = [r for r in results if not r['cfi_enabled']][:limit]
        return {'summary': summary, 'output_dir': output_dir, 'no_cfi_so_sample': no_cfi,
                'note': f'未开 CFI 共 {summary["cfi_not_enabled_so"]} 个，已生成完整检测形式的报告（.so 级数据）于 {output_dir}，双击 index.html 查看'}

    reg.add(
        'detect_so_level',
        'Skill 1：只做 .so 级 CFI 检测（查 __cfi_check 符号），不扫函数/调用点，最快。'
        '返回总数、CFI 开启数、未开启 .so 列表样本，并生成 .so 级 Excel（未开 CFI 标红）。适合快速摸底"哪些没开 CFI"。',
        {
            'type': 'object',
            'properties': {
                'lib_dir': {'type': 'string', 'description': 'lib.unstripped 目录路径，留空用默认'},
                'limit': {'type': 'integer', 'default': 50, 'description': '未开 CFI 的 .so 列表显示前 N 个'},
                'output_dir': {'type': 'string', 'description': 'Excel 输出目录，留空用默认'},
            },
            'required': [],
        },
        t_detect_so_level,
    )

    def t_detect_functions(lib_dir=None, output_dir='', start_web=True):
        lib_dir = lib_dir or reg.defaults.get('lib_dir')
        if not lib_dir:
            return "错误：未提供 lib_dir"
        output_dir = _auto_output_dir('functions', output_dir or reg.defaults.get('output_dir'))
        ELFFile = ensure_pyelftools()
        cxxfilt = ensure_cxxfilt()
        results, summary = run_detection(lib_dir, ELFFile, function_detail=True,
                                         progress=reg.on_progress or (lambda i, total, path: None),
                                         log=reg.on_log or (lambda m: None))
        module_list, name_table = build_module_data(results, cxxfilt)
        generate_sqlite(summary, module_list, name_table, output_dir)
        _gen_dim_html(output_dir, '函数级 CFI 检测',
            [
                {'title':'.so 级','cards':[('.so总数','total_so','#4f46e5'),('CFI开启','cfi_enabled_so','#059669'),('CFI未开','cfi_not_enabled_so','#dc2626')],'pie_expr':'s.cfi_enabled_so/s.total_so*100','pie_label':'.so覆盖率'},
                {'title':'函数级','cards':[('保护函数','total_cfi_protected_funcs','#059669'),('未保护','total_truly_unprotected','#dc2626'),('基础设施','total_cfi_infra','#4f46e5')],'pie_expr':'s.total_cfi_protected_funcs/(s.total_cfi_protected_funcs+s.total_truly_unprotected)*100','pie_label':'函数保护率'},
            ],
            [('CFI','cfi_enabled',''),('保护','cfi_protected_count','green'),('未保护','truly_unprotected_count','red'),('基础设施','cfi_infra_count','')])
        generate_app(output_dir)
        generate_excel(summary, module_list, output_dir, include_calls=False)
        generate_bat_files(output_dir)
        summary['output_dir'] = output_dir
        if start_web:
            stop_service()
            start_service(output_dir)
        return summary

    reg.add(
        'detect_functions',
        'Skill 2：函数级检测，对开启 CFI 的 .so 分类保护/基础设施/真正未保护函数。'
        '返回保护函数数、未保护函数数、函数保护率，并生成函数级统计 Excel。',
        {
            'type': 'object',
            'properties': {'lib_dir': {'type': 'string'}, 'output_dir': {'type': 'string'}},
            'required': [],
        },
        t_detect_functions,
    )

    def t_detect_vcall(lib_dir=None, output_dir='', start_web=True):
        lib_dir = lib_dir or reg.defaults.get('lib_dir')
        if not lib_dir:
            return "错误：未提供 lib_dir"
        output_dir = _auto_output_dir('vcall', output_dir or reg.defaults.get('output_dir'))
        ELFFile = ensure_pyelftools()
        cxxfilt = ensure_cxxfilt()
        results, summary = run_detection(lib_dir, ELFFile, function_detail=True,
                                         progress=reg.on_progress or (lambda i, total, path: None),
                                         log=reg.on_log or (lambda m: None))
        module_list, name_table = build_module_data(results, cxxfilt)
        generate_sqlite(summary, module_list, name_table, output_dir)
        _gen_dim_html(output_dir, 'vcall 虚函数调用检测',
            [
                {'title':'.so 级','cards':[('.so总数','total_so','#4f46e5'),('CFI开启','cfi_enabled_so','#059669'),('CFI未开','cfi_not_enabled_so','#dc2626')],'pie_expr':'s.cfi_enabled_so/s.total_so*100','pie_label':'.so覆盖率'},
                {'title':'函数级','cards':[('保护函数','total_cfi_protected_funcs','#059669'),('未保护','total_truly_unprotected','#dc2626'),('基础设施','total_cfi_infra','#4f46e5')],'pie_expr':'s.total_cfi_protected_funcs/(s.total_cfi_protected_funcs+s.total_truly_unprotected)*100','pie_label':'函数保护率'},
                {'title':'vcall','cards':[('调用点','total_vcall_sites','#4f46e5'),('有CFI','total_vcall_cfi','#059669'),('无CFI','total_vcall_no_cfi','#dc2626')],'pie_expr':'s.total_vcall_cfi_rate','pie_label':'vcall保护率'},
            ],
            [('CFI','cfi_enabled',''),('保护','cfi_protected_count','green'),('未保护','truly_unprotected_count','red'),('调用点','vcall_site_count',''),('有CFI','vcall_cfi_count','green'),('无CFI','vcall_no_cfi_count','red')])
        generate_app(output_dir)
        generate_excel(summary, module_list, output_dir)
        generate_bat_files(output_dir)
        summary['output_dir'] = output_dir
        if start_web:
            stop_service()
            start_service(output_dir)
        return summary

    reg.add(
        'detect_vcall',
        'Skill 3：vcall（虚函数调用）检测，扫描 .text 找虚函数调用点 + CFI 保护判定。'
        '返回 vcall 调用点数、有/无 CFI 数、保护率，并生成 vcall 统计 Excel。',
        {
            'type': 'object',
            'properties': {'lib_dir': {'type': 'string'}, 'output_dir': {'type': 'string'}},
            'required': [],
        },
        t_detect_vcall,
    )

    def t_detect_icall(lib_dir=None, output_dir='', start_web=True):
        lib_dir = lib_dir or reg.defaults.get('lib_dir')
        if not lib_dir:
            return "错误：未提供 lib_dir"
        output_dir = _auto_output_dir('icall', output_dir or reg.defaults.get('output_dir'))
        ELFFile = ensure_pyelftools()
        cxxfilt = ensure_cxxfilt()
        results, summary = run_detection(lib_dir, ELFFile, function_detail=True,
                                         progress=reg.on_progress or (lambda i, total, path: None),
                                         log=reg.on_log or (lambda m: None))
        module_list, name_table = build_module_data(results, cxxfilt)
        generate_sqlite(summary, module_list, name_table, output_dir)
        _gen_dim_html(output_dir, 'icall 间接调用检测',
            [
                {'title':'.so 级','cards':[('.so总数','total_so','#4f46e5'),('CFI开启','cfi_enabled_so','#059669'),('CFI未开','cfi_not_enabled_so','#dc2626')],'pie_expr':'s.cfi_enabled_so/s.total_so*100','pie_label':'.so覆盖率'},
                {'title':'函数级','cards':[('保护函数','total_cfi_protected_funcs','#059669'),('未保护','total_truly_unprotected','#dc2626'),('基础设施','total_cfi_infra','#4f46e5')],'pie_expr':'s.total_cfi_protected_funcs/(s.total_cfi_protected_funcs+s.total_truly_unprotected)*100','pie_label':'函数保护率'},
                {'title':'icall','cards':[('调用点','total_icall_sites','#4f46e5'),('有CFI','total_icall_cfi','#059669'),('无CFI','total_icall_no_cfi','#dc2626')],'pie_expr':'s.total_icall_cfi_rate','pie_label':'icall保护率'},
            ],
            [('CFI','cfi_enabled',''),('保护','cfi_protected_count','green'),('未保护','truly_unprotected_count','red'),('调用点','icall_site_count',''),('有CFI','icall_cfi_count','green'),('无CFI','icall_no_cfi_count','red')])
        generate_app(output_dir)
        generate_excel(summary, module_list, output_dir)
        generate_bat_files(output_dir)
        summary['output_dir'] = output_dir
        if start_web:
            stop_service()
            start_service(output_dir)
        return summary

    reg.add(
        'detect_icall',
        'Skill 4：icall（非 vtable 间接调用，如函数指针/回调）检测，扫描 .text 找调用点 + CFI 保护判定。'
        '返回 icall 调用点数、有/无 CFI 数、保护率，并生成 icall 统计 Excel。',
        {
            'type': 'object',
            'properties': {'lib_dir': {'type': 'string'}, 'output_dir': {'type': 'string'}},
            'required': [],
        },
        t_detect_icall,
    )

    def t_regenerate_report(report_type, output_dir=''):
        output_dir = output_dir or reg.defaults.get('output_dir')
        if not output_dir:
            return "错误：未提供 output_dir"
        if report_type == 'html':
            generate_html(output_dir)
            return f"已重新生成 index.html: {os.path.join(output_dir, 'index.html')}"
        if report_type == 'app':
            generate_app(output_dir)
            return f"已重新生成 app.py: {os.path.join(output_dir, 'app.py')}"
        return f"不支持的报告类型 '{report_type}'，可选: html, app。Excel 报告需重跑检测。"

    reg.add(
        'regenerate_report',
        '重新生成某类报告文件（不重跑检测）。支持 html（前端页面）和 app（Flask API）。'
        'Excel 报告需重跑检测流程，不在此工具范围。',
        {
            'type': 'object',
            'properties': {
                'report_type': {'type': 'string', 'enum': ['html', 'app']},
                'output_dir': {'type': 'string'},
            },
            'required': ['report_type'],
        },
        t_regenerate_report,
    )

    def t_query_summary(output_dir=''):
        output_dir = output_dir or reg.defaults.get('output_dir')
        conn = _connect(output_dir)
        row = conn.execute('SELECT * FROM summary').fetchone()
        conn.close()
        if not row:
            return "无 summary 数据"
        return dict(row)

    reg.add(
        'query_summary',
        '查询 CFI 检测总体统计（来自 SQLite summary 表），含 .so 总数、CFI 开启数、'
        '保护函数数、未保护函数数、vcall/icall 调用点与保护率等。',
        {
            'type': 'object',
            'properties': {
                'output_dir': {'type': 'string', 'description': '检测输出目录，留空用默认'},
            },
            'required': [],
        },
        t_query_summary,
    )

    def t_query_no_cfi_so(output_dir='', module=None, limit=200):
        output_dir = output_dir or reg.defaults.get('output_dir')
        conn = _connect(output_dir)
        if module:
            rows = conn.execute(
                'SELECT module, path FROM so_files WHERE cfi_enabled=0 AND module=? ORDER BY path',
                (module,),
            ).fetchall()
        else:
            rows = conn.execute(
                'SELECT module, path FROM so_files WHERE cfi_enabled=0 ORDER BY module, path LIMIT ?',
                (limit,),
            ).fetchall()
        conn.close()
        items = [dict(r) for r in rows]
        shown, total = _truncate(items, limit)
        return {'no_cfi_so_count': total, 'items': shown, 'note': f'显示前 {len(shown)} 条' if len(shown) < total else '全部'}

    reg.add(
        'query_no_cfi_so',
        '查询未开启 CFI 的 .so 列表（cfi_enabled=0）。可按 module 过滤。',
        {
            'type': 'object',
            'properties': {
                'output_dir': {'type': 'string'},
                'module': {'type': 'string', 'description': '按模块过滤（路径第一段，如 security）'},
                'limit': {'type': 'integer', 'default': 200},
            },
            'required': [],
        },
        t_query_no_cfi_so,
    )

    def t_query_functions(so_id, func_type='unprotected', output_dir='', limit=100):
        output_dir = output_dir or reg.defaults.get('output_dir')
        conn = _connect(output_dir)
        if func_type in ('protected', 'unprotected', 'infra'):
            rows = conn.execute(
                'SELECT n.name FROM so_functions sf JOIN name_table n ON sf.func_id=n.id '
                'WHERE sf.so_id=? AND sf.func_type=? LIMIT ?',
                (so_id, func_type, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                'SELECT n.name, sf.func_type FROM so_functions sf JOIN name_table n ON sf.func_id=n.id '
                'WHERE sf.so_id=? LIMIT ?',
                (so_id, limit),
            ).fetchall()
        conn.close()
        return {'so_id': so_id, 'func_type': func_type, 'items': [dict(r) for r in rows]}

    reg.add(
        'query_functions',
        '查询某个 .so 的函数列表（按类型）。需先有检测结果（so_id 来自模块查询）。',
        {
            'type': 'object',
            'properties': {
                'so_id': {'type': 'integer', 'description': 'so_files 表主键 id'},
                'func_type': {'type': 'string', 'enum': ['protected', 'unprotected', 'infra', 'all'], 'default': 'unprotected'},
                'output_dir': {'type': 'string'},
                'limit': {'type': 'integer', 'default': 100},
            },
            'required': ['so_id'],
        },
        t_query_functions,
    )

    def t_search_functions(keyword, func_type=None, output_dir='', limit=50):
        output_dir = output_dir or reg.defaults.get('output_dir')
        if not keyword or len(keyword) < 2:
            return {'error': '关键词至少 2 个字符'}
        conn = _connect(output_dir)
        pattern = f'%{keyword}%'
        if func_type in ('protected', 'unprotected', 'infra'):
            rows = conn.execute(
                'SELECT n.name, sf.func_type, so.path, so.module FROM so_functions sf '
                'JOIN name_table n ON sf.func_id=n.id '
                'JOIN so_files so ON sf.so_id=so.id '
                'WHERE n.name LIKE ? AND sf.func_type=? LIMIT ?',
                (pattern, func_type, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                'SELECT n.name, sf.func_type, so.path, so.module FROM so_functions sf '
                'JOIN name_table n ON sf.func_id=n.id '
                'JOIN so_files so ON sf.so_id=so.id '
                'WHERE n.name LIKE ? LIMIT ?',
                (pattern, limit),
            ).fetchall()
        conn.close()
        return {'keyword': keyword, 'count': len(rows), 'items': [dict(r) for r in rows]}

    reg.add(
        'search_functions',
        '按关键词模糊搜索函数名（LIKE 匹配），返回函数名、类型、所属 .so 路径与模块。'
        '用于查找特定函数是否受 CFI 保护。',
        {
            'type': 'object',
            'properties': {
                'keyword': {'type': 'string', 'description': '函数名关键词（≥2字符）'},
                'func_type': {'type': 'string', 'enum': ['protected', 'unprotected', 'infra'], 'description': '可选过滤'},
                'output_dir': {'type': 'string'},
                'limit': {'type': 'integer', 'default': 50},
            },
            'required': ['keyword'],
        },
        t_search_functions,
    )

    def t_query_modules(output_dir=''):
        output_dir = output_dir or reg.defaults.get('output_dir')
        conn = _connect(output_dir)
        rows = conn.execute(
            'SELECT module, desc, total_so, cfi_enabled_so, cfi_not_enabled_so, cfi_rate_percent '
            'FROM modules ORDER BY cfi_rate_percent DESC'
        ).fetchall()
        conn.close()
        return {'modules': [dict(r) for r in rows]}

    reg.add(
        'query_modules',
        '查询所有模块的 CFI 覆盖概览（模块名、说明、.so总数、CFI开启数、覆盖率），按覆盖率降序。',
        {
            'type': 'object',
            'properties': {'output_dir': {'type': 'string'}},
            'required': [],
        },
        t_query_modules,
    )

    def t_start_service(output_dir=''):
        output_dir = output_dir or reg.defaults.get('output_dir')
        pid = start_service(output_dir)
        return {'status': '已启动', 'pid': pid, 'url': 'http://127.0.0.1:5000', 'output_dir': output_dir}

    reg.add(
        'start_report_service',
        '后台启动 Flask 报告 Web 服务（端口 5000），启动后可双击 index.html 或访问 http://127.0.0.1:5000。',
        {
            'type': 'object',
            'properties': {'output_dir': {'type': 'string'}},
            'required': [],
        },
        t_start_service,
    )

    def t_stop_service():
        killed = stop_service()
        return {'status': '已停止', 'killed_pids': killed}

    reg.add(
        'stop_report_service',
        '停止后台 Flask 报告服务（杀掉占用 5000 端口的进程）。',
        {'type': 'object', 'properties': {}, 'required': []},
        t_stop_service,
    )

    def t_query_sql(sql, output_dir='', limit=200):
        output_dir = output_dir or reg.defaults.get('output_dir')
        stmt = sql.strip().rstrip(';')
        if not stmt.lower().startswith('select'):
            return {'error': '仅允许 SELECT 查询'}
        conn = _connect(output_dir)
        conn.row_factory = sqlite3.Row
        try:
            cur = conn.execute(stmt)
            rows = [dict(r) for r in cur.fetchmany(limit)]
            return {'rowcount': len(rows), 'rows': rows}
        except Exception as e:
            return {'error': str(e)}
        finally:
            conn.close()

    reg.add(
        'query_sql',
        '对 CFI 检测结果数据库执行任意只读 SQL 查询（仅 SELECT，最多返回 200 行）。'
        '可用表：summary, modules, so_files, name_table, so_functions。'
        '示例：SELECT module,total_so,cfi_rate_percent FROM modules ORDER BY cfi_rate_percent DESC',
        {
            'type': 'object',
            'properties': {
                'sql': {'type': 'string', 'description': 'SELECT 语句'},
                'output_dir': {'type': 'string'},
                'limit': {'type': 'integer', 'default': 200},
            },
            'required': ['sql'],
        },
        t_query_sql,
    )

    def t_propose_plan(goal, steps):
        return json.dumps({"goal": goal, "steps": steps}, ensure_ascii=False)

    reg.add(
        'propose_plan',
        '对检测类任务（run_cfi_detection / detect_*）先提出执行计划供用户确认，再执行。'
        '用户确认后你才依次调用工具执行。简单查询（query_* / search_functions）可直接执行，不必先规划。',
        {
            'type': 'object',
            'properties': {
                'goal': {'type': 'string', 'description': '本次任务整体目标'},
                'steps': {
                    'type': 'array',
                    'description': '执行步骤列表',
                    'items': {
                        'type': 'object',
                        'properties': {
                            'step': {'type': 'integer'},
                            'action': {'type': 'string', 'description': '这一步做什么'},
                            'tool': {'type': 'string', 'description': '调用的工具名'},
                            'reason': {'type': 'string'},
                        },
                    },
                },
            },
            'required': ['goal', 'steps'],
        },
        t_propose_plan,
    )

    def t_reflect_check(summary):
        checks = []
        def add(name, status, detail=''):
            checks.append({'check': name, 'status': status, 'detail': detail})
        ts = summary.get('total_so', 0)
        on = summary.get('cfi_enabled_so', 0)
        off = summary.get('cfi_not_enabled_so', 0)
        add('so总数=开启+未开启', '正常' if on + off == ts else '异常', f'{on}+{off}={on+off}, total={ts}')
        add('开启数<=总数', '正常' if on <= ts else '异常')
        for k in ['vcall_cfi_rate', 'icall_cfi_rate']:
            r = summary.get(k, 0)
            add(k + ' 在0-100%', '正常' if 0 <= r <= 100 else '异常', f'{r}%')
        vs = summary.get('total_vcall_sites', 0)
        if vs > 0 and summary.get('total_vcall_cfi', 0) == 0:
            add('vcall有调用点但全无CFI', '需关注', f'{vs}个vcall全无保护')
        ics = summary.get('total_icall_sites', 0)
        if ics > 0 and summary.get('total_icall_cfi', 0) == 0:
            add('icall有调用点但全无CFI', '需关注')
        pf = summary.get('total_cfi_protected_funcs', 0) + summary.get('total_truly_unprotected', 0)
        if pf > 0:
            rate = round(summary.get('total_cfi_protected_funcs', 0) / pf * 100, 1)
            add('函数保护率', '正常', f'{rate}%')
        else:
            add('有函数数据', '需关注', '保护+未保护=0，可能未做函数级检测')
        abnormal = [c for c in checks if c['status'] in ('异常', '需关注')]
        return {'overall': '有异常需关注' if abnormal else '全部正常',
                'abnormal_count': len(abnormal), 'checks': checks}

    reg.add(
        'reflect_check',
        '反思自检：对检测返回的 summary 做合理性校验（so总数一致性、保护率范围、有调用点却无保护等）。'
        '完整检测后调用此工具自检结果质量，发现异常向用户提示。',
        {
            'type': 'object',
            'properties': {
                'summary': {'type': 'object', 'description': 'run_cfi_detection 返回的 summary 对象'},
            },
            'required': ['summary'],
        },
        t_reflect_check,
    )

    def t_list_history(output_dir=''):
        output_dir = output_dir or reg.defaults.get('output_dir')
        history_dir = os.path.join(output_dir, 'history')
        if not os.path.isdir(history_dir):
            return {'archives': [], 'note': '无历史存档，每次检测后会自动存档到 history/'}
        files = sorted(f for f in os.listdir(history_dir) if f.endswith('.sqlite'))
        return {'archives': files, 'count': len(files), 'note': '用 compare_changes 对比某存档与当前'}

    reg.add(
        'list_history',
        '列出历史检测存档（每次检测后自动存到 output/history/，文件名含时间戳）。'
        '用于查看可对比的历史版本。',
        {'type': 'object', 'properties': {'output_dir': {'type': 'string'}}, 'required': []},
        t_list_history,
    )

    def t_compare_changes(version_a, output_dir='', version_b='latest'):
        output_dir = output_dir or reg.defaults.get('output_dir')
        main_db = os.path.join(output_dir, 'cfi_detection.sqlite')
        history_dir = os.path.join(output_dir, 'history')
        if version_b == 'latest':
            db_b, label_b = main_db, 'latest(当前)'
        else:
            db_b, label_b = os.path.join(history_dir, version_b), version_b
        db_a, label_a = os.path.join(history_dir, version_a), version_a
        if not os.path.exists(db_a):
            return {'error': f'存档 {version_a} 不存在，用 list_history 查看'}
        if not os.path.exists(db_b):
            return {'error': '目标库不存在，请先检测'}
        ca = sqlite3.connect(db_a); ca.row_factory = sqlite3.Row
        cb = sqlite3.connect(db_b); cb.row_factory = sqlite3.Row
        a_rows = {r['path']: r['cfi_enabled'] for r in ca.execute('SELECT path, cfi_enabled FROM so_files')}
        b_rows = {r['path']: r['cfi_enabled'] for r in cb.execute('SELECT path, cfi_enabled FROM so_files')}
        enabled_now = [p for p, v in b_rows.items() if a_rows.get(p) == 0 and v == 1]
        disabled_now = [p for p, v in b_rows.items() if a_rows.get(p) == 1 and v == 0]
        sa = dict(ca.execute('SELECT * FROM summary').fetchone())
        sb = dict(cb.execute('SELECT * FROM summary').fetchone())
        ca.close(); cb.close()
        conn = sqlite3.connect(main_db)
        conn.execute('CREATE TABLE IF NOT EXISTS changes (id INTEGER PRIMARY KEY AUTOINCREMENT, path TEXT, field TEXT, old_value, new_value, version_a TEXT, version_b TEXT)')
        conn.execute('DELETE FROM changes')
        for p in enabled_now:
            conn.execute('INSERT INTO changes (path,field,old_value,new_value,version_a,version_b) VALUES (?,?,?,?,?,?)', (p, 'cfi_enabled', 0, 1, label_a, label_b))
        for p in disabled_now:
            conn.execute('INSERT INTO changes (path,field,old_value,new_value,version_a,version_b) VALUES (?,?,?,?,?,?)', (p, 'cfi_enabled', 1, 0, label_a, label_b))
        conn.commit(); conn.close()
        return {
            'version_a': label_a, 'version_b': label_b,
            'newly_enabled_cfi': enabled_now[:80], 'newly_enabled_count': len(enabled_now),
            'newly_disabled_cfi': disabled_now[:80], 'newly_disabled_count': len(disabled_now),
            'summary_delta': {k: (sa.get(k), sb.get(k)) for k in ['total_so', 'cfi_enabled_so', 'cfi_not_enabled_so', 'total_cfi_protected_funcs', 'total_truly_unprotected', 'total_vcall_cfi_rate', 'total_icall_cfi_rate']},
            'note': f'共 {len(enabled_now)+len(disabled_now)} 个 .so CFI 状态变化，已存入 changes 表。用 generate_changes_excel 生成变化报告。',
        }

    reg.add(
        'compare_changes',
        '对比两次检测的 .so CFI 状态变化（如某 .so 从未开 CFI 变为开启）。'
        'version_a 是历史存档文件名（用 list_history 查看，如 cfi_20260730_123456.sqlite），'
        'version_b 默认 latest（当前最新检测）。结果存入 changes 表。',
        {
            'type': 'object',
            'properties': {
                'version_a': {'type': 'string', 'description': '历史存档文件名（list_history 里的）'},
                'version_b': {'type': 'string', 'default': 'latest', 'description': '对比目标，默认 latest(当前)'},
                'output_dir': {'type': 'string'},
            },
            'required': ['version_a'],
        },
        t_compare_changes,
    )

    def t_generate_changes_excel(output_dir=''):
        output_dir = output_dir or reg.defaults.get('output_dir')
        main_db = os.path.join(output_dir, 'cfi_detection.sqlite')
        if not os.path.exists(main_db):
            return '错误：无检测结果库，先检测'
        conn = sqlite3.connect(main_db)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute('SELECT path, field, old_value, new_value, version_a, version_b FROM changes ORDER BY path').fetchall()
        except Exception as e:
            conn.close()
            return f'错误：无 changes 表（{e}），先 compare_changes 对比两次检测'
        conn.close()
        if not rows:
            return '无变化记录，先 compare_changes 对比两次检测'
        Workbook, Font, PatternFill, Alignment, Border, Side = ensure_openpyxl()
        wb = Workbook()
        ws = wb.active
        ws.title = 'CFI变化'
        headers = ['序号', '.so路径', '字段', '旧值', '新值', '变化', '版本A', '版本B']
        for col, h in enumerate(headers, 1):
            c = ws.cell(1, col, h)
            c.font = Font(bold=True, color='FFFFFF')
            c.fill = PatternFill(start_color='2563EB', end_color='2563EB', fill_type='solid')
            c.alignment = Alignment(horizontal='center')
        green = PatternFill(start_color='D1FAE5', end_color='D1FAE5', fill_type='solid')
        red = PatternFill(start_color='FEE2E2', end_color='FEE2E2', fill_type='solid')
        thin = Border(left=Side(style='thin', color='CBD5E1'), right=Side(style='thin', color='CBD5E1'), top=Side(style='thin', color='CBD5E1'), bottom=Side(style='thin', color='CBD5E1'))
        for i, r in enumerate(rows, 2):
            old, new = r['old_value'], r['new_value']
            change = '开启CFI(0→1)' if (old == 0 and new == 1) else ('关闭CFI(1→0)' if (old == 1 and new == 0) else f'{old}→{new}')
            vals = [i - 1, r['path'], r['field'], old, new, change, r['version_a'], r['version_b']]
            for col, v in enumerate(vals, 1):
                cell = ws.cell(i, col, v)
                cell.border = thin
                if col == 6:
                    cell.fill = green if (old == 0 and new == 1) else red
        ws.column_dimensions['B'].width = 55
        ws.column_dimensions['F'].width = 16
        out = os.path.join(output_dir, 'cfi_changes_report.xlsx')
        wb.save(out)
        return {'file': out, 'changes_count': len(rows),
                'note': '变化报告已生成，含开启CFI(绿)/关闭CFI(红)对照'}

    reg.add(
        'generate_changes_excel',
        '从 changes 表生成 CFI 变化对照 Excel（compare_changes 后调用）。'
        '每行一个 .so 的 CFI 状态变化，开启CFI(0→1)绿色、关闭CFI(1→0)红色。',
        {'type': 'object', 'properties': {'output_dir': {'type': 'string'}}, 'required': []},
        t_generate_changes_excel,
    )

    if extra_tools:
        for name, tool in extra_tools.items():
            reg.tools[name] = tool

    return reg
