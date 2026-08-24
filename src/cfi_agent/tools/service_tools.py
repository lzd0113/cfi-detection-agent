import os
import json
import sqlite3

from ..engine.html_report import generate_html
from ..engine.api_server import generate_app
from ..engine.service import start_service, stop_service
from ..engine.excel_report import ensure_openpyxl
from .registry import _connect


def register_service_tools(reg):
    def _out(output_dir):
        return output_dir or reg.last_output_dir or reg.defaults.get('output_dir')

    def t_regenerate_report(report_type, output_dir=''):
        output_dir = _out(output_dir)
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

    def t_start_service(output_dir=''):
        output_dir = _out(output_dir)
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

    def _history_dir(output_dir):
        d = _out(output_dir)
        base = os.path.dirname(d) if os.path.basename(d).startswith(('full_', 'so_level_', 'functions_', 'vcall_', 'icall_', 'pac_', 'bti_')) else d
        return os.path.join(base, 'history')

    def _read_meta(db_path):
        try:
            c = sqlite3.connect(db_path)
            row = c.execute('SELECT * FROM snapshot_meta').fetchone()
            if row:
                cols = [d[0] for d in c.execute('SELECT * FROM snapshot_meta').description]
                meta = dict(zip(cols, row))
            else:
                meta = {}
            sa = c.execute('SELECT total_so, cfi_enabled_so, cfi_not_enabled_so FROM summary').fetchone()
            meta['total_so'] = sa[0] if sa else 0
            meta['cfi_enabled_so'] = sa[1] if sa else 0
            c.close()
            return meta
        except Exception:
            return {}

    def t_list_history(output_dir=''):
        hdir = _history_dir(output_dir)
        if not os.path.isdir(hdir):
            return {'archives': [], 'note': '无历史存档。每次检测后自动存档到 output/history/'}
        files = sorted(f for f in os.listdir(hdir) if f.endswith('.sqlite'))
        archives = []
        for f in files:
            meta = _read_meta(os.path.join(hdir, f))
            archives.append({
                'file': f,
                'type': meta.get('detection_type', 'unknown'),
                'time': meta.get('detection_time', ''),
                'total_so': meta.get('total_so', 0),
                'cfi_enabled': meta.get('cfi_enabled_so', 0),
            })
        return {'archives': archives, 'count': len(archives)}

    reg.add(
        'list_history',
        '列出历史检测存档（所有检测类型统一存到 output/history/）。'
        '每个存档含检测类型、时间、.so 总数、CFI 开启数。用于选择对比基准。',
        {'type': 'object', 'properties': {'output_dir': {'type': 'string'}}, 'required': []},
        t_list_history,
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

    _HIGH_RISK_MODULES = {'security', 'account', 'tee', 'useriam'}
    _MED_RISK_MODULES = {'arkui', 'arkcompiler', 'communication', 'multimedia', 'distributeddatamgr', 'bundlemanager', 'graphic', 'hdf', 'startup', 'powermgr', 'notification', 'inputmethod'}
    _LOW_RISK_MODULES = {'thirdparty', 'xts', 'testfwk', 'build'}

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

        risks = []
        def add_risk(level, module, so_path, risk, recommendation):
            risks.append({'level': level, 'module': module, 'so': so_path, 'risk': risk, 'recommendation': recommendation})

        aarch = summary.get('aarch64_so', 0)
        cfi_rate = round(on / ts * 100, 1) if ts > 0 else 0
        if cfi_rate < 30:
            add_risk('高', '全局', '-', f'整体 CFI 覆盖率仅 {cfi_rate}%（{on}/{ts}），大量 .so 无前向 CFI 防护', '优先对安全敏感模块开启 CFI')

        pac_total = summary.get('total_pac_func_protected', 0) + summary.get('total_pac_func_sign_only', 0) + summary.get('total_pac_func_no_pac', 0)
        if aarch > 0 and pac_total > 0:
            pac_rate = round(summary.get('total_pac_func_protected', 0) / pac_total * 100, 1)
            sign_only = summary.get('total_pac_func_sign_only', 0)
            if pac_rate < 30:
                add_risk('高', '-', '-', f'PAC 覆盖率仅 {pac_rate}%（{aarch} 个 AArch64 .so），ROP 防护薄弱', '提高 PAC 编译覆盖率')
            if sign_only > 0 and sign_only / max(pac_total, 1) > 0.3:
                add_risk('中', '-', '-', f'PAC sign_only 比例 {round(sign_only/pac_total*100,1)}%（签名未验证），签名无效', '修复 sign_only 函数，确保签名后有认证')
            bti_total = summary.get('total_bti_func_with', 0) + summary.get('total_bti_func_without', 0)
            if bti_total > 0:
                bti_rate = round(summary.get('total_bti_func_with', 0) / bti_total * 100, 1)
                if bti_rate < 10:
                    add_risk('高', '-', '-', f'BTI 覆盖率仅 {bti_rate}%，JOP 防护薄弱', '提高 BTI 编译覆盖率')

        if vs > 1000 and summary.get('total_vcall_cfi_rate', 0) < 30:
            add_risk('中', '-', '-', f'vcall 调用点 {vs} 个，CFI 覆盖率仅 {summary.get("total_vcall_cfi_rate", 0)}%，虚表劫持风险', '提高虚函数调用 CFI 覆盖率')
        if ics > 100 and summary.get('total_icall_cfi_rate', 0) < 30:
            add_risk('中', '-', '-', f'icall 调用点 {ics} 个，CFI 覆盖率仅 {summary.get("total_icall_cfi_rate", 0)}%，间接调用劫持风险', '提高间接调用 CFI 覆盖率')

        so_rate = round(on / ts * 100, 1) if ts > 0 else 0
        if so_rate < 50:
            add_risk('中', '-', '-', f'.so CFI 覆盖率 {so_rate}%，超过半数 .so 无 CFI', '扩大 CFI 编译覆盖范围')

        high_risks = [r for r in risks if r['level'] == '高']
        med_risks = [r for r in risks if r['level'] == '中']
        risk_overall = '高风险' if high_risks else ('中风险' if med_risks else '低风险')

        return {'overall': '有异常需关注' if abnormal else '全部正常',
                'abnormal_count': len(abnormal), 'checks': checks,
                'risk_level': risk_overall,
                'risk_count': {'高': len(high_risks), '中': len(med_risks)},
                'risk_assessment': risks}

    reg.add(
        'reflect_check',
        '反思自检 + 风险评估：对检测结果做合理性校验，并基于安全知识库给出风险评估（高/中/低）。'
        '检查 .so 总数一致性、保护率范围、PAC/BTI 覆盖率、vcall/icall 保护率等。'
        '完整检测后调用此工具获取安全建议，向用户提示哪些模块需要优先修复。',
        {
            'type': 'object',
            'properties': {
                'summary': {'type': 'object', 'description': 'run_cfi_detection 返回的 summary 对象'},
            },
            'required': ['summary'],
        },
        t_reflect_check,
    )

    def t_compare_changes(version_a, output_dir='', version_b='latest'):
        hdir = _history_dir(output_dir)
        cur_dir = _out(output_dir)
        main_db = os.path.join(cur_dir, 'cfi_detection.sqlite')
        if version_b == 'latest':
            db_b, label_b = main_db, 'latest(当前)'
        else:
            db_b, label_b = os.path.join(hdir, version_b), version_b
        db_a, label_a = os.path.join(hdir, version_a), version_a
        if not os.path.exists(db_a):
            return {'error': f'存档 {version_a} 不存在，用 list_history 查看'}
        if not os.path.exists(db_b):
            return {'error': '目标库不存在，请先检测'}
        meta_a = _read_meta(db_a)
        meta_b = _read_meta(db_b)
        ca = sqlite3.connect(db_a); ca.row_factory = sqlite3.Row
        cb = sqlite3.connect(db_b); cb.row_factory = sqlite3.Row
        a_rows = {r['path']: r['cfi_enabled'] for r in ca.execute('SELECT path, cfi_enabled FROM so_files')}
        b_rows = {r['path']: r['cfi_enabled'] for r in cb.execute('SELECT path, cfi_enabled FROM so_files')}
        enabled_now = [p for p, v in b_rows.items() if a_rows.get(p) == 0 and v == 1]
        disabled_now = [p for p, v in b_rows.items() if a_rows.get(p) == 1 and v == 0]
        added_so = [p for p in b_rows if p not in a_rows]
        removed_so = [p for p in a_rows if p not in b_rows]
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
        for p in added_so:
            conn.execute('INSERT INTO changes (path,field,old_value,new_value,version_a,version_b) VALUES (?,?,?,?,?,?)', (p, 'so_added', '-', '+', label_a, label_b))
        for p in removed_so:
            conn.execute('INSERT INTO changes (path,field,old_value,new_value,version_a,version_b) VALUES (?,?,?,?,?,?)', (p, 'so_removed', '+', '-', label_a, label_b))
        conn.commit(); conn.close()
        dim_a = {'functions': meta_a.get('has_functions',0), 'vcall': meta_a.get('has_vcall',0),
                 'icall': meta_a.get('has_icall',0), 'pac': meta_a.get('has_pac',0), 'bti': meta_a.get('has_bti',0)}
        dim_b = {'functions': meta_b.get('has_functions',0), 'vcall': meta_b.get('has_vcall',0),
                 'icall': meta_b.get('has_icall',0), 'pac': meta_b.get('has_pac',0), 'bti': meta_b.get('has_bti',0)}
        comparable = [d for d in dim_a if dim_a[d] and dim_b.get(d)]
        skipped = [d for d in dim_a if not dim_a[d] and dim_b.get(d)]
        return {
            'version_a': f'{label_a} ({meta_a.get("detection_type","unknown")})',
            'version_b': f'{label_b} ({meta_b.get("detection_type","unknown")})',
            'newly_enabled_cfi': enabled_now[:80], 'newly_enabled_count': len(enabled_now),
            'newly_disabled_cfi': disabled_now[:80], 'newly_disabled_count': len(disabled_now),
            'added_so': added_so[:80], 'added_so_count': len(added_so),
            'removed_so': removed_so[:80], 'removed_so_count': len(removed_so),
            'comparable_dimensions': comparable,
            'skipped_dimensions': [f'{d} (快照A无此数据)' for d in skipped],
            'summary_delta': {k: (sa.get(k), sb.get(k)) for k in ['total_so', 'cfi_enabled_so', 'cfi_not_enabled_so', 'total_cfi_protected_funcs', 'total_truly_unprotected', 'total_vcall_cfi_rate', 'total_icall_cfi_rate']},
            'note': f'共 {len(enabled_now)+len(disabled_now)+len(added_so)+len(removed_so)} 项变化，已存入 changes 表。用 generate_changes_excel 生成变化报告。',
        }

    reg.add(
        'compare_changes',
        '对比两次检测的变化（支持跨检测类型对比，自动取两快照都有的维度）。'
        'version_a 是历史存档文件名（用 list_history 查看），version_b 默认 latest(当前)。'
        '可比维度由两快照的 snapshot_meta 自动决定——so_level 对 full 只比 .so CFI 状态，full 对 full 比全部。',
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
        cur_dir = _out(output_dir)
        main_db = os.path.join(cur_dir, 'cfi_detection.sqlite')
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
        headers = ['序号', '.so路径', '变化类型', '旧值', '新值', '说明', '版本A', '版本B']
        for col, h in enumerate(headers, 1):
            c = ws.cell(1, col, h)
            c.font = Font(bold=True, color='FFFFFF')
            c.fill = PatternFill(start_color='2563EB', end_color='2563EB', fill_type='solid')
            c.alignment = Alignment(horizontal='center')
        green = PatternFill(start_color='D1FAE5', end_color='D1FAE5', fill_type='solid')
        red = PatternFill(start_color='FEE2E2', end_color='FEE2E2', fill_type='solid')
        blue = PatternFill(start_color='DBEAFE', end_color='DBEAFE', fill_type='solid')
        thin = Border(left=Side(style='thin', color='CBD5E1'), right=Side(style='thin', color='CBD5E1'), top=Side(style='thin', color='CBD5E1'), bottom=Side(style='thin', color='CBD5E1'))
        for i, r in enumerate(rows, 2):
            old, new = r['old_value'], r['new_value']
            field = r['field']
            if field == 'cfi_enabled' and old == 0 and new == 1:
                change, fill = '开启CFI(0→1)', green
            elif field == 'cfi_enabled' and old == 1 and new == 0:
                change, fill = '关闭CFI(1→0)', red
            elif field == 'so_added':
                change, fill = '新增.so', blue
            elif field == 'so_removed':
                change, fill = '移除.so', red
            else:
                change, fill = f'{old}→{new}', blue
            vals = [i - 1, r['path'], field, old, new, change, r['version_a'], r['version_b']]
            for col, v in enumerate(vals, 1):
                cell = ws.cell(i, col, v)
                cell.border = thin
                if col == 6:
                    cell.fill = fill
        ws.column_dimensions['B'].width = 55
        ws.column_dimensions['F'].width = 16
        out = os.path.join(cur_dir, 'cfi_changes_report.xlsx')
        wb.save(out)
        return {'file': out, 'changes_count': len(rows),
                'note': '变化报告已生成：开启CFI(绿)/关闭CFI(红)/新增.so(蓝)/移除.so(红)'}

    reg.add(
        'generate_changes_excel',
        '从 changes 表生成 CFI 变化对照 Excel（compare_changes 后调用）。'
        '支持开启CFI(绿)/关闭CFI(红)/新增.so(蓝)/移除.so(红)四种变化类型。',
        {'type': 'object', 'properties': {'output_dir': {'type': 'string'}}, 'required': []},
        t_generate_changes_excel,
    )
