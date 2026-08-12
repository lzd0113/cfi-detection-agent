import os
import json
import sqlite3

from .registry import _connect, _truncate


def register_query_tools(reg):
    def _out(output_dir):
        return output_dir or reg.last_output_dir or reg.defaults.get('output_dir')

    def t_query_summary(output_dir=''):
        output_dir = _out(output_dir)
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
        output_dir = _out(output_dir)
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
        output_dir = _out(output_dir)
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
        output_dir = _out(output_dir)
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
        output_dir = _out(output_dir)
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

    def t_query_sql(sql, output_dir='', limit=200):
        output_dir = _out(output_dir)
        stmt = sql.strip()
        if not stmt.lower().startswith('select'):
            return {'error': '仅允许 SELECT 查询'}
        if ';' in stmt.rstrip(';'):
            return {'error': '仅允许单条语句'}
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
