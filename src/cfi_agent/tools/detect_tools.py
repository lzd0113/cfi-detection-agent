import os

from ..engine.pipeline import run_full_pipeline
from ..engine.detection import ensure_pyelftools, run_so_level, run_dimension, extract_module
from ..engine.demangle import ensure_cxxfilt, build_module_data
from ..engine.report_utils import generate_reports
from ..engine.constants import MODULE_DESC
from .registry import _auto_output_dir, _make_timed_callbacks, _fmt_elapsed


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


def register_detect_tools(reg):
    def t_run_cfi_detection(lib_dir=None, mode='full', output_dir='', start_web=True):
        lib_dir = lib_dir or reg.defaults.get('lib_dir')
        if not lib_dir:
            return "错误：未提供 lib_dir，也无默认值"
        if not os.path.isdir(lib_dir):
            return f"错误：目录不存在 {lib_dir}"
        if mode not in ('full', 'fast'):
            mode = 'full'
        output_dir = _auto_output_dir('full', output_dir or reg.defaults.get('output_dir'))
        reg.last_output_dir = output_dir

        timed_log, timed_progress, finish_timer = _make_timed_callbacks(reg.on_log, reg.on_progress)
        summary, modules = run_full_pipeline(
            lib_dir, output_dir, mode=mode,
            progress=timed_progress,
            log=timed_log,
            start_web=bool(start_web),
        )
        elapsed = finish_timer()
        return {
            'status': '完成',
            'mode': mode,
            'output_dir': output_dir,
            '耗时': _fmt_elapsed(elapsed),
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
        reg.last_output_dir = output_dir
        base_output_dir = os.path.dirname(output_dir)
        ELFFile = ensure_pyelftools()
        timed_log, timed_progress, finish_timer = _make_timed_callbacks(reg.on_log, reg.on_progress)
        results, summary = run_so_level(lib_dir, ELFFile, progress=timed_progress, log=timed_log)
        full_summary, module_list = _build_so_level_full_data(results, summary)
        generate_reports(full_summary, module_list, [], output_dir,
                         include_calls=True, generate_pyw=False,
                         history_snapshot=False, history_type='so_level',
                         base_output_dir=base_output_dir,
                         start_web=start_web)
        elapsed = finish_timer()
        no_cfi = [r for r in results if not r['cfi_enabled']][:limit]
        return {'summary': summary, 'output_dir': output_dir, '耗时': _fmt_elapsed(elapsed), 'no_cfi_so_sample': no_cfi,
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
        reg.last_output_dir = output_dir
        base_output_dir = os.path.dirname(output_dir)
        ELFFile = ensure_pyelftools()
        cxxfilt = ensure_cxxfilt()
        timed_log, timed_progress, finish_timer = _make_timed_callbacks(reg.on_log, reg.on_progress)
        results, summary = run_dimension(lib_dir, ELFFile, 'functions',
                                         progress=timed_progress,
                                         log=timed_log)
        module_list, name_table = build_module_data(results, cxxfilt)
        generate_reports(summary, module_list, name_table, output_dir,
                         include_calls=False, generate_pyw=False,
                         history_snapshot=False, history_type='functions',
                         base_output_dir=base_output_dir,
                         start_web=start_web)
        summary['output_dir'] = output_dir
        elapsed = finish_timer()
        summary['耗时'] = _fmt_elapsed(elapsed)
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

    def _make_dim_tool(dim_name, dim_label_zh, dim_desc):
        def t_func(lib_dir=None, output_dir='', start_web=True):
            lib_dir = lib_dir or reg.defaults.get('lib_dir')
            if not lib_dir:
                return "错误：未提供 lib_dir"
            output_dir = _auto_output_dir(dim_name, output_dir or reg.defaults.get('output_dir'))
            reg.last_output_dir = output_dir
            base_output_dir = os.path.dirname(output_dir)
            ELFFile = ensure_pyelftools()
            cxxfilt = ensure_cxxfilt()
            timed_log, timed_progress, finish_timer = _make_timed_callbacks(reg.on_log, reg.on_progress)
            results, summary = run_dimension(lib_dir, ELFFile, dim_name,
                                             progress=timed_progress,
                                             log=timed_log)
            module_list, name_table = build_module_data(results, cxxfilt)
            generate_reports(summary, module_list, name_table, output_dir,
                             include_calls=(dim_name in ('vcall', 'icall')),
                             generate_pyw=True,
                             history_snapshot=False, history_type=dim_name,
                             base_output_dir=base_output_dir,
                             start_web=start_web)
            summary['output_dir'] = output_dir
            elapsed = finish_timer()
            summary['耗时'] = _fmt_elapsed(elapsed)
            return summary
        return t_func

    t_detect_vcall = _make_dim_tool('vcall', 'vcall', 'vcall 虚函数调用检测')
    t_detect_icall = _make_dim_tool('icall', 'icall', 'icall 间接调用检测')
    t_detect_pac = _make_dim_tool('pac', 'PAC', 'PAC 返回地址签名/认证检测')
    t_detect_bti = _make_dim_tool('bti', 'BTI', 'BTI 分支目标标识检测')

    reg.add('detect_vcall', 'vcall 检测：.so 级 + 函数级 + vcall（虚函数调用），不含 icall/PAC/BTI。返回 vcall 覆盖率。',
        {'type': 'object', 'properties': {'lib_dir': {'type': 'string'}, 'output_dir': {'type': 'string'}}, 'required': []}, t_detect_vcall)
    reg.add('detect_icall', 'icall 检测：.so 级 + 函数级 + icall（间接调用），不含 vcall/PAC/BTI。返回 icall 覆盖率。',
        {'type': 'object', 'properties': {'lib_dir': {'type': 'string'}, 'output_dir': {'type': 'string'}}, 'required': []}, t_detect_icall)
    reg.add('detect_pac', 'PAC 检测：.so 级 + 函数级 + PAC（返回地址签名/认证），不含 vcall/icall/BTI。返回 PAC 覆盖率。',
        {'type': 'object', 'properties': {'lib_dir': {'type': 'string'}, 'output_dir': {'type': 'string'}}, 'required': []}, t_detect_pac)
    reg.add('detect_bti', 'BTI 检测：.so 级 + 函数级 + BTI（分支目标标识），不含 vcall/icall/PAC。返回 BTI 覆盖率。',
        {'type': 'object', 'properties': {'lib_dir': {'type': 'string'}, 'output_dir': {'type': 'string'}}, 'required': []}, t_detect_bti)
