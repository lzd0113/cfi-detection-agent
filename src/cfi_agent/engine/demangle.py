import sys
import subprocess
from collections import defaultdict

from .constants import MODULE_DESC
from .detection import extract_module


def ensure_cxxfilt():
    try:
        subprocess.run(['c++filt', '--version'], capture_output=True, timeout=5)
        return 'c++filt'
    except Exception:
        pass
    try:
        import cxxfilt
        return cxxfilt
    except ImportError:
        pass
    try:
        print("cxxfilt 未安装且 c++filt 不可用，正在自动安装 cxxfilt...")
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'cxxfilt'], check=True)
        print("cxxfilt 安装完成")
        import cxxfilt
        return cxxfilt
    except Exception:
        print("警告: cxxfilt 安装失败，函数名将不会 demangle")
        return None


def demangle_batch(names, cxxfilt_module=None):
    if not names:
        return []
    if cxxfilt_module is not None:
        if isinstance(cxxfilt_module, str) and cxxfilt_module == 'c++filt':
            try:
                stripped = []
                suffix_map = {}
                for n in names:
                    if n.endswith('.cfi'):
                        base = n[:-4]
                        stripped.append(base)
                        suffix_map[base] = n
                    else:
                        stripped.append(n)
                        suffix_map[n] = n
                demangled_result = {}
                chunk_size = 50000
                for chunk_start in range(0, len(stripped), chunk_size):
                    chunk = stripped[chunk_start:chunk_start + chunk_size]
                    input_text = '\n'.join(chunk)
                    res = subprocess.run(
                        ['c++filt'],
                        input=input_text,
                        capture_output=True,
                        text=True,
                        timeout=300
                    )
                    out_lines = res.stdout.strip().split('\n') if res.stdout.strip() else []
                    for orig, dem in zip(chunk, out_lines):
                        demangled_result[orig] = dem
                final = []
                for orig in stripped:
                    full_name = suffix_map[orig]
                    dem = demangled_result.get(orig, orig)
                    if full_name.endswith('.cfi'):
                        final.append(dem + '.cfi')
                    else:
                        final.append(dem)
                return final
            except Exception:
                return names
        else:
            try:
                result = []
                for n in names:
                    try:
                        d = cxxfilt_module.demangle(n)
                        result.append(d)
                    except Exception:
                        result.append(n)
                return result
            except Exception:
                return names
    return names


def build_module_data(results, cxxfilt_module=None):
    modules = defaultdict(lambda: {
        'so_files': [],
        'cfi_enabled_so': 0,
        'cfi_not_enabled_so': 0,
        'cfi_protected_count': 0,
        'cfi_infra_count': 0,
        'truly_unprotected_count': 0,
        'other_count': 0,
        'vcall_site_count': 0,
        'vcall_cfi_count': 0,
        'vcall_no_cfi_count': 0,
        'icall_site_count': 0,
        'icall_cfi_count': 0,
        'icall_no_cfi_count': 0,
        'pac_sign_count': 0,
        'pac_auth_count': 0,
        'bti_count': 0,
        'retaa_count': 0,
        'retab_count': 0,
        'pac_func_protected': 0,
        'pac_func_sign_only': 0,
        'pac_func_no_pac': 0,
        'bti_func_with': 0,
        'bti_func_without': 0,
    })

    all_cfi_names = set()
    for r in results:
        # Collect CFI function names for ALL .so (including NO CFI — they have unprotected functions)
        if r.get('cfi_protected'):
            all_cfi_names.update(r['cfi_protected'])
        if r.get('truly_unprotected'):
            all_cfi_names.update(r['truly_unprotected'])
        if r.get('cfi_infra'):
            all_cfi_names.update(r['cfi_infra'])
        # Also collect PAC/BTI function names (for AArch64 .so, regardless of CFI status)
        if r.get('pac_bti_available'):
            for key in ['pac_protected_list', 'pac_sign_only_list', 'pac_no_pac_list',
                        'bti_with_list', 'bti_without_list']:
                if r.get(key):
                    all_cfi_names.update(r[key])

    demangled_map = {}
    if all_cfi_names:
        names_list = sorted(all_cfi_names)
        demangled = demangle_batch(names_list, cxxfilt_module)
        if demangled and len(demangled) == len(names_list):
            for orig, dem in zip(names_list, demangled):
                demangled_map[orig] = dem
        else:
            for n in names_list:
                demangled_map[n] = n

    name_table = []
    name_to_idx = {}

    def get_name_idx(name):
        dem = demangled_map.get(name, name)
        if dem not in name_to_idx:
            name_to_idx[dem] = len(name_table)
            name_table.append(dem)
        return name_to_idx[dem]

    for r in results:
        # Convert function name lists to indices for ALL .so (including NO CFI)
        if r.get('cfi_protected'):
            r['cfi_protected'] = [get_name_idx(n) for n in r['cfi_protected']]
        if r.get('truly_unprotected'):
            r['truly_unprotected'] = [get_name_idx(n) for n in r['truly_unprotected']]
        if r.get('cfi_infra'):
            r['cfi_infra'] = [get_name_idx(n) for n in r['cfi_infra']]
        # Convert PAC/BTI function name lists to indices
        if r.get('pac_bti_available'):
            for key in ['pac_protected_list', 'pac_sign_only_list', 'pac_no_pac_list',
                        'bti_with_list', 'bti_without_list']:
                if r.get(key):
                    r[key] = [get_name_idx(n) for n in r[key]]

    for r in results:
        path = r['path']
        module = extract_module(path)
        m = modules[module]

        m['so_files'].append(r)
        if r.get('cfi_enabled'):
            m['cfi_enabled_so'] += 1
            m['cfi_protected_count'] += r.get('cfi_protected_count', 0)
            m['cfi_infra_count'] += r.get('cfi_infra_count', 0)
            m['truly_unprotected_count'] += r.get('truly_unprotected_count', 0)
            m['other_count'] += r.get('other_count', 0)
            m['vcall_site_count'] += r.get('vcall_site_count', 0)
            m['vcall_cfi_count'] += r.get('vcall_cfi_count', 0)
            m['vcall_no_cfi_count'] += r.get('vcall_no_cfi_count', 0)
            m['icall_site_count'] += r.get('icall_site_count', 0)
            m['icall_cfi_count'] += r.get('icall_cfi_count', 0)
            m['icall_no_cfi_count'] += r.get('icall_no_cfi_count', 0)
        else:
            m['cfi_not_enabled_so'] += 1
            m['truly_unprotected_count'] += r.get('truly_unprotected_count', 0)
            m['other_count'] += r.get('other_count', 0)

        m['pac_sign_count'] += r.get('pac_sign_count', 0)
        m['pac_auth_count'] += r.get('pac_auth_count', 0)
        m['bti_count'] += r.get('bti_count', 0)
        m['retaa_count'] += r.get('retaa_count', 0)
        m['retab_count'] += r.get('retab_count', 0)
        m['pac_func_protected'] += r.get('pac_func_protected', 0)
        m['pac_func_sign_only'] += r.get('pac_func_sign_only', 0)
        m['pac_func_no_pac'] += r.get('pac_func_no_pac', 0)
        m['bti_func_with'] += r.get('bti_func_with', 0)
        m['bti_func_without'] += r.get('bti_func_without', 0)

    module_list = []
    for mod_name in sorted(modules.keys()):
        m = modules[mod_name]
        total_so = m['cfi_enabled_so'] + m['cfi_not_enabled_so']
        rate = round(m['cfi_enabled_so'] / total_so * 100, 1) if total_so > 0 else 0
        module_list.append({
            'module': mod_name,
            'desc': MODULE_DESC.get(mod_name, ''),
            'total_so': total_so,
            'cfi_enabled_so': m['cfi_enabled_so'],
            'cfi_not_enabled_so': m['cfi_not_enabled_so'],
            'cfi_rate_percent': rate,
            'cfi_protected_count': m['cfi_protected_count'],
            'cfi_infra_count': m['cfi_infra_count'],
            'truly_unprotected_count': m['truly_unprotected_count'],
            'other_count': m['other_count'],
            'vcall_site_count': m['vcall_site_count'],
            'vcall_cfi_count': m['vcall_cfi_count'],
            'vcall_no_cfi_count': m['vcall_no_cfi_count'],
            'vcall_cfi_rate': round(m['vcall_cfi_count'] / m['vcall_site_count'] * 100, 1) if m['vcall_site_count'] > 0 else 0,
            'icall_site_count': m['icall_site_count'],
            'icall_cfi_count': m['icall_cfi_count'],
            'icall_no_cfi_count': m['icall_no_cfi_count'],
            'icall_cfi_rate': round(m['icall_cfi_count'] / m['icall_site_count'] * 100, 1) if m['icall_site_count'] > 0 else 0,
            'pac_sign_count': m['pac_sign_count'],
            'pac_auth_count': m['pac_auth_count'],
            'bti_count': m['bti_count'],
            'retaa_count': m['retaa_count'],
            'retab_count': m['retab_count'],
            'pac_func_protected': m['pac_func_protected'],
            'pac_func_sign_only': m['pac_func_sign_only'],
            'pac_func_no_pac': m['pac_func_no_pac'],
            'bti_func_with': m['bti_func_with'],
            'bti_func_without': m['bti_func_without'],
            'so_files': m['so_files'],
        })

    return module_list, name_table
