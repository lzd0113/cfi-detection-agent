import os

from .detection import ensure_pyelftools, run_detection
from .demangle import ensure_cxxfilt, build_module_data
from .report_utils import generate_reports


def run_full_pipeline(lib_dir, output_dir, mode='full', progress=None, log=None, start_web=True):
    function_detail = (mode == 'full')
    os.makedirs(output_dir, exist_ok=True)

    ELFFile = ensure_pyelftools()
    cxxfilt_module = ensure_cxxfilt() if function_detail else None

    results, summary = run_detection(lib_dir, ELFFile, function_detail, progress=progress, log=log)
    modules, name_table = build_module_data(results, cxxfilt_module)

    base_output_dir = os.path.dirname(output_dir) if os.path.basename(output_dir).startswith('full_') else output_dir
    generate_reports(summary, modules, name_table, output_dir,
                     include_calls=True, generate_pyw=True,
                     history_snapshot=False, history_type='full',
                     base_output_dir=base_output_dir, start_web=start_web, log=log)

    return summary, modules
