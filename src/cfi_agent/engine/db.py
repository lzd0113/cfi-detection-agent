import os
import sqlite3


def generate_sqlite(summary, modules, name_table, output_dir):
    db_file = os.path.join(output_dir, 'cfi_detection.sqlite')
    if os.path.exists(db_file):
        os.remove(db_file)

    conn = sqlite3.connect(db_file)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=NORMAL')
    cursor = conn.cursor()

    cursor.executescript("""
    CREATE TABLE summary (
        total_so INTEGER, cfi_enabled_so INTEGER, cfi_not_enabled_so INTEGER,
        function_detail INTEGER, total_cfi_protected_funcs INTEGER,
        total_cfi_infra INTEGER, total_truly_unprotected INTEGER,
        total_other_funcs INTEGER, total_vcall_sites INTEGER,
        total_vcall_cfi INTEGER, total_vcall_no_cfi INTEGER,
        total_vcall_cfi_rate REAL, total_icall_sites INTEGER,
        total_icall_cfi INTEGER, total_icall_no_cfi INTEGER,
        total_icall_cfi_rate REAL,
        aarch64_so INTEGER, total_pac_sign_count INTEGER,
        total_pac_auth_count INTEGER, total_bti_count INTEGER,
        total_retaa_count INTEGER, total_retab_count INTEGER,
        total_pac_func_protected INTEGER, total_pac_func_sign_only INTEGER,
        total_pac_func_no_pac INTEGER, total_bti_func_with INTEGER,
        total_bti_func_without INTEGER
    );
    CREATE TABLE modules (
        module TEXT PRIMARY KEY, desc TEXT, total_so INTEGER,
        cfi_enabled_so INTEGER, cfi_not_enabled_so INTEGER,
        cfi_rate_percent REAL, cfi_protected_count INTEGER,
        cfi_infra_count INTEGER, truly_unprotected_count INTEGER,
        other_count INTEGER, vcall_site_count INTEGER,
        vcall_cfi_count INTEGER, vcall_no_cfi_count INTEGER,
        vcall_cfi_rate REAL, icall_site_count INTEGER,
        icall_cfi_count INTEGER, icall_no_cfi_count INTEGER,
        icall_cfi_rate REAL,
        pac_sign_count INTEGER, pac_auth_count INTEGER, bti_count INTEGER,
        retaa_count INTEGER, retab_count INTEGER,
        pac_func_protected INTEGER, pac_func_sign_only INTEGER,
        pac_func_no_pac INTEGER, bti_func_with INTEGER, bti_func_without INTEGER
    );
    CREATE TABLE so_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT, module TEXT, path TEXT,
        cfi_enabled INTEGER, cfi_protected_count INTEGER,
        cfi_infra_count INTEGER, truly_unprotected_count INTEGER,
        other_count INTEGER, vcall_site_count INTEGER,
        vcall_cfi_count INTEGER, vcall_no_cfi_count INTEGER,
        vcall_cfi_rate REAL, icall_site_count INTEGER,
        icall_cfi_count INTEGER, icall_no_cfi_count INTEGER,
        icall_cfi_rate REAL,
        pac_bti_available INTEGER, pac_property INTEGER, bti_property INTEGER,
        pac_sign_count INTEGER, pac_auth_count INTEGER, bti_count INTEGER,
        retaa_count INTEGER, retab_count INTEGER,
        pac_func_protected INTEGER, pac_func_sign_only INTEGER,
        pac_func_no_pac INTEGER, bti_func_with INTEGER, bti_func_without INTEGER,
        error TEXT
    );
    CREATE TABLE name_table (
        id INTEGER PRIMARY KEY, name TEXT
    );
    CREATE TABLE so_functions (
        so_id INTEGER, func_id INTEGER, func_type TEXT
    );
    CREATE INDEX idx_sf_so ON so_functions(so_id);
    CREATE INDEX idx_sf_type ON so_functions(func_type);
    CREATE INDEX idx_fid ON so_functions(func_id);
    """)

    q = lambda n: ','.join(['?'] * n)

    cursor.execute('INSERT INTO summary VALUES (' + q(27) + ')', (
        summary['total_so'], summary['cfi_enabled_so'], summary['cfi_not_enabled_so'],
        int(summary['function_detail']), summary['total_cfi_protected_funcs'],
        summary['total_cfi_infra'], summary['total_truly_unprotected'],
        summary['total_other_funcs'], summary['total_vcall_sites'],
        summary['total_vcall_cfi'], summary['total_vcall_no_cfi'],
        summary['total_vcall_cfi_rate'], summary['total_icall_sites'],
        summary['total_icall_cfi'], summary['total_icall_no_cfi'],
        summary['total_icall_cfi_rate'],
        summary.get('aarch64_so', 0), summary.get('total_pac_sign_count', 0),
        summary.get('total_pac_auth_count', 0), summary.get('total_bti_count', 0),
        summary.get('total_retaa_count', 0), summary.get('total_retab_count', 0),
        summary.get('total_pac_func_protected', 0), summary.get('total_pac_func_sign_only', 0),
        summary.get('total_pac_func_no_pac', 0), summary.get('total_bti_func_with', 0),
        summary.get('total_bti_func_without', 0)
    ))

    mod_rows = [(
        m['module'], m['desc'], m['total_so'], m['cfi_enabled_so'],
        m['cfi_not_enabled_so'], m['cfi_rate_percent'],
        m['cfi_protected_count'], m['cfi_infra_count'],
        m['truly_unprotected_count'], m['other_count'],
        m['vcall_site_count'], m['vcall_cfi_count'],
        m['vcall_no_cfi_count'], m['vcall_cfi_rate'],
        m['icall_site_count'], m['icall_cfi_count'],
        m['icall_no_cfi_count'], m['icall_cfi_rate'],
        m.get('pac_sign_count', 0), m.get('pac_auth_count', 0), m.get('bti_count', 0),
        m.get('retaa_count', 0), m.get('retab_count', 0),
        m.get('pac_func_protected', 0), m.get('pac_func_sign_only', 0),
        m.get('pac_func_no_pac', 0), m.get('bti_func_with', 0), m.get('bti_func_without', 0)
    ) for m in modules]
    cursor.executemany('INSERT INTO modules VALUES (' + q(28) + ')', mod_rows)

    cursor.executemany('INSERT INTO name_table (id, name) VALUES (?,?)',
                       [(i, n) for i, n in enumerate(name_table)])

    so_func_rows = []
    for m in modules:
        for so in m['so_files']:
            cursor.execute("INSERT INTO so_files "
                "(module, path, cfi_enabled, cfi_protected_count, cfi_infra_count, "
                "truly_unprotected_count, other_count, vcall_site_count, "
                "vcall_cfi_count, vcall_no_cfi_count, vcall_cfi_rate, "
                "icall_site_count, icall_cfi_count, icall_no_cfi_count, "
                "icall_cfi_rate, "
                "pac_bti_available, pac_property, bti_property, "
                "pac_sign_count, pac_auth_count, bti_count, "
                "retaa_count, retab_count, "
                "pac_func_protected, pac_func_sign_only, pac_func_no_pac, "
                "bti_func_with, bti_func_without, error) "
                "VALUES (" + q(29) + ")", (
                m['module'], so['path'], int(so.get('cfi_enabled', False)),
                so.get('cfi_protected_count', 0), so.get('cfi_infra_count', 0),
                so.get('truly_unprotected_count', 0), so.get('other_count', 0),
                so.get('vcall_site_count', 0), so.get('vcall_cfi_count', 0),
                so.get('vcall_no_cfi_count', 0), so.get('vcall_cfi_rate', 0),
                so.get('icall_site_count', 0), so.get('icall_cfi_count', 0),
                so.get('icall_no_cfi_count', 0), so.get('icall_cfi_rate', 0),
                int(so.get('pac_bti_available', False)),
                {-1: -1, None: -1, True: 1, False: 0}.get(so.get('pac_property'), -1),
                {-1: -1, None: -1, True: 1, False: 0}.get(so.get('bti_property'), -1),
                so.get('pac_sign_count', 0), so.get('pac_auth_count', 0),
                so.get('bti_count', 0), so.get('retaa_count', 0), so.get('retab_count', 0),
                so.get('pac_func_protected', 0), so.get('pac_func_sign_only', 0),
                so.get('pac_func_no_pac', 0), so.get('bti_func_with', 0),
                so.get('bti_func_without', 0), so.get('error', None)
            ))
            so_id = cursor.lastrowid
            for fk, label in [('cfi_protected', 'protected'), ('truly_unprotected', 'unprotected'), ('cfi_infra', 'infra'),
                              ('pac_protected_list', 'pac_protected'), ('pac_sign_only_list', 'pac_sign_only'),
                              ('pac_no_pac_list', 'pac_no_pac'), ('bti_with_list', 'bti_with'),
                              ('bti_without_list', 'bti_without')]:
                for fi in so.get(fk, []):
                    so_func_rows.append((so_id, fi, label))

    so_func_rows = list(set(so_func_rows))  # deduplicate (same func_id from alias symbols)
    cursor.executemany('INSERT INTO so_functions VALUES (?,?,?)', so_func_rows)

    conn.commit()
    cursor.execute('VACUUM')  # compact database, reclaim free pages
    conn.close()

    print(f"SQLite 数据库已保存: {db_file}")
    return db_file
