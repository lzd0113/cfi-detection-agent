import os
import sys
import struct
import subprocess
import bisect
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed


def ensure_pyelftools():
    try:
        from elftools.elf.elffile import ELFFile
        return ELFFile
    except ImportError:
        print("pyelftools 未安装，正在自动安装...")
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'pyelftools'], check=True)
        print("pyelftools 安装完成")
        from elftools.elf.elffile import ELFFile
        return ELFFile


def decode_thumb_bl_blx(data, offset, base_addr):
    if offset + 4 > len(data):
        return None
    hw1 = data[offset] | (data[offset + 1] << 8)
    hw2 = data[offset + 2] | (data[offset + 3] << 8)
    if (hw1 & 0xF800) != 0xF000:
        return None
    if (hw2 & 0xC000) != 0xC000:
        return None
    S = (hw1 >> 10) & 1
    imm10 = hw1 & 0x3FF
    imm11 = hw2 & 0x7FF
    J1 = (hw2 >> 13) & 1
    J2 = (hw2 >> 11) & 1
    I1 = (~(J1 ^ S)) & 1
    I2 = (~(J2 ^ S)) & 1
    val = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1)
    if S:
        val = (val | 0xFE000000) & 0xFFFFFFFF
    target = (base_addr + offset + 4 + val) & 0xFFFFFFFF
    return target


def _read_u32_le(data, offset):
    if offset + 4 > len(data):
        return None
    return data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24)


def _has_cfi_near(slowpath_calls, site_addr, window=48):
    """Check if any address in sorted slowpath_calls is within `window` bytes of site_addr. O(log n) via bisect."""
    if not slowpath_calls:
        return False
    pos = bisect.bisect_left(slowpath_calls, site_addr)
    if pos < len(slowpath_calls) and slowpath_calls[pos] - site_addr < window:
        return True
    if pos > 0 and site_addr - slowpath_calls[pos - 1] < window:
        return True
    return False


def decode_aarch64_bl(data, offset, base_addr):
    instr = _read_u32_le(data, offset)
    if instr is None:
        return None
    if (instr & 0xFC000000) != 0x94000000:
        return None
    imm26 = instr & 0x03FFFFFF
    if imm26 & 0x02000000:
        imm26 -= 0x04000000
    return base_addr + offset + (imm26 << 2)


def is_aarch64_blr(instr):
    if (instr & 0xFFFFFC1F) == 0xD63F0000:
        return (instr >> 5) & 0x1F
    return None


def is_aarch64_ldr_mem(instr):
    if (instr & 0xFFC00000) in (0xF9400000, 0xB9400000):
        return (instr & 0x1F, (instr >> 5) & 0x1F)
    if (instr & 0xFFE00C00) in (0xF8600800, 0xB8600800, 0xF8400C00, 0xB8400C00, 0xF8400400, 0xB8400400):
        return (instr & 0x1F, (instr >> 5) & 0x1F)
    return None


def find_slowpath_plt(elf):
    from elftools.elf.relocation import RelocationSection
    for sec in elf.iter_sections():
        if isinstance(sec, RelocationSection) and sec.name in ('.rel.plt', '.rela.plt'):
            sym_link = elf.get_section(sec['sh_link'])
            for i, rel in enumerate(sec.iter_relocations()):
                sym_idx = rel['r_info_sym']
                if sym_idx < sym_link.num_symbols():
                    sym = sym_link.get_symbol(sym_idx)
                    if sym.name == '__cfi_slowpath':
                        plt_sec = elf.get_section_by_name('.plt')
                        if plt_sec:
                            return plt_sec['sh_addr'] + 32 + i * 16
    return None


# ============================================================
# Precise vcall/icall classification (basic-block + register trace)
# ============================================================

def _is_bb_boundary(instr):
    """Check if AArch64 instruction ends a basic block."""
    if (instr & 0xFC000000) == 0x14000000:  # B
        return True
    if (instr & 0xFC000000) == 0x94000000:  # BL
        return True
    if (instr & 0xFF000010) == 0x54000000:  # B.cond
        return True
    if (instr & 0x7F000000) in (0x34000000, 0x35000000, 0x36000000, 0x37000000):  # CBZ/CBNZ/TBZ/TBNZ
        return True
    if (instr & 0xFFFFFC1F) in (0xD65F0000, 0xD61F0000, 0xD63F0000):  # RET/BR/BLR
        return True
    return False


def _is_mov_reg(instr):
    """MOV Xd, Xm (= ORR Xd, XZR, Xm, 64-bit). Returns (rd, rm) or None."""
    if (instr & 0xFFE0FFE0) == 0xAA0003E0:
        return instr & 0x1F, (instr >> 16) & 0x1F
    return None


def _is_ldr_with_base(instr):
    """LDR Xt, [Xn, ...]. Returns (rt, rn) or None."""
    if (instr & 0xFFC00000) in (0xF9400000, 0xB9400000):
        return instr & 0x1F, (instr >> 5) & 0x1F
    if (instr & 0xFFE00C00) in (0xF8600800, 0xB8600800, 0xF8400C00, 0xB8400C00, 0xF8400400, 0xB8400400):
        return instr & 0x1F, (instr >> 5) & 0x1F
    return None


def _classify_blr_vcall(data, blr_offset, rn, max_lookback=32):
    """Trace BLR's register backwards within basic block to determine vcall vs icall.

    Returns: True=vcall, False=icall, None=unknown.
    """
    current_reg = rn
    for step in range(1, max_lookback + 1):
        i = blr_offset - step * 4
        if i < 0 or i + 4 > len(data):
            break
        instr = _read_u32_le(data, i)
        if instr is None:
            break

        if _is_bb_boundary(instr):
            break

        mov = _is_mov_reg(instr)
        if mov is not None:
            rd, rm = mov
            if rd == current_reg:
                current_reg = rm
                continue

        ldr = _is_ldr_with_base(instr)
        if ldr is not None:
            rt, rn_ldr = ldr
            if rt == current_reg:
                if rn_ldr == 0:  # LDR from [X0] — this pointer → vcall
                    return True
                elif rn_ldr == 31:  # LDR from [SP] — stack → icall
                    return False
                elif 19 <= rn_ldr <= 28:  # callee-saved reg → likely holds this/vtable → vcall
                    return True
                else:
                    current_reg = rn_ldr  # trace the base register further
                    continue
    return None


def check_cfi_enabled(elf):
    for sec_name in ['.dynsym', '.symtab']:
        sec = elf.get_section_by_name(sec_name)
        if sec:
            for sym in sec.iter_symbols():
                if sym.name == '__cfi_check' and sym['st_value'] != 0:
                    return True
    return False


def classify_functions(elf):
    cfi_protected_set = set()
    cfi_infra_set = set()
    other_funcs_set = set()
    symtab = elf.get_section_by_name('.symtab')
    if symtab:
        for sym in symtab.iter_symbols():
            if sym['st_info']['type'] != 'STT_FUNC':
                continue
            if sym['st_value'] == 0:
                continue  # skip external symbols (defined in other .so, not in this one)
            name = sym.name
            if not name:
                continue
            if name.endswith('.cfi') and not name.startswith('.L.'):
                cfi_protected_set.add(name[:-4])
            elif name.startswith('__cfi') or name.startswith('.L.cfi'):
                cfi_infra_set.add(name)
            else:
                other_funcs_set.add(name)
    cfi_protected = sorted(cfi_protected_set)
    truly_unprotected = sorted(other_funcs_set - cfi_protected_set)
    cfi_infra = sorted(cfi_infra_set)
    return {
        'cfi_protected': cfi_protected,
        'cfi_protected_count': len(cfi_protected),
        'cfi_infra': cfi_infra,
        'cfi_infra_count': len(cfi_infra),
        'truly_unprotected': truly_unprotected,
        'truly_unprotected_count': len(truly_unprotected),
        'other_count': len(other_funcs_set),
    }


def scan_call_sites(elf, dimension=None):
    """Scan for indirect call sites. dimension='vcall' or 'icall' to only compute one."""
    machine = elf.get_machine_arch()
    if machine == 'AArch64':
        return scan_call_sites_aarch64(elf, dimension)
    slowpath_plt = find_slowpath_plt(elf)
    text_sec = elf.get_section_by_name('.text')
    vcall_cfi_count = vcall_site_count = vcall_no_cfi_count = 0
    icall_cfi_count = icall_site_count = icall_no_cfi_count = 0

    if slowpath_plt and text_sec:
        text_data = text_sec.data()
        text_base = text_sec['sh_addr']

        slowpath_calls = []
        for i in range(0, len(text_data) - 4, 2):
            target = decode_thumb_bl_blx(text_data, i, text_base)
            if target is not None and target == slowpath_plt:
                slowpath_calls.append(text_base + i)

        for i in range(0, len(text_data) - 2, 2):
            hw = text_data[i] | (text_data[i + 1] << 8)
            if (hw & 0xFF87) not in (0x4700, 0x4780):
                continue
            reg = (hw >> 3) & 0xF
            is_vcall = False
            for j in range(max(0, i - 20), i, 2):
                prev_hw = text_data[j] | (text_data[j + 1] << 8)
                if (prev_hw & 0xF800) == 0x6800:
                    rt = prev_hw & 7
                    if rt == reg:
                        is_vcall = True
                        break
            site_addr = text_base + i
            has_cfi = _has_cfi_near(slowpath_calls, site_addr)
            if is_vcall and dimension != 'icall':
                vcall_site_count += 1
                if has_cfi:
                    vcall_cfi_count += 1
                else:
                    vcall_no_cfi_count += 1
            elif not is_vcall and dimension != 'vcall':
                icall_site_count += 1
                if has_cfi:
                    icall_cfi_count += 1
                else:
                    icall_no_cfi_count += 1

    return {
        'vcall_site_count': vcall_site_count,
        'vcall_cfi_count': vcall_cfi_count,
        'vcall_no_cfi_count': vcall_no_cfi_count,
        'vcall_cfi_rate': round(vcall_cfi_count / vcall_site_count * 100, 1) if vcall_site_count > 0 else 0,
        'icall_site_count': icall_site_count,
        'icall_cfi_count': icall_cfi_count,
        'icall_no_cfi_count': icall_no_cfi_count,
        'icall_cfi_rate': round(icall_cfi_count / icall_site_count * 100, 1) if icall_site_count > 0 else 0,
    }


def scan_call_sites_aarch64(elf, dimension=None):
    """Scan AArch64 .text for BLR indirect calls. dimension='vcall' or 'icall' to only compute one."""
    slowpath_plt = find_slowpath_plt(elf)
    text_sec = elf.get_section_by_name('.text')
    vcall_cfi_count = vcall_site_count = vcall_no_cfi_count = 0
    icall_cfi_count = icall_site_count = icall_no_cfi_count = 0

    if text_sec:
        text_data = text_sec.data()
        text_base = text_sec['sh_addr']

        slowpath_calls = []
        if slowpath_plt:
            for i in range(0, len(text_data) - 3, 4):
                target = decode_aarch64_bl(text_data, i, text_base)
                if target is not None and target == slowpath_plt:
                    slowpath_calls.append(text_base + i)

        for i in range(0, len(text_data) - 3, 4):
            instr = _read_u32_le(text_data, i)
            if instr is None:
                continue
            rn = is_aarch64_blr(instr)
            if rn is None:
                continue
            result = _classify_blr_vcall(text_data, i, rn)
            if result is True:
                is_vcall = True
            elif result is False:
                is_vcall = False
            else:
                is_vcall = False
                for j in range(max(0, i - 20), i, 4):
                    prev_instr = _read_u32_le(text_data, j)
                    if prev_instr is None:
                        continue
                    ldr = is_aarch64_ldr_mem(prev_instr)
                    if ldr is not None:
                        rt, _ = ldr
                        if rt == rn:
                            is_vcall = True
                            break
            site_addr = text_base + i
            has_cfi = _has_cfi_near(slowpath_calls, site_addr)
            if is_vcall and dimension != 'icall':
                vcall_site_count += 1
                if has_cfi:
                    vcall_cfi_count += 1
                else:
                    vcall_no_cfi_count += 1
            elif not is_vcall and dimension != 'vcall':
                icall_site_count += 1
                if has_cfi:
                    icall_cfi_count += 1
                else:
                    icall_no_cfi_count += 1

    return {
        'vcall_site_count': vcall_site_count,
        'vcall_cfi_count': vcall_cfi_count,
        'vcall_no_cfi_count': vcall_no_cfi_count,
        'vcall_cfi_rate': round(vcall_cfi_count / vcall_site_count * 100, 1) if vcall_site_count > 0 else 0,
        'icall_site_count': icall_site_count,
        'icall_cfi_count': icall_cfi_count,
        'icall_no_cfi_count': icall_no_cfi_count,
        'icall_cfi_rate': round(icall_cfi_count / icall_site_count * 100, 1) if icall_site_count > 0 else 0,
    }


# ============================================================
# PAC / BTI detection (AArch64 only)
# ============================================================

_HINT_MASK = 0xFFFFF01F
_HINT_BASE = 0xD503201F
_PAC_SIGN_HINTS = {25, 26, 27}
_PAC_AUTH_HINTS = {28, 29, 30, 31}
_PAC_HINT_NAMES = {
    25: "PACIASP", 26: "PACIZB", 27: "PACIBSP",
    28: "AUTIZA", 29: "AUTIASP", 30: "AUTIZB", 31: "AUTIBSP",
}
_BTI_HINT_RANGE = {32, 34, 36, 38}
_BTI_HINT_NAMES = {32: "BTI", 34: "BTI c", 36: "BTI j", 38: "BTI jc"}
_RETAA_WORD = 0xD65F0BFF
_RETAB_WORD = 0xD65F0FFF
_NT_GNU_PROPERTY_TYPE_0 = 5
_GNU_PROPERTY_AARCH64_FEATURE_1_AND = 0xC0000000
_FEAT_BTI = 0x1
_FEAT_PAC = 0x2
_SHF_EXECINSTR = 0x4
_SHT_PROGBITS = 1


def _check_pac_bti_property(elf):
    """Parse .note.gnu.property for PAC/BTI feature flags."""
    sec = elf.get_section_by_name('.note.gnu.property')
    if not sec:
        return None, None
    data = sec.data()
    align = sec['sh_addralign'] or 8
    if align < 2:
        align = 8
    has_pac = None
    has_bti = None
    pos = 0
    while pos + 12 <= len(data):
        namesz, descsz, ntype = struct.unpack_from('<III', data, pos)
        pos += 12
        name = data[pos:pos + namesz].rstrip(b'\x00')
        pos += namesz
        pos = (pos + align - 1) // align * align
        desc = data[pos:pos + descsz]
        pos += descsz
        pos = (pos + align - 1) // align * align
        if ntype == _NT_GNU_PROPERTY_TYPE_0 and name == b'GNU':
            dpos = 0
            while dpos + 8 <= len(desc):
                pr_type, pr_ds = struct.unpack_from('<II', desc, dpos)
                dpos += 8
                pr_data = desc[dpos:dpos + pr_ds]
                dpos += (pr_ds + 7) & ~7
                if pr_type == _GNU_PROPERTY_AARCH64_FEATURE_1_AND and pr_ds >= 4:
                    feat = struct.unpack_from('<I', pr_data, 0)[0]
                    has_pac = bool(feat & _FEAT_PAC)
                    has_bti = bool(feat & _FEAT_BTI)
    return has_pac, has_bti


def _scan_pac_bti_bytes(elf):
    """Byte-scan executable sections for PAC/BTI/RETAA/RETAB instructions."""
    pac_sign = 0
    pac_auth = 0
    bti = 0
    retaa = 0
    retab = 0
    for sec in elf.iter_sections():
        if not (sec['sh_flags'] & _SHF_EXECINSTR) or sec['sh_size'] == 0:
            continue
        data = sec.data()
        for i in range(0, len(data) - 3, 4):
            word = struct.unpack_from('<I', data, i)[0]
            if (word & _HINT_MASK) == _HINT_BASE:
                imm7 = (word >> 5) & 0x7F
                if imm7 in _PAC_SIGN_HINTS:
                    pac_sign += 1
                elif imm7 in _PAC_AUTH_HINTS:
                    pac_auth += 1
                elif imm7 in _BTI_HINT_RANGE:
                    bti += 1
            if word == _RETAA_WORD:
                retaa += 1
                pac_auth += 1  # RETAA is also a PAC authentication
            elif word == _RETAB_WORD:
                retab += 1
                pac_auth += 1  # RETAB is also a PAC authentication
    return {
        'pac_sign_count': pac_sign,
        'pac_auth_count': pac_auth,
        'bti_count': bti,
        'retaa_count': retaa,
        'retab_count': retab,
    }


def _scan_pac_bti_functions(elf):
    """Function-level PAC/BTI coverage via .symtab. Optimized: pre-read section data once."""
    symtab = elf.get_section_by_name('.symtab')
    if not symtab:
        return {'pac_func_total': 0, 'pac_func_protected': 0, 'pac_func_sign_only': 0,
                'pac_func_no_pac': 0, 'bti_func_total': 0, 'bti_func_with': 0, 'bti_func_without': 0}

    # Deduplicate by st_value (address) — different names at same address = same function
    # Skip .cfi suffix: foo.cfi and foo are the same logical function
    seen_names = set()
    func_syms = []
    for s in symtab.iter_symbols():
        if s['st_info']['type'] != 'STT_FUNC' or s['st_value'] == 0 or not s.name:
            continue
        if s.name.endswith('.cfi'):
            continue  # foo.cfi is the CFI instrumented version of foo, not a separate function
        if s.name not in seen_names:
            seen_names.add(s.name)
            func_syms.append(s)

    total = len(func_syms)
    if total == 0:
        return {'pac_func_total': 0, 'pac_func_protected': 0, 'pac_func_sign_only': 0,
                'pac_func_no_pac': 0, 'bti_func_total': 0, 'bti_func_with': 0, 'bti_func_without': 0,
                'pac_protected_list': [], 'pac_sign_only_list': [], 'pac_no_pac_list': [],
                'bti_with_list': [], 'bti_without_list': []}

    # Pre-read executable section data ONCE (key optimization: avoids re-reading per function)
    exec_secs = []
    for sec in elf.iter_sections():
        if (sec['sh_flags'] & _SHF_EXECINSTR) and sec['sh_size'] > 0:
            exec_secs.append((sec['sh_addr'], sec['sh_size'], sec.data()))

    pac_protected = 0
    pac_sign_only = 0
    pac_no_pac = 0
    bti_with = 0
    bti_without = 0
    pac_protected_list = []
    pac_sign_only_list = []
    pac_no_pac_list = []
    bti_with_list = []
    bti_without_list = []

    for sym in func_syms:
        addr = sym['st_value']
        size = sym['st_size']
        name = sym.name

        # Find section by address (only check executable sections, typically 2-4)
        sec_base = None
        sec_data = None
        for base, sec_size, data in exec_secs:
            if base <= addr < base + sec_size:
                sec_base = base
                sec_data = data
                break

        if sec_data is None:
            pac_no_pac += 1
            bti_without += 1
            pac_no_pac_list.append(name)
            bti_without_list.append(name)
            continue

        offset = addr - sec_base

        # BTI check: first instruction at function entry
        has_bti = False
        if offset + 4 <= len(sec_data):
            word = struct.unpack_from('<I', sec_data, offset)[0]
            if (word & _HINT_MASK) == _HINT_BASE:
                imm7 = (word >> 5) & 0x7F
                if imm7 in _BTI_HINT_RANGE:
                    has_bti = True

        if has_bti:
            bti_with += 1
            bti_with_list.append(name)
        else:
            bti_without += 1
            bti_without_list.append(name)

        # PAC check: scan function range for sign + auth
        has_sign = False
        has_auth = False
        if size > 0:
            end = min(offset + size, len(sec_data))
            for i in range(offset, end - 3, 4):
                word = struct.unpack_from('<I', sec_data, i)[0]
                if (word & _HINT_MASK) == _HINT_BASE:
                    imm7 = (word >> 5) & 0x7F
                    if imm7 in _PAC_SIGN_HINTS:
                        has_sign = True
                    elif imm7 in _PAC_AUTH_HINTS:
                        has_auth = True
                if word == _RETAA_WORD or word == _RETAB_WORD:
                    has_auth = True
        else:
            if offset + 4 <= len(sec_data):
                word = struct.unpack_from('<I', sec_data, offset)[0]
                if (word & _HINT_MASK) == _HINT_BASE:
                    imm7 = (word >> 5) & 0x7F
                    if imm7 in _PAC_SIGN_HINTS:
                        has_sign = True

        if has_sign and has_auth:
            pac_protected += 1
            pac_protected_list.append(name)
        elif has_sign:
            pac_sign_only += 1
            pac_sign_only_list.append(name)
        else:
            pac_no_pac += 1
            pac_no_pac_list.append(name)

    return {
        'pac_func_total': total,
        'pac_func_protected': pac_protected,
        'pac_func_sign_only': pac_sign_only,
        'pac_func_no_pac': pac_no_pac,
        'bti_func_total': total,
        'bti_func_with': bti_with,
        'bti_func_without': bti_without,
        'pac_protected_list': pac_protected_list,
        'pac_sign_only_list': pac_sign_only_list,
        'pac_no_pac_list': pac_no_pac_list,
        'bti_with_list': bti_with_list,
        'bti_without_list': bti_without_list,
    }


def analyze_pac_bti(elf, dimension=None):
    """PAC/BTI analysis for AArch64 .so. dimension='pac' or 'bti' to only compute one."""
    pac_prop, bti_prop = _check_pac_bti_property(elf)
    byte_data = _scan_pac_bti_bytes(elf)
    func_data = _scan_pac_bti_functions(elf)
    result = {
        'pac_bti_available': True,
        'pac_property': pac_prop,
        'bti_property': bti_prop,
        **byte_data,
        **func_data,
        'pac_sign_count': func_data['pac_func_protected'] + func_data['pac_func_sign_only'],
        'pac_auth_count': func_data['pac_func_protected'],
    }
    # Zero out non-requested dimension
    if dimension == 'pac':
        for k in ['bti_count', 'bti_func_with', 'bti_func_without', 'bti_func_total',
                  'bti_with_list', 'bti_without_list', 'retaa_count', 'retab_count']:
            result[k] = 0 if not isinstance(result.get(k), list) else []
        result['bti_property'] = None
    elif dimension == 'bti':
        for k in ['pac_sign_count', 'pac_auth_count', 'pac_func_protected', 'pac_func_sign_only',
                  'pac_func_no_pac', 'pac_func_total', 'pac_property',
                  'pac_protected_list', 'pac_sign_only_list', 'pac_no_pac_list']:
            result[k] = 0 if not isinstance(result.get(k), list) else []
        result['pac_property'] = None
    return result


def _log(log, msg):
    if log:
        log(msg)
    else:
        print(msg)


def _iter_so(lib_dir):
    return sorted(Path(lib_dir).rglob('*.so'))


def _rel(so_file, lib_dir):
    return str(so_file.relative_to(lib_dir)).replace(os.sep, '/')


def extract_module(rel_path):
    """Extract module name from relative path, skipping wrapper directories like lib.unstripped."""
    parts = rel_path.split('/')
    while parts and (parts[0].startswith('lib.unstripped') or parts[0] == 'lib'):
        parts = parts[1:]
    return parts[0] if parts else ''


_DIM_ZERO_KEYS = {
    'icall': ['vcall_site_count', 'vcall_cfi_count', 'vcall_no_cfi_count', 'vcall_cfi_rate'],
    'vcall': ['icall_site_count', 'icall_cfi_count', 'icall_no_cfi_count', 'icall_cfi_rate'],
    'pac': ['vcall_site_count', 'vcall_cfi_count', 'vcall_no_cfi_count', 'vcall_cfi_rate',
            'icall_site_count', 'icall_cfi_count', 'icall_no_cfi_count', 'icall_cfi_rate',
            'bti_count', 'bti_func_with', 'bti_func_without', 'bti_func_total'],
    'bti': ['vcall_site_count', 'vcall_cfi_count', 'vcall_no_cfi_count', 'vcall_cfi_rate',
            'icall_site_count', 'icall_cfi_count', 'icall_no_cfi_count', 'icall_cfi_rate',
            'pac_sign_count', 'pac_auth_count', 'pac_func_protected', 'pac_func_sign_only', 'pac_no_pac'],
    'functions': ['vcall_site_count', 'vcall_cfi_count', 'vcall_no_cfi_count', 'vcall_cfi_rate',
                  'icall_site_count', 'icall_cfi_count', 'icall_no_cfi_count', 'icall_cfi_rate',
                  'pac_sign_count', 'pac_auth_count', 'pac_func_protected', 'pac_func_sign_only', 'pac_func_no_pac',
                  'bti_count', 'bti_func_with', 'bti_func_without', 'bti_func_total'],
}

_DIM_LABELS = {'functions': '仅函数级 CFI', 'vcall': 'vcall', 'icall': 'icall', 'pac': 'PAC', 'bti': 'BTI'}


def run_dimension(lib_dir, ELFFile, dimension, progress=None, log=None):
    """Run .so level + function classification + specified dimension only.
    dimension: 'functions', 'vcall', 'icall', 'pac', 'bti'
    """
    return run_detection(lib_dir, ELFFile, function_detail=True, dimension=dimension,
                         progress=progress, log=log)


def _analyze_so_level(args):
    """Worker for parallel .so-level detection."""
    so_file_str, rel_path = args
    ELFFile = ensure_pyelftools()
    error = None
    try:
        with open(so_file_str, 'rb') as f:
            elf = ELFFile(f)
            enabled = check_cfi_enabled(elf)
    except Exception as e:
        enabled = False
        error = str(e)
    r = {'path': rel_path, 'cfi_enabled': enabled}
    if error:
        r['error'] = error
    return r


def run_so_level(lib_dir, ELFFile, progress=None, log=None):
    so_files = _iter_so(lib_dir)
    total = len(so_files)
    _log(log, f"找到 {total} 个 .so 文件（仅 .so 级检测）")

    tasks = [(str(so_file), _rel(so_file, lib_dir)) for so_file in so_files]
    num_workers = min(os.cpu_count() or 4, 8)

    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        future_to_idx = {executor.submit(_analyze_so_level, t): i for i, t in enumerate(tasks)}
        temp_results = [None] * total
        completed = 0
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                temp_results[idx] = future.result()
            except Exception as e:
                temp_results[idx] = {'path': tasks[idx][1], 'cfi_enabled': False, 'error': str(e)}
            completed += 1
            if progress:
                progress(completed, total, temp_results[idx].get('path', ''))
            elif completed % 100 == 0:
                _log(log, f"  进度: {completed} / {total}")

    results = temp_results
    on = sum(1 for r in results if r and r.get('cfi_enabled'))
    err_count = sum(1 for r in results if r and r.get('error'))
    summary = {'total_so': total, 'cfi_enabled_so': on, 'cfi_not_enabled_so': total - on}
    _log(log, f"  CFI 已开启: {on} / 未开启: {total - on}")
    if err_count:
        _log(log, f"  解析失败: {err_count}")
    return results, summary


def _analyze_one_so(args):
    """Worker function for parallel .so analysis. Must be module-level for ProcessPoolExecutor."""
    so_file_str, rel_path, function_detail, dimension, is_full, zero_keys = args
    ELFFile = ensure_pyelftools()
    try:
        with open(so_file_str, 'rb') as f:
            elf = ELFFile(f)
            cfi_enabled = check_cfi_enabled(elf)

            if not function_detail:
                result = {'cfi_enabled': cfi_enabled}
            else:
                fn = classify_functions(elf)
                calls = {}
                pac_bti = {}

                if is_full:
                    calls = scan_call_sites(elf) if cfi_enabled else {}
                    machine = elf.get_machine_arch()
                    if machine == 'AArch64':
                        pac_bti = analyze_pac_bti(elf)
                else:
                    if dimension in ('vcall', 'icall') and cfi_enabled:
                        calls = scan_call_sites(elf, dimension)
                    if dimension in ('pac', 'bti'):
                        machine = elf.get_machine_arch()
                        if machine == 'AArch64':
                            pac_bti = analyze_pac_bti(elf, dimension)

                result = {'cfi_enabled': cfi_enabled, **fn, **calls, **pac_bti}

                for k in zero_keys:
                    result[k] = 0
    except Exception as e:
        if not function_detail:
            result = {'cfi_enabled': False, 'error': str(e)}
        else:
            result = {'cfi_enabled': False, 'error': str(e),
                      'cfi_protected': [], 'cfi_protected_count': 0,
                      'cfi_infra': [], 'cfi_infra_count': 0,
                      'truly_unprotected': [], 'truly_unprotected_count': 0, 'other_count': 0}

    result['path'] = rel_path
    return result


def _run_serial(so_files, lib_dir, ELFFile, function_detail, dimension, is_full, zero_keys, progress, log):
    """Serial .so processing — no pickling overhead, best for full detection with large function lists."""
    results = []
    total = len(so_files)
    for i, so_file in enumerate(so_files, 1):
        rel_path = _rel(so_file, lib_dir)
        try:
            with open(str(so_file), 'rb') as f:
                elf = ELFFile(f)
                cfi_enabled = check_cfi_enabled(elf)
                if not function_detail:
                    result = {'cfi_enabled': cfi_enabled}
                else:
                    fn = classify_functions(elf)
                    calls = {}
                    pac_bti = {}
                    if is_full:
                        calls = scan_call_sites(elf) if cfi_enabled else {}
                        machine = elf.get_machine_arch()
                        if machine == 'AArch64':
                            pac_bti = analyze_pac_bti(elf)
                    else:
                        if dimension in ('vcall', 'icall') and cfi_enabled:
                            calls = scan_call_sites(elf, dimension)
                        if dimension in ('pac', 'bti'):
                            machine = elf.get_machine_arch()
                            if machine == 'AArch64':
                                pac_bti = analyze_pac_bti(elf, dimension)
                    result = {'cfi_enabled': cfi_enabled, **fn, **calls, **pac_bti}
                    for k in zero_keys:
                        result[k] = 0
        except Exception as e:
            if not function_detail:
                result = {'cfi_enabled': False, 'error': str(e)}
            else:
                result = {'cfi_enabled': False, 'error': str(e),
                          'cfi_protected': [], 'cfi_protected_count': 0,
                          'cfi_infra': [], 'cfi_infra_count': 0,
                          'truly_unprotected': [], 'truly_unprotected_count': 0, 'other_count': 0}
        result['path'] = rel_path
        results.append(result)
        if progress:
            progress(i, total, rel_path)
        elif i % 100 == 0:
            _log(log, f"  进度: {i} / {total}")
    if not progress:
        _log(log, f"  进度: {total} / {total} - 完成!")
    return results


def _run_parallel(so_files, lib_dir, function_detail, dimension, is_full, zero_keys, progress, log):
    """Parallel .so processing via ProcessPoolExecutor — pickling overhead for large function lists."""
    total = len(so_files)
    tasks = [(str(so_file), _rel(so_file, lib_dir), function_detail, dimension, is_full, zero_keys)
             for so_file in so_files]
    num_workers = min(os.cpu_count() or 4, 8)
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        future_to_idx = {executor.submit(_analyze_one_so, t): i for i, t in enumerate(tasks)}
        temp_results = [None] * total
        completed = 0
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                temp_results[idx] = future.result()
            except Exception as e:
                rel_path = tasks[idx][1]
                if function_detail:
                    temp_results[idx] = {'cfi_enabled': False, 'error': str(e),
                                        'cfi_protected': [], 'cfi_protected_count': 0,
                                        'cfi_infra': [], 'cfi_infra_count': 0,
                                        'truly_unprotected': [], 'truly_unprotected_count': 0, 'other_count': 0}
                else:
                    temp_results[idx] = {'cfi_enabled': False, 'error': str(e)}
                temp_results[idx]['path'] = rel_path
            completed += 1
            if progress:
                progress(completed, total, temp_results[idx].get('path', ''))
            elif completed % 100 == 0:
                _log(log, f"  进度: {completed} / {total}")
    for i in range(total):
        if temp_results[i] is None:
            temp_results[i] = {'cfi_enabled': False, 'error': 'worker did not return result',
                                'path': tasks[i][1]}
    return temp_results


def run_detection(lib_dir, ELFFile, function_detail=True, dimension=None, progress=None, log=None, parallel=True):
    """Run CFI detection on all .so files.

    dimension=None: full detection (all dimensions).
    dimension='functions'/'vcall'/'icall'/'pac'/'bti': single dimension only.
    function_detail=False: only .so level (skip all function/call/PAC/BTI analysis).
    """
    is_full = dimension is None

    if is_full:
        _log(log, f"正在查找 .so 文件...")
    else:
        _log(log, f"找到 .so 文件...")

    so_files = _iter_so(lib_dir)
    total = len(so_files)

    if is_full:
        _log(log, f"找到 {total} 个 .so 文件")
        if not function_detail:
            _log(log, "模式: 仅 .so 级检测 (跳过函数级分析)")
    else:
        dim_label = _DIM_LABELS.get(dimension, dimension)
        others = [v for v in ['vcall', 'icall', 'pac', 'bti'] if v != dimension]
        _log(log, f"找到 {total} 个 .so 文件（{dim_label} 检测，不含 {'/'.join(others)}）")
    _log(log, "")

    results = []
    cfi_on_count = cfi_off_count = 0
    total_cfi_funcs = total_truly_unprotected = total_other_funcs = total_infra = 0
    total_vcall_sites = total_vcall_cfi = total_vcall_no_cfi = 0
    total_icall_sites = total_icall_cfi = total_icall_no_cfi = 0
    aarch64_count = 0
    total_pac_sign = total_pac_auth = total_bti = total_retaa = total_retab = 0
    total_pac_func_protected = total_pac_func_sign_only = total_pac_func_no_pac = 0
    total_bti_func_with = total_bti_func_without = 0

    zero_keys = _DIM_ZERO_KEYS.get(dimension, []) if not is_full else []

    if parallel and function_detail:
        results = _run_parallel(so_files, lib_dir, function_detail, dimension, is_full, zero_keys, progress, log)
    else:
        results = _run_serial(so_files, lib_dir, ELFFile, function_detail, dimension, is_full, zero_keys, progress, log)

    for result in results:
        cfi_enabled = result.get('cfi_enabled')
        if cfi_enabled:
            cfi_on_count += 1
            if function_detail:
                total_cfi_funcs += result.get('cfi_protected_count', 0)
                total_infra += result.get('cfi_infra_count', 0)
                total_vcall_sites += result.get('vcall_site_count', 0)
                total_vcall_cfi += result.get('vcall_cfi_count', 0)
                total_vcall_no_cfi += result.get('vcall_no_cfi_count', 0)
                total_icall_sites += result.get('icall_site_count', 0)
                total_icall_cfi += result.get('icall_cfi_count', 0)
                total_icall_no_cfi += result.get('icall_no_cfi_count', 0)
        else:
            cfi_off_count += 1
        if function_detail:
            total_truly_unprotected += result.get('truly_unprotected_count', 0)
            if is_full:
                total_other_funcs += result.get('other_count', 0)

        if result.get('pac_bti_available'):
            aarch64_count += 1
            if function_detail:
                total_pac_sign += result.get('pac_sign_count', 0)
                total_pac_auth += result.get('pac_auth_count', 0)
                total_bti += result.get('bti_count', 0)
                total_retaa += result.get('retaa_count', 0)
                total_retab += result.get('retab_count', 0)
                total_pac_func_protected += result.get('pac_func_protected', 0)
                total_pac_func_sign_only += result.get('pac_func_sign_only', 0)
                total_pac_func_no_pac += result.get('pac_func_no_pac', 0)
                total_bti_func_with += result.get('bti_func_with', 0)
                total_bti_func_without += result.get('bti_func_without', 0)

    if not progress:
        _log(log, f"  进度: {total} / {total} - 完成!")
    err_count = sum(1 for r in results if r.get('error'))
    _log(log, "")
    _log(log, f"  CFI 已开启 .so:       {cfi_on_count}")
    _log(log, f"  CFI 未开启 .so:       {cfi_off_count}")
    if err_count:
        _log(log, f"  解析失败 .so:         {err_count}")
    if function_detail:
        _log(log, f"  CFI 保护函数:         {total_cfi_funcs}")
        _log(log, f"  CFI 基础设施符号:     {total_infra}")
        if is_full:
            _log(log, f"  真正未保护函数:       {total_truly_unprotected}")
            _log(log, f"  其他函数总数:         {total_other_funcs}")
            _log(log, f"  vcall 调用点:         {total_vcall_sites} (有CFI:{total_vcall_cfi} 无CFI:{total_vcall_no_cfi})")
            _log(log, f"  icall 调用点:         {total_icall_sites} (有CFI:{total_icall_cfi} 无CFI:{total_icall_no_cfi})")
        else:
            _log(log, f"  未保护函数:           {total_truly_unprotected}")
        if is_full and dimension is None:
            pass
        if not is_full and dimension in ('vcall', 'icall'):
            _log(log, f"  vcall 调用点:         {total_vcall_sites} (有CFI:{total_vcall_cfi} 无CFI:{total_vcall_no_cfi})")
            _log(log, f"  icall 调用点:         {total_icall_sites} (有CFI:{total_icall_cfi} 无CFI:{total_icall_no_cfi})")
    if function_detail and aarch64_count > 0 and (is_full or dimension in ('pac', 'bti')):
        _log(log, "")
        _log(log, f"  AArch64 .so:          {aarch64_count}")
        _log(log, f"  PAC 签名指令:         {total_pac_sign}")
        _log(log, f"  PAC 认证指令:         {total_pac_auth}")
        if is_full:
            _log(log, f"  RETAA/RETAB:          {total_retaa}/{total_retab}")
        _log(log, f"  BTI 指令:            {total_bti}")
        if is_full:
            _log(log, f"  PAC 函数保护:        {total_pac_func_protected} (sign_only:{total_pac_func_sign_only} no_pac:{total_pac_func_no_pac})")
        else:
            _log(log, f"  PAC 函数保护:        {total_pac_func_protected}")
        _log(log, f"  BTI 函数覆盖:        {total_bti_func_with} / {total_bti_func_with + total_bti_func_without}")
    _log(log, "")

    summary = {
        'total_so': total,
        'cfi_enabled_so': cfi_on_count,
        'cfi_not_enabled_so': cfi_off_count,
        'function_detail': function_detail,
        'total_cfi_protected_funcs': total_cfi_funcs,
        'total_cfi_infra': total_infra,
        'total_truly_unprotected': total_truly_unprotected,
        'total_other_funcs': total_other_funcs,
        'total_vcall_sites': total_vcall_sites,
        'total_vcall_cfi': total_vcall_cfi,
        'total_vcall_no_cfi': total_vcall_no_cfi,
        'total_vcall_cfi_rate': round(total_vcall_cfi / total_vcall_sites * 100, 1) if total_vcall_sites > 0 else 0,
        'total_icall_sites': total_icall_sites,
        'total_icall_cfi': total_icall_cfi,
        'total_icall_no_cfi': total_icall_no_cfi,
        'total_icall_cfi_rate': round(total_icall_cfi / total_icall_sites * 100, 1) if total_icall_sites > 0 else 0,
        'aarch64_so': aarch64_count,
        'total_pac_sign_count': total_pac_sign,
        'total_pac_auth_count': total_pac_auth,
        'total_bti_count': total_bti,
        'total_retaa_count': total_retaa,
        'total_retab_count': total_retab,
        'total_pac_func_protected': total_pac_func_protected,
        'total_pac_func_sign_only': total_pac_func_sign_only,
        'total_pac_func_no_pac': total_pac_func_no_pac,
        'total_bti_func_with': total_bti_func_with,
        'total_bti_func_without': total_bti_func_without,
        'has_vcall': 1 if (is_full or dimension == 'vcall') else 0,
        'has_icall': 1 if (is_full or dimension == 'icall') else 0,
        'has_pac': 1 if ((is_full or dimension == 'pac') and aarch64_count > 0) else 0,
        'has_bti': 1 if ((is_full or dimension == 'bti') and aarch64_count > 0) else 0,
    }
    return results, summary
