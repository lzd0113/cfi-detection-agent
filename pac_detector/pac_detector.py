#!/usr/bin/env python3
"""
Branch Protection Detector - PAC + BTI detection for AArch64 ELF.

Three-layer detection:
  L1: Check .note.gnu.property for FEATURE_1_PAC / FEATURE_1_BTI
  L2: Full capstone disassembly, search all PAC + BTI mnemonics
  L3: Byte-pattern scan (HINT scan + RETAA/RETAB) as fallback

Usage:
  python pac_detector.py <path-to-.so> [--json] [--verbose]
"""

import sys
import struct
import json
from collections import Counter

# ============================================================
# Constants
# ============================================================

EM_AARCH64 = 183
SHT_PROGBITS = 1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
STT_FUNC = 2

NT_GNU_PROPERTY_TYPE_0 = 5
GNU_PROPERTY_AARCH64_FEATURE_1_AND = 0xC0000000
FEAT_BTI = 0x1
FEAT_PAC = 0x2

PAC_MNEMONICS = {
    "paciasp", "pacibsp", "autiasp", "autibsp",
    "pacia", "pacib", "pacda", "pacdb", "pacga",
    "autia", "autib", "autda", "autdb", "autga",
    "paciza", "pacizb", "pacdza", "pacdzb", "pacgza", "pacgzb",
    "retaa", "retab",
    "braa", "brab", "blraa", "blrab",
    "xpaci", "xpacd",
}

HINT_MASK = 0xFFFFF01F
HINT_BASE = 0xD503201F
PAC_HINT_RANGE = set(range(25, 32))
PAC_SIGN_HINTS = {25, 26, 27}
PAC_AUTH_HINTS = {28, 29, 30, 31}
PAC_HINT_NAMES = {
    25: "PACIASP", 26: "PACIZB", 27: "PACIBSP",
    28: "AUTIZA", 29: "AUTIASP", 30: "AUTIZB", 31: "AUTIBSP",
}

BTI_MNEMONICS = {"bti"}
BTI_HINT_RANGE = {32, 34, 36, 38}
BTI_HINT_NAMES = {32: "BTI", 34: "BTI c", 36: "BTI j", 38: "BTI jc"}

RETAA_WORD = 0xD65F0BFF
RETAB_WORD = 0xD65F0FFF
RET_WORD = 0xD65F03C0

KNOWN_HINTS = {
    0: "nop", 1: "yield", 2: "wfe", 3: "wfi", 4: "sev", 5: "sevl",
}


# ============================================================
# ELF64 Parser (zero external dependencies)
# ============================================================

class ELF64:
    """Minimal ELF64 parser: section headers, string table, section data."""

    def __init__(self, filepath):
        with open(filepath, "rb") as f:
            self.data = f.read()
        self._parse_header()
        self._parse_sections()

    def _parse_header(self):
        if len(self.data) < 64 or self.data[:4] != b"\x7fELF":
            raise ValueError("Not an ELF file")
        if self.data[4] != 2:
            raise ValueError("Not ELF64 (class=%d)" % self.data[4])
        self.is_le = self.data[5] == 1
        self.endian = "<" if self.is_le else ">"
        hdr = struct.unpack_from(self.endian + "HHIQQQIHHHHHH", self.data, 16)
        (self.e_type, self.e_machine, self.e_version, self.e_entry,
         self.e_phoff, self.e_shoff, self.e_flags, self.e_ehsize,
         self.e_phentsize, self.e_phnum, self.e_shentsize,
         self.e_shnum, self.e_shstrndx) = hdr

    def _parse_sections(self):
        self.sections = []
        fmt = self.endian + "IIQQQQIIQQ"
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            vals = struct.unpack_from(fmt, self.data, off)
            self.sections.append({
                "name_off": vals[0], "type": vals[1], "flags": vals[2],
                "addr": vals[3], "offset": vals[4], "size": vals[5],
                "link": vals[6], "info": vals[7], "addralign": vals[8],
                "entsize": vals[9],
                "name": "",
            })
        if self.e_shstrndx < len(self.sections):
            strtab = self.sections[self.e_shstrndx]
            strdata = self.data[strtab["offset"]:strtab["offset"] + strtab["size"]]
            for sec in self.sections:
                no = sec["name_off"]
                end = strdata.find(b"\x00", no)
                if end >= 0:
                    sec["name"] = strdata[no:end].decode("ascii", errors="replace")

    def get_section(self, name):
        for sec in self.sections:
            if sec["name"] == name:
                return sec
        return None

    def section_data(self, sec):
        if sec is None or sec["size"] == 0:
            return b""
        return self.data[sec["offset"]:sec["offset"] + sec["size"]]

    def exec_sections(self):
        out = []
        for sec in self.sections:
            if (sec["flags"] & SHF_EXECINSTR) and sec["type"] == SHT_PROGBITS and sec["size"] > 0:
                out.append(sec)
        return out

    def find_section_by_addr(self, addr):
        for sec in self.sections:
            if sec["size"] > 0 and sec["addr"] <= addr < sec["addr"] + sec["size"]:
                return sec
        return None

    def get_symbols(self):
        symtab = self.get_section(".symtab")
        if not symtab or symtab["size"] == 0:
            return []
        link = symtab.get("link", 0)
        strtab_sec = self.sections[link] if link < len(self.sections) else None
        strdata = self.section_data(strtab_sec) if strtab_sec else b""
        sym_data = self.section_data(symtab)
        entsize = symtab.get("entsize", 0) or 24
        symbols = []
        for off in range(0, len(sym_data) - entsize + 1, entsize):
            vals = struct.unpack_from(self.endian + "IBBHQQ", sym_data, off)
            st_name, st_info, st_other, st_shndx, st_value, st_size = vals
            name = ""
            if st_name < len(strdata):
                end = strdata.find(b"\x00", st_name)
                if end >= 0:
                    name = strdata[st_name:end].decode("ascii", errors="replace")
            symbols.append({
                "name": name, "info": st_info, "type": st_info & 0xF,
                "value": st_value, "size": st_size, "shndx": st_shndx,
            })
        return symbols


# ============================================================
# L1: .note.gnu.property check
# ============================================================

def check_gnu_property(elf):
    """Parse .note.gnu.property, return PAC/BTI feature flags."""
    sec = elf.get_section(".note.gnu.property")
    if sec is None:
        return {"found": False, "pac": None, "bti": None, "props": []}

    data = elf.section_data(sec)
    align = sec.get("addralign", 8) or 8
    if align < 2:
        align = 8
    result = {"found": True, "pac": None, "bti": None, "props": []}
    pos = 0
    end = len(data)

    while pos + 12 <= end:
        namesz, descsz, ntype = struct.unpack_from("<III", data, pos)
        pos += 12
        name = data[pos:pos + namesz].rstrip(b"\x00")
        pos += namesz
        pos = (pos + align - 1) // align * align
        desc = data[pos:pos + descsz]
        pos += descsz
        pos = (pos + align - 1) // align * align

        if ntype == NT_GNU_PROPERTY_TYPE_0 and name == b"GNU":
            dpos = 0
            while dpos + 8 <= len(desc):
                pr_type, pr_ds = struct.unpack_from("<II", desc, dpos)
                dpos += 8
                pr_data = desc[dpos:dpos + pr_ds]
                dpos += (pr_ds + 7) & ~7

                entry = {"type": "0x%08X" % pr_type, "datasize": pr_ds}
                if pr_type == GNU_PROPERTY_AARCH64_FEATURE_1_AND and pr_ds >= 4:
                    feat = struct.unpack_from("<I", pr_data, 0)[0]
                    entry["features"] = "0x%08X" % feat
                    result["pac"] = bool(feat & FEAT_PAC)
                    result["bti"] = bool(feat & FEAT_BTI)
                result["props"].append(entry)

    return result


# ============================================================
# L2: Capstone disassembly
# ============================================================

def capstone_scan(elf):
    """Disassemble all executable sections with capstone, find PAC + BTI."""
    try:
        import capstone
    except ImportError:
        return None

    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = False

    sections_out = []
    total_insns = 0
    pac_counter = Counter()
    bti_counter = Counter()

    for sec in elf.exec_sections():
        code = elf.section_data(sec)
        pac_hits = []
        bti_hits = []
        count = 0

        for insn in md.disasm(code, sec["addr"]):
            count += 1
            if insn.mnemonic in PAC_MNEMONICS:
                pac_hits.append({
                    "addr": insn.address,
                    "mnemonic": insn.mnemonic,
                    "op_str": insn.op_str,
                })
                pac_counter[insn.mnemonic] += 1
            elif insn.mnemonic in BTI_MNEMONICS:
                bti_hits.append({
                    "addr": insn.address,
                    "mnemonic": insn.mnemonic,
                    "op_str": insn.op_str,
                })
                bti_counter[insn.mnemonic + (" " + insn.op_str if insn.op_str else "")] += 1

        total_insns += count
        sections_out.append({
            "name": sec["name"],
            "addr": sec["addr"],
            "size": sec["size"],
            "insns": count,
            "pac_hits": pac_hits,
            "bti_hits": bti_hits,
        })

    return {
        "available": True,
        "sections": sections_out,
        "total_insns": total_insns,
        "pac_total": sum(pac_counter.values()),
        "bti_total": sum(bti_counter.values()),
        "pac_breakdown": dict(pac_counter),
        "bti_breakdown": dict(bti_counter),
    }


# ============================================================
# L3: Byte-pattern scan (fallback / supplement)
# ============================================================

def byte_scan(elf):
    """Scan executable sections at 4-byte stride for PAC + BTI patterns."""
    pac_hints = {}
    bti_hints = {}
    other_hints = {}
    retaa = 0
    retab = 0
    ret = 0

    for sec in elf.exec_sections():
        data = elf.section_data(sec)
        base = sec["addr"]
        for i in range(0, len(data) - 3, 4):
            word = struct.unpack_from("<I", data, i)[0]

            if (word & HINT_MASK) == HINT_BASE:
                imm7 = (word >> 5) & 0x7F
                if imm7 in PAC_HINT_RANGE:
                    pac_hints[imm7] = pac_hints.get(imm7, 0) + 1
                elif imm7 in BTI_HINT_RANGE:
                    bti_hints[imm7] = bti_hints.get(imm7, 0) + 1
                else:
                    other_hints[imm7] = other_hints.get(imm7, 0) + 1

            if word == RETAA_WORD:
                retaa += 1
            elif word == RETAB_WORD:
                retab += 1
            elif word == RET_WORD:
                ret += 1

    return {
        "pac_hints": pac_hints,
        "bti_hints": bti_hints,
        "other_hints": other_hints,
        "retaa": retaa,
        "retab": retab,
        "ret": ret,
    }


# ============================================================
# L4: BTI Function Coverage (function-level analysis)
# ============================================================

def bti_function_coverage(elf):
    """Check function entry points for BTI instructions via .symtab."""
    symbols = elf.get_symbols()
    func_syms = [s for s in symbols if s["type"] == STT_FUNC and s["value"] != 0]

    total = len(func_syms)
    if total == 0:
        return {"available": False, "reason": "no .symtab or no function symbols"}

    with_bti = 0
    without_bti = 0
    bti_type_counter = Counter()
    no_bti_samples = []

    for sym in func_syms:
        addr = sym["value"]
        sec = elf.find_section_by_addr(addr)
        if not sec:
            without_bti += 1
            continue

        data = elf.section_data(sec)
        offset = addr - sec["addr"]
        if offset + 4 > len(data):
            without_bti += 1
            continue

        word = struct.unpack_from("<I", data, offset)[0]
        if (word & HINT_MASK) == HINT_BASE:
            imm7 = (word >> 5) & 0x7F
            if imm7 in BTI_HINT_RANGE:
                with_bti += 1
                bti_type_counter[BTI_HINT_NAMES.get(imm7, "HINT#%d" % imm7)] += 1
                continue

        without_bti += 1
        if len(no_bti_samples) < 20:
            no_bti_samples.append({"addr": addr, "name": sym["name"]})

    coverage = round(with_bti / total * 100, 1) if total > 0 else 0
    return {
        "available": True,
        "total_functions": total,
        "with_bti": with_bti,
        "without_bti": without_bti,
        "coverage_rate": coverage,
        "bti_type_breakdown": dict(bti_type_counter),
        "no_bti_samples": no_bti_samples,
    }


# ============================================================
# L5: PAC Function Analysis (function-level PAC protection)
# ============================================================

def pac_function_analysis(elf):
    """Analyze PAC protection at function level: sign/auth/retaa/retab per function."""
    symbols = elf.get_symbols()
    func_syms = [s for s in symbols if s["type"] == STT_FUNC and s["value"] != 0]

    total = len(func_syms)
    if total == 0:
        return {"available": False, "reason": "no .symtab or no function symbols"}

    protected = []
    sign_only = []
    auth_only = []
    no_pac = []
    unknown = []
    pac_points = []

    for sym in func_syms:
        addr = sym["value"]
        size = sym["size"]
        name = sym["name"]
        sec = elf.find_section_by_addr(addr)
        if not sec:
            no_pac.append({"addr": addr, "name": name})
            continue

        data = elf.section_data(sec)
        offset = addr - sec["addr"]

        has_sign = False
        has_auth = False

        if size > 0:
            end = min(offset + size, len(data))
            for i in range(offset, end - 3, 4):
                word = struct.unpack_from("<I", data, i)[0]

                if (word & HINT_MASK) == HINT_BASE:
                    imm7 = (word >> 5) & 0x7F
                    if imm7 in PAC_SIGN_HINTS:
                        has_sign = True
                        pac_points.append({"addr": sec["addr"] + i,
                                          "type": PAC_HINT_NAMES.get(imm7, "HINT#%d" % imm7),
                                          "function": name})
                    elif imm7 in PAC_AUTH_HINTS:
                        has_auth = True
                        pac_points.append({"addr": sec["addr"] + i,
                                          "type": PAC_HINT_NAMES.get(imm7, "HINT#%d" % imm7),
                                          "function": name})
                if word == RETAA_WORD:
                    has_auth = True
                    pac_points.append({"addr": sec["addr"] + i, "type": "RETAA", "function": name})
                elif word == RETAB_WORD:
                    has_auth = True
                    pac_points.append({"addr": sec["addr"] + i, "type": "RETAB", "function": name})
        else:
            if offset + 4 <= len(data):
                word = struct.unpack_from("<I", data, offset)[0]
                if (word & HINT_MASK) == HINT_BASE:
                    imm7 = (word >> 5) & 0x7F
                    if imm7 in PAC_SIGN_HINTS:
                        has_sign = True
                        pac_points.append({"addr": sec["addr"] + offset,
                                          "type": PAC_HINT_NAMES.get(imm7, "HINT#%d" % imm7),
                                          "function": name})
            unknown.append({"addr": addr, "name": name})
            continue

        entry = {"addr": addr, "name": name}
        if has_sign and has_auth:
            protected.append(entry)
        elif has_sign:
            sign_only.append(entry)
        elif has_auth:
            auth_only.append(entry)
        else:
            no_pac.append(entry)

    classified = total - len(unknown)
    coverage = round(len(protected) / classified * 100, 1) if classified > 0 else 0

    pac_type_counter = Counter()
    for p in pac_points:
        pac_type_counter[p["type"]] += 1

    return {
        "available": True,
        "total_functions": total,
        "classified": classified,
        "unknown_size": len(unknown),
        "protected_count": len(protected),
        "sign_only_count": len(sign_only),
        "auth_only_count": len(auth_only),
        "no_pac_count": len(no_pac),
        "coverage_rate": coverage,
        "total_pac_points": len(pac_points),
        "pac_type_breakdown": dict(pac_type_counter),
        "protected_sample": protected[:20],
        "no_pac_sample": no_pac[:20],
        "sign_only_sample": sign_only[:10],
        "auth_only_sample": auth_only[:10],
        "pac_points_sample": pac_points[:50],
    }


# ============================================================
# Report generation
# ============================================================

def build_report(filepath, elf, l1, l2, l3, l4=None, l5=None, verbose=False):
    L = []
    sep = "=" * 64
    L.append(sep)
    L.append("  PAC + BTI Detection Report")
    L.append(sep)
    L.append("File:   %s" % filepath)
    L.append("Arch:  %s (EM=%d)" % (
        "AArch64" if elf.e_machine == EM_AARCH64 else "Unknown",
        elf.e_machine))
    L.append("Endian: %s" % ("little" if elf.is_le else "big"))
    L.append("")

    # ---- L1 ----
    L.append("--- L1: .note.gnu.property ---")
    if l1["found"]:
        L.append("  Section: FOUND")
        if l1["pac"] is not None:
            L.append("  PAC feature: %s" % ("SET" if l1["pac"] else "NOT SET"))
        else:
            L.append("  PAC feature: (no FEATURE_1_AND property)")
        if l1["bti"] is not None:
            L.append("  BTI feature: %s" % ("SET" if l1["bti"] else "NOT SET"))
        for p in l1["props"]:
            L.append("  Property: type=%s datasize=%d %s" % (
                p["type"], p["datasize"],
                p.get("features", "")))
    else:
        L.append("  Section: NOT FOUND")
    L.append("")

    # ---- L2 ----
    L.append("--- L2: Capstone Disassembly ---")
    if l2 is not None:
        L.append("  Capstone: available")
        L.append("  Total instructions: %d" % l2["total_insns"])
        L.append("")
        L.append("  [PAC] hits: %d" % l2["pac_total"])
        if l2["pac_breakdown"]:
            for m, c in sorted(l2["pac_breakdown"].items(), key=lambda x: -x[1]):
                L.append("    %-12s  x%d" % (m, c))
        L.append("")
        L.append("  [BTI] hits: %d" % l2["bti_total"])
        if l2["bti_breakdown"]:
            for m, c in sorted(l2["bti_breakdown"].items(), key=lambda x: -x[1]):
                L.append("    %-12s  x%d" % (m, c))
        L.append("")
        shown = 0
        for sr in l2["sections"]:
            pac_n = len(sr.get("pac_hits", []))
            bti_n = len(sr.get("bti_hits", []))
            if pac_n or bti_n:
                L.append("  Section %s (%d bytes, %d insns, PAC:%d BTI:%d):" % (
                    sr["name"], sr["size"], sr["insns"], pac_n, bti_n))
                if shown < 10:
                    for h in sr.get("pac_hits", [])[:max(0, 10 - shown)]:
                        L.append("    0x%x: %s %s" % (
                            h["addr"], h["mnemonic"], h["op_str"]))
                        shown += 1
                    for h in sr.get("bti_hits", [])[:max(0, 10 - shown)]:
                        L.append("    0x%x: %s %s" % (
                            h["addr"], h["mnemonic"], h["op_str"]))
                        shown += 1
    else:
        L.append("  Capstone: NOT installed (skipped)")
    L.append("")

    # ---- L3 ----
    L.append("--- L3: Byte Scan ---")
    if l2 is not None:
        L.append("  (supplementary to L2)")
    if l3["pac_hints"]:
        L.append("  PAC-family HINT instructions:")
        for imm7 in sorted(l3["pac_hints"]):
            L.append("    HINT #%d  x%d" % (imm7, l3["pac_hints"][imm7]))
    else:
        L.append("  PAC-family HINT instructions: none")
    if l3.get("bti_hints"):
        L.append("  BTI-family HINT instructions:")
        for imm7 in sorted(l3["bti_hints"]):
            L.append("    HINT #%d  x%d" % (imm7, l3["bti_hints"][imm7]))
    else:
        L.append("  BTI-family HINT instructions: none")
    L.append("  RETAA: %d" % l3["retaa"])
    L.append("  RETAB: %d" % l3["retab"])
    L.append("  plain RET: %d" % l3["ret"])
    if verbose and l3["other_hints"]:
        L.append("  Other HINT instructions (verbose):")
        for imm7 in sorted(l3["other_hints"]):
            nm = KNOWN_HINTS.get(imm7, "")
            tag = " (%s)" % nm if nm else ""
            L.append("    HINT #%d%s  x%d" % (imm7, tag, l3["other_hints"][imm7]))
    L.append("")

    # ---- L4: BTI Function Coverage ----
    if l4 and l4.get("available"):
        L.append("--- L4: BTI Function Coverage ---")
        L.append("  Total functions: %d" % l4["total_functions"])
        L.append("  Functions with BTI at entry: %d" % l4["with_bti"])
        L.append("  Functions without BTI: %d" % l4["without_bti"])
        L.append("  BTI coverage rate: %s%%" % l4["coverage_rate"])
        if l4["bti_type_breakdown"]:
            L.append("  BTI type distribution at function entries:")
            for t, c in sorted(l4["bti_type_breakdown"].items(), key=lambda x: -x[1]):
                L.append("    %-12s  x%d" % (t, c))
        if verbose and l4["no_bti_samples"]:
            L.append("  Sample functions WITHOUT BTI (first %d):" % min(10, len(l4["no_bti_samples"])))
            for s in l4["no_bti_samples"][:10]:
                L.append("    0x%x: %s" % (s["addr"], s["name"] or "(unnamed)"))
        L.append("")

    # ---- L5: PAC Function Analysis ----
    if l5 and l5.get("available"):
        L.append("--- L5: PAC Function Analysis ---")
        L.append("  Total functions: %d" % l5["total_functions"])
        if l5["unknown_size"]:
            L.append("  (size unknown, prologue-only check: %d)" % l5["unknown_size"])
        L.append("  PAC protected (sign + auth): %d" % l5["protected_count"])
        L.append("  Sign only (no auth): %d" % l5["sign_only_count"])
        L.append("  Auth only (no sign): %d" % l5["auth_only_count"])
        L.append("  No PAC: %d" % l5["no_pac_count"])
        L.append("  PAC coverage rate: %s%%" % l5["coverage_rate"])
        L.append("  Total PAC instruction points: %d" % l5["total_pac_points"])
        if l5["pac_type_breakdown"]:
            L.append("  PAC type breakdown:")
            for t, c in sorted(l5["pac_type_breakdown"].items(), key=lambda x: -x[1]):
                L.append("    %-12s  x%d" % (t, c))
        if verbose:
            if l5["protected_sample"]:
                L.append("  Sample PROTECTED functions (first %d):" % min(10, len(l5["protected_sample"])))
                for s in l5["protected_sample"][:10]:
                    L.append("    0x%x: %s" % (s["addr"], s["name"] or "(unnamed)"))
            if l5["no_pac_sample"]:
                L.append("  Sample functions WITHOUT PAC (first %d):" % min(10, len(l5["no_pac_sample"])))
                for s in l5["no_pac_sample"][:10]:
                    L.append("    0x%x: %s" % (s["addr"], s["name"] or "(unnamed)"))
            if l5["sign_only_sample"]:
                L.append("  Sign-only functions (first %d):" % min(5, len(l5["sign_only_sample"])))
                for s in l5["sign_only_sample"][:5]:
                    L.append("    0x%x: %s" % (s["addr"], s["name"] or "(unnamed)"))
            if l5["auth_only_sample"]:
                L.append("  Auth-only functions (first %d):" % min(5, len(l5["auth_only_sample"])))
                for s in l5["auth_only_sample"][:5]:
                    L.append("    0x%x: %s" % (s["addr"], s["name"] or "(unnamed)"))
            if l5["pac_points_sample"]:
                L.append("  PAC instruction points (first %d):" % min(20, len(l5["pac_points_sample"])))
                for p in l5["pac_points_sample"][:20]:
                    L.append("    0x%x: %-12s  (%s)" % (p["addr"], p["type"], p["function"] or "(unnamed)"))
        L.append("")

    # ---- Conclusion ----
    L.append(sep)
    L.append("=== Conclusion ===")

    pac = False
    bti = False
    method_pac = []
    method_bti = []
    pac_type = []

    if l1.get("pac"):
        pac = True
        method_pac.append("L1 (note)")
    if l1.get("bti"):
        bti = True
        method_bti.append("L1 (note)")

    if l2 is not None:
        if l2["pac_total"] > 0:
            pac = True
            method_pac.append("L2 (capstone)")
            for m in l2["pac_breakdown"]:
                if "paci" in m or "auti" in m or "retaa" in m:
                    pac_type.append(m)
        if l2["bti_total"] > 0:
            bti = True
            method_bti.append("L2 (capstone)")

    hint_pac_total = sum(l3["pac_hints"].values()) if l3["pac_hints"] else 0
    hint_bti_total = sum(l3.get("bti_hints", {}).values()) if l3.get("bti_hints") else 0
    if hint_pac_total > 0 or l3["retaa"] > 0 or l3["retab"] > 0:
        pac = True
        if not method_pac:
            method_pac.append("L3 (byte scan)")
    if hint_bti_total > 0:
        bti = True
        if not method_bti:
            method_bti.append("L3 (byte scan)")

    if pac:
        L.append("  PAC: DETECTED")
        L.append("  Method: %s" % " + ".join(method_pac))
        if pac_type:
            L.append("  Instructions: %s" % ", ".join(sorted(set(pac_type))))
        if l3["pac_hints"] and l2 is None:
            L.append("  HINT imm7 values: %s" % sorted(l3["pac_hints"].keys()))
    else:
        L.append("  PAC: NOT DETECTED")

    if l5 and l5.get("available"):
        L.append("  PAC function coverage: %s%% (%d / %d functions)" % (
            l5["coverage_rate"], l5["protected_count"], l5["classified"]))

    if bti:
        L.append("  BTI: DETECTED")
        L.append("  Method: %s" % " + ".join(method_bti))
        if l2 is not None and l2["bti_breakdown"]:
            L.append("  Instructions: %s" % ", ".join(sorted(l2["bti_breakdown"].keys())))
        if l3.get("bti_hints") and l2 is None:
            L.append("  HINT imm7 values: %s" % sorted(l3["bti_hints"].keys()))
    else:
        L.append("  BTI: NOT DETECTED")

    if l4 and l4.get("available"):
        L.append("  BTI function coverage: %s%% (%d / %d functions)" % (
            l4["coverage_rate"], l4["with_bti"], l4["total_functions"]))

    if not l1.get("found"):
        L.append("  Note: .note.gnu.property absent (toolchain may omit it)")

    L.append(sep)
    return "\n".join(L)


# ============================================================
# Main
# ============================================================

def main():
    if len(sys.argv) < 2:
        print("Usage: python %s <path-to-.so> [--json] [--verbose]" % sys.argv[0])
        sys.exit(1)

    filepath = sys.argv[1]
    json_out = "--json" in sys.argv
    verbose = "--verbose" in sys.argv

    try:
        elf = ELF64(filepath)
    except Exception as e:
        print("Error: %s" % e)
        sys.exit(1)

    if elf.e_machine != EM_AARCH64:
        print("Warning: EM=%d (not AArch64=183), results may be invalid" % elf.e_machine)

    l1 = check_gnu_property(elf)
    l2 = capstone_scan(elf)
    l3 = byte_scan(elf)
    l4 = bti_function_coverage(elf)
    l5 = pac_function_analysis(elf)

    if json_out:
        out = {
            "file": filepath,
            "arch": "AArch64" if elf.e_machine == EM_AARCH64 else "EM=%d" % elf.e_machine,
            "endian": "little" if elf.is_le else "big",
            "l1_note": l1,
            "l2_capstone": {
                "available": l2["available"] if l2 else False,
                "total_insns": l2["total_insns"] if l2 else 0,
                "pac_total": l2["pac_total"] if l2 else 0,
                "bti_total": l2["bti_total"] if l2 else 0,
                "pac_breakdown": l2["pac_breakdown"] if l2 else {},
                "bti_breakdown": l2["bti_breakdown"] if l2 else {},
            },
            "l3_bytescan": l3,
            "l4_bti_coverage": l4,
            "l5_pac_analysis": l5,
        }
        print(json.dumps(out, indent=2, default=str))
    else:
        print(build_report(filepath, elf, l1, l2, l3, l4, l5, verbose))


if __name__ == "__main__":
    main()
