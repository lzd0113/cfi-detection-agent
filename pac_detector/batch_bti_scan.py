#!/usr/bin/env python3
"""
Batch BTI scanner for AArch64 .so collections.
Usage: python batch_bti_scan.py [lib_dir]
If lib_dir is not provided, prompts the user to input it.
"""
import sys, struct, os
from pathlib import Path
from collections import Counter, defaultdict

# Constants
EM_AARCH64 = 183
SHT_PROGBITS = 1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
HINT_MASK = 0xFFFFF01F
HINT_BASE = 0xD503201F
BTI_HINT_RANGE = {32, 34, 36, 38}
BTI_HINT_NAMES = {32: "BTI", 34: "BTI c", 36: "BTI j", 38: "BTI jc"}


class ELF64:
    """Minimal ELF64 parser."""

    def __init__(self, filepath):
        with open(filepath, "rb") as f:
            self.data = f.read()
        if len(self.data) < 64 or self.data[:4] != b"\x7fELF":
            raise ValueError("Not an ELF file")
        if self.data[4] != 2:
            raise ValueError("Not ELF64")
        self.is_le = self.data[5] == 1
        self.endian = "<" if self.is_le else ">"
        hdr = struct.unpack_from(self.endian + "HHIQQQIHHHHHH", self.data, 16)
        (self.e_type, self.e_machine, self.e_version, self.e_entry,
         self.e_phoff, self.e_shoff, self.e_flags, self.e_ehsize,
         self.e_phentsize, self.e_phnum, self.e_shentsize,
         self.e_shnum, self.e_shstrndx) = hdr
        self._parse_sections()

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
                "entsize": vals[9], "name": "",
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


def scan_lib_dir(lib_dir):
    lib_dir = Path(lib_dir)
    if not lib_dir.is_dir():
        print("Error: directory not found: %s" % lib_dir)
        sys.exit(1)

    so_files = sorted(lib_dir.rglob('*.so'))
    total = len(so_files)
    if total == 0:
        print("Error: no .so files found in %s" % lib_dir)
        sys.exit(1)

    print("Found %d .so files in %s" % (total, lib_dir))
    print("Scanning BTI...\n")

    bti_note = 0
    bti_insn = 0
    no_bti = 0
    non_aarch64 = 0
    bti_counter = Counter()
    mod_stats = defaultdict(lambda: {'total': 0, 'bti': 0, 'bti_count': 0})

    for idx, so_file in enumerate(so_files, 1):
        rel = str(so_file.relative_to(lib_dir)).replace(os.sep, '/')
        module = rel.split('/')[0] if '/' in rel else ''
        ms = mod_stats[module]
        ms['total'] += 1

        try:
            elf = ELF64(str(so_file))
        except Exception:
            no_bti += 1
            continue

        if elf.e_machine != EM_AARCH64:
            non_aarch64 += 1
            no_bti += 1
            continue

        # L1: .note.gnu.property BTI flag
        has_note = False
        sec = elf.get_section('.note.gnu.property')
        if sec:
            data = elf.section_data(sec)
            align = sec.get('addralign', 8) or 8
            if align < 2:
                align = 8
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
                if ntype == 5 and name == b'GNU':
                    dpos = 0
                    while dpos + 8 <= len(desc):
                        pr_type, pr_ds = struct.unpack_from('<II', desc, dpos)
                        dpos += 8
                        pr_data = desc[dpos:dpos + pr_ds]
                        dpos += (pr_ds + 7) & ~7
                        if pr_type == 0xC0000000 and pr_ds >= 4:
                            if struct.unpack_from('<I', pr_data, 0)[0] & 0x1:
                                has_note = True

        # L3: byte scan BTI
        insn_count = 0
        for esec in elf.exec_sections():
            data = elf.section_data(esec)
            for i in range(0, len(data) - 3, 4):
                word = struct.unpack_from('<I', data, i)[0]
                if (word & HINT_MASK) == HINT_BASE:
                    imm7 = (word >> 5) & 0x7F
                    if imm7 in BTI_HINT_RANGE:
                        insn_count += 1
                        bti_counter[BTI_HINT_NAMES.get(imm7, 'HINT#%d' % imm7)] += 1

        if has_note:
            bti_note += 1
        if insn_count > 0:
            bti_insn += 1
            ms['bti'] += 1
            ms['bti_count'] += insn_count
        if not has_note and insn_count == 0:
            no_bti += 1

        if idx % 500 == 0:
            print('  Progress: %d / %d' % (idx, total), flush=True)

    print()
    print('=' * 64)
    print('  BTI Detection Summary')
    print('=' * 64)
    print('Input directory: %s' % lib_dir)
    print('Total .so files:                %d' % total)
    if non_aarch64:
        print('  (non-AArch64 skipped:         %d)' % non_aarch64)
    print('.so with .note.gnu.property BTI: %d (%.1f%%)' % (bti_note, bti_note * 100.0 / total))
    print('.so with BTI instructions:       %d (%.1f%%)' % (bti_insn, bti_insn * 100.0 / total))
    print('.so without any BTI:             %d (%.1f%%)' % (no_bti, no_bti * 100.0 / total))
    print()
    print('BTI instruction breakdown:')
    if bti_counter:
        for t, c in bti_counter.most_common():
            print('  %-12s  x%d' % (t, c))
    else:
        print('  (none)')
    print()
    print('Per-module (top 20 by BTI .so count):')
    print('  %-25s %5s %5s %5s' % ('Module', '.so', 'BTI', 'Insn'))
    for mod, ms in sorted(mod_stats.items(), key=lambda x: -x[1]['bti'])[:20]:
        print('  %-25s %5d %5d %5d' % (mod, ms['total'], ms['bti'], ms['bti_count']))
    print()
    print('=' * 64)


def main():
    if len(sys.argv) >= 2:
        lib_dir = sys.argv[1]
    else:
        print("BTI Batch Scanner for AArch64 .so files")
        print("-" * 40)
        lib_dir = input("Please enter the .so directory path: ").strip().strip('"').strip("'")

    if not lib_dir:
        print("Error: no directory provided")
        sys.exit(1)

    scan_lib_dir(lib_dir)


if __name__ == "__main__":
    main()
