#!/usr/bin/env python3
"""Generate a complete MSVC module-definition (.def) file from a DLL.

Why this exists instead of gendef:
  * SDR++'s sdrpp_core.dll exports ~11.6k symbols. gendef's C++ demangler
    aborts early on modern MSVC mangling ($$Q rvalue-refs, $$V, ECSU types),
    truncating the .def to a few hundred entries, so the resulting import
    library is missing almost every core/ImGui symbol a plugin needs.
  * pefile reads the export table directly (no demangling), but caps export
    enumeration at 8192 per instance by default; we raise that cap.

Each export is classified as a function or DATA by checking whether its RVA
lands in an executable section -- the same distinction gendef makes, needed so
the import library emits correct entries for SDR++'s exported global objects.

Usage: gen_def.py <input.dll> <output.def> [dll_name_for_LIBRARY_line]
"""
import sys
import pefile

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_CNT_CODE = 0x00000020


def main():
    if len(sys.argv) < 3:
        sys.stderr.write("usage: gen_def.py <dll> <out.def> [libname]\n")
        return 2
    dll = sys.argv[1]
    out = sys.argv[2]
    libname = sys.argv[3] if len(sys.argv) > 3 else None

    pe = pefile.PE(dll, fast_load=True)
    # Raise the per-instance export cap (default 8192) BEFORE parsing the
    # export directory, or pefile silently truncates the export table and
    # warns "Assuming corrupt".
    pe.max_symbol_exports = 500000
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])

    code_ranges = []
    for s in pe.sections:
        ch = s.Characteristics
        if ch & IMAGE_SCN_MEM_EXECUTE or ch & IMAGE_SCN_CNT_CODE:
            start = s.VirtualAddress
            size = max(s.Misc_VirtualSize, s.SizeOfRawData)
            code_ranges.append((start, start + size))

    def is_code(rva):
        return any(a <= rva < b for a, b in code_ranges)

    exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if exp is None:
        sys.stderr.write("error: no export directory in %s\n" % dll)
        return 1

    lines = []
    n_func = n_data = n_noname = 0
    for sym in exp.symbols:
        if sym.name is None:
            n_noname += 1   # exported by ordinal only; cannot import by name
            continue
        name = sym.name.decode("ascii", "replace")
        if is_code(sym.address):
            lines.append(name)
            n_func += 1
        else:
            lines.append(name + " DATA")
            n_data += 1

    with open(out, "w", newline="\n") as f:
        if libname:
            f.write("LIBRARY " + libname + "\n")
        f.write("EXPORTS\n")
        f.write("\n".join(lines) + "\n")

    sys.stderr.write(
        "gen_def: %s -> %s  named=%d functions=%d data=%d ordinal_only=%d\n"
        % (dll, out, n_func + n_data, n_func, n_data, n_noname))
    if n_func + n_data < 1000:
        sys.stderr.write("error: export count implausibly low; aborting\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
