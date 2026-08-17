#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Analyze ntoskrnl.exe bugcheck call chain on Windows 10/11 x64.

Finds the addresses (RVAs) of:
  - KeBugCheckEx   (exported)
  - KeBugCheck     (exported)
  - KeBugCheck2    (NOT exported) -> located via call/jmp from KeBugCheckEx
  - KiDisplayBlueScreen (NOT exported) -> located via calls from KeBugCheck2
and prints disassembly of the relevant regions, plus identifies the
"BugCheck ..." format-string referencing function and "*** STOP:" string
references to cross-validate the findings.
"""
import sys
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

NTOS = r"C:\Windows\System32\ntoskrnl.exe"
IMAGE_BASE_PREFERRED = 0x140000000

pe = pefile.PE(NTOS, fast_load=False)
image_base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True


def va(rva):
    return image_base + rva


def rva_of_va(x):
    return x - image_base


def read(rva, n):
    return pe.get_data(rva, n)


def disasm_range(start_rva, length, max_insns=4000):
    data = read(start_rva, length)
    return list(md.disasm(data, va(start_rva)))


def disasm_va(start_va, length, max_insns=4000):
    return disasm_range(rva_of_va(start_va), length, max_insns)


def print_insns(insns, limit=60):
    for i in insns[:limit]:
        print("  %016X: %-8s %s" % (i.address, i.mnemonic, i.op_str))


def calls_and_jmps(insns):
    out = []
    for i in insns:
        if i.mnemonic in ("call", "jmp") and i.operands and i.operands[0].type == X86_OP_IMM:
            out.append((i, i.operands[0].imm))
    return out


def prologue_hex(va_, n=24):
    try:
        return read(rva_of_va(va_), n).hex(" ")
    except Exception:
        return "?"


def find_ascii(s):
    """Find all RVAs of ASCII string s in the image (scan .rdata)."""
    needle = s.encode("ascii") + b"\x00"
    hits = []
    for sec in pe.sections:
        if b".rdata" not in sec.Name and b".text" not in sec.Name:
            continue
        data = sec.get_data()
        idx = 0
        while True:
            idx = data.find(needle, idx)
            if idx < 0:
                break
            hits.append(sec.VirtualAddress + idx)
            idx += 1
    return hits


def find_rip_refs(target_rva, scan_rva_range=(0, 0x800000)):
    """Find rip-relative references (lea/cmp/mov ... [rip+disp]) to target_rva."""
    refs = []
    for sec in pe.sections:
        if b".text" not in sec.Name:
            continue
        base_rva = sec.VirtualAddress
        data = sec.get_data()
        # scan for 48 8D 05/0D (lea rax/rcx, [rip+disp]) style + any modrm with rip base
        i = 0
        while i < len(data) - 7:
            b = data[i]
            if b in (0x48, 0x4C) and data[i+1] == 0x8D and (data[i+2] & 0xC7) == 0x05:
                disp = int.from_bytes(data[i+3:i+7], "little", signed=True)
                insn_va = va(base_rva + i)
                ref_va = insn_va + 7 + disp
                if ref_va == va(target_rva):
                    refs.append(base_rva + i)
                i += 7
            else:
                i += 1
    return refs


def find_func_containing(ref_rva, length=0x600):
    """Given an rva inside .text, find function start by walking back to a plausible prologue."""
    sec = None
    for s in pe.sections:
        if b".text" in s.Name and s.VirtualAddress <= ref_rva < s.VirtualAddress + s.Misc_VirtualSize:
            sec = s
            break
    if sec is None:
        return None
    data = sec.get_data()
    off = ref_rva - sec.VirtualAddress
    # walk back up to `length` bytes looking for int3 (0xCC) padding or ret+cc pattern
    start = off
    for k in range(off, max(0, off - length), -1):
        if data[k] == 0xCC and k + 1 < len(data) and data[k+1] == 0xCC:
            start = k + 1
            break
        if k > 0 and data[k-1] == 0xCC and data[k] != 0xCC:
            start = k
            break
    # then walk forward until we hit a plausible prologue within the first 16 bytes
    for k in range(start, min(off, start + 16)):
        if data[k] in (0x48, 0x53, 0x57, 0x56, 0x55, 0x41):
            start = k
            break
    return sec.VirtualAddress + start


# ---------------------------------------------------------------------------
print("== exports ==")
exports = {}
for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    if exp.name:
        exports[exp.name.decode()] = exp.address
for name in ("KeBugCheckEx", "KeBugCheck", "KeBugCheck2", "KeBugCheck2Ex", "KiDisplayBlueScreen",
             "KiBugCheckDispatch", "KeBugCheckActive", "KeBugCheckCallbackListHead", "HalBugCheckSystem"):
    if name in exports:
        print("  %-28s RVA=%08X  VA=%016X" % (name, exports[name], va(exports[name])))
    else:
        print("  %-28s NOT EXPORTED" % name)

kbcx_rva = exports["KeBugCheckEx"]
kbc_rva = exports["KeBugCheck"]

print("\n== KeBugCheckEx disassembly (first 0x90 bytes) ==")
ins = disasm_range(kbcx_rva, 0x90)
print_insns(ins, 40)
cj = calls_and_jmps(ins)
print("  call/jmp targets from KeBugCheckEx:")
for i, t in cj:
    print("    %016X %s -> %016X   prologue: %s" % (i.address, i.mnemonic, t, prologue_hex(t)))

print("\n== KeBugCheck disassembly (first 0x80 bytes) ==")
ins = disasm_range(kbc_rva, 0x80)
print_insns(ins, 40)
cj = calls_and_jmps(ins)
print("  call/jmp targets from KeBugCheck:")
for i, t in cj:
    print("    %016X %s -> %016X   prologue: %s" % (i.address, i.mnemonic, t, prologue_hex(t)))

# ---------------------------------------------------------------------------
print("\n== hunt: string 'BugCheck %' ==")
for s in ("BugCheck %08X", "BugCheck %p", "BugCheck 0x", "*** STOP:", "BugCheck"):
    hits = find_ascii(s)
    print("  %-16s -> %d hits (first 5: %s)" % (s, len(hits), ["%08X" % h for h in hits[:5]]))

print("\n== rip refs to first 'BugCheck %' string ==")
hits = find_ascii("BugCheck %")
if hits:
    refs = find_rip_refs(hits[0])
    print("  refs:", ["%08X" % r for r in refs])
    for r in refs[:10]:
        print("   ref at RVA %08X, containing func start guess %08X" % (r, find_func_containing(r)))

print("\n== rip refs to first '*** STOP:' string ==")
hits = find_ascii("*** STOP:")
if hits:
    refs = find_rip_refs(hits[0])
    print("  refs:", ["%08X" % r for r in refs])
    for r in refs[:10]:
        print("   ref at RVA %08X, containing func start guess %08X" % (r, find_func_containing(r)))
