#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Part 11: call graph of the display-subsystem cluster on 26100."""
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM

NTOS = r"C:\Windows\System32\ntoskrnl.exe"
pe = pefile.PE(NTOS, fast_load=False)
image_base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

def rva(x): return x - image_base
def read(rva_, n): return pe.get_data(rva_, n)
def disasm(start_va, length):
    return list(md.disasm(read(rva(start_va), length), start_va))
def ph(va_, n=24):
    try: return read(rva(va_), n).hex(" ")
    except Exception: return "?"

def find_xrefs(target_va):
    refs = []
    for sec in pe.sections:
        if b".text" not in sec.Name:
            continue
        base = sec.VirtualAddress
        data = sec.get_data()
        i = 0
        while i < len(data) - 5:
            if data[i] in (0xE8, 0xE9):
                disp = int.from_bytes(data[i+1:i+5], "little", signed=True)
                src = image_base + base + i
                dst = src + 5 + disp
                if dst == target_va:
                    refs.append((src, data[i]))
                i += 5
            else:
                i += 1
    return refs

cluster = {
    0x1404FA160: "context-save (dispatcher)",
    0x1404FA460: "push-rbp fn (cli-trap helpers)",
    0x1404FA9F0: "wrapper (KeBugCheckEx-like)",
    0x1404FAB40: "snprintf wrapper",
    0x1404FAD20: "helper (3 callers)",
    0x1404FAFE8: "big helper (2 callers)",
    0x1404FB208: "printf-like",
    0x1404FB483: "calls FB208",
    0x1404FB74E: "calls FEF58 + 0x140230F50",
    0x1404FB8A6: "calls FE52C",
    0x1404FBB13: "calls FE52C",
    0x1404FBBED: "calls FE52C",
    0x1404FACC7: "calls FEF58",
    0x1404FCE73: "calls FEF58",
    0x1404FD559: "calls FEF58",
    0x1404FE51C: "text formatter A",
    0x1404FE52C: "text formatter B",
    0x1404FEF58: "text formatter C",
    0x1404FFBD0: "big fn D",
    0x1404FFD50: "big fn E",
    0x140B63540: "WHEA-ish (wrapper target)",
    0x140B74870: "param recorder",
    0x140B77E30: "param recorder 2",
}

print("== xrefs of cluster functions ==")
for fn, name in cluster.items():
    refs = find_xrefs(fn)
    print("  %016X %-28s: %d refs  %s" % (fn, name, len(refs),
          ["%016X" % r[0] for r in refs[:8]]))

print("\n== KeBugCheck2 (0x1405AE6F0) call targets in 0x1404F0000..0x140510000 ==")
for i in disasm(0x1405AE6F0, 0x9000):
    if i.mnemonic in ("call", "jmp") and i.operands and i.operands[0].type == X86_OP_IMM:
        t = i.operands[0].imm
        if 0x1404F0000 <= t < 0x140510000:
            print("  from %016X -> %016X" % (i.address, t))

print("\n== dump-writer (0x1405971E8) call targets in cluster ==")
for i in disasm(0x1405971E8, 0x1400):
    if i.mnemonic in ("call", "jmp") and i.operands and i.operands[0].type == X86_OP_IMM:
        t = i.operands[0].imm
        if 0x1404F0000 <= t < 0x140510000 or 0x140B60000 <= t < 0x140BA0000:
            print("  from %016X -> %016X" % (i.address, t))

print("\n== who calls 0x1404FB74E / 0x1404FB8A6 / 0x1404FCE73 / 0x1404FD559? (their callers) ==")
for fn in (0x1404FB74E, 0x1404FB8A6, 0x1404FCE73, 0x1404FD559, 0x1404FACC7, 0x1404FBB13):
    refs = find_xrefs(fn)
    print("  %016X: %s" % (fn, ["%016X" % r[0] for r in refs[:10]]))

print("\n== what is 0x140230F50 (called by 0x1404FB74E's fn)? prologue + who calls IT ==")
print("  prologue:", ph(0x140230F50))
refs = find_xrefs(0x140230F50)
print("  xrefs:", ["%016X" % r[0] for r in refs[:10]])
