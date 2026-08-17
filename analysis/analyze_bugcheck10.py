#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Part 10: last identification attempt for KiBugCheckDispatch/display on 26100."""
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

print("== 0x140231750 (jmp target of 0x1404FA981): body calls 0x4000 ==")
uniq = []
for i in disasm(0x140231750, 0x4000):
    if i.mnemonic in ("call", "jmp") and i.operands and i.operands[0].type == X86_OP_IMM:
        t = i.operands[0].imm
        if t not in [u[0] for u in uniq]:
            uniq.append((t, i.address))
for t, a in uniq[:40]:
    print("  %016X (from %016X)  prologue: %s" % (t, a, ph(t)))
print("  total:", len(uniq))

print("\n== 0x1404FA460 region: find function start (disasm 0x1404FA3E0..0x1404FA480) ==")
for i in disasm(0x1404FA3E0, 0xA0):
    print("  %016X: %-8s %s" % (i.address, i.mnemonic, i.op_str))

print("\n== xrefs to the fn starting at 0x1404FA400-ish: check 0x1404FA400 ==")
for cand in (0x1404FA400, 0x1404FA410, 0x1404FA420, 0x1404FA430, 0x1404FA440, 0x1404FA450, 0x1404FA460):
    refs = find_xrefs(cand)
    if refs:
        print("  %016X: %s" % (cand, ["%016X" % r[0] for r in refs[:10]]))

print("\n== fn containing 0x1406ABD20: disasm 0x1406ABC00..0x1406ABE80 ==")
for i in disasm(0x1406ABC00, 0x280):
    print("  %016X: %-8s %s" % (i.address, i.mnemonic, i.op_str))

print("\n== fn containing 0x1405BF343: disasm 0x1405BF180..0x1405BF500 ==")
for i in disasm(0x1405BF180, 0x380):
    print("  %016X: %-8s %s" % (i.address, i.mnemonic, i.op_str))
