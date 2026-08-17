#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Part 7: KeBugCheck2 final region + wrapper callers + BIGFN nature."""
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

print("== KeBugCheck2 end region: 0x1405B1380..0x1405B15EC ==")
for i in disasm(0x1405B1380, 0x26C):
    print("  %016X: %-8s %s" % (i.address, i.mnemonic, i.op_str))

print("\n== xrefs to wrapper 0x1404FA9F0 ==")
for src, op in find_xrefs(0x1404FA9F0):
    print("  %016X (%s)" % (src, "call" if op == 0xE8 else "jmp"))

print("\n== containing fn of 0x14059728F: disasm 0x1405971A0..0x1405975F0 ==")
for i in disasm(0x1405971A0, 0x450):
    print("  %016X: %-8s %s" % (i.address, i.mnemonic, i.op_str))

print("\n== containing fn of 0x1405BF343: disasm 0x1405BF200..0x1405BF4A0 ==")
for i in disasm(0x1405BF200, 0x2A0):
    print("  %016X: %-8s %s" % (i.address, i.mnemonic, i.op_str))

print("\n== containing fn of 0x1406ABD20: disasm 0x1406ABC80..0x1406ABE00 ==")
for i in disasm(0x1406ABC80, 0x180):
    print("  %016X: %-8s %s" % (i.address, i.mnemonic, i.op_str))

print("\n== BIGFN 0x140B63540: unique call targets (0x6000) ==")
uniq = []
for i in disasm(0x140B63540, 0x6000):
    if i.mnemonic in ("call", "jmp") and i.operands and i.operands[0].type == X86_OP_IMM:
        t = i.operands[0].imm
        if t not in [u[0] for u in uniq]:
            uniq.append((t, i.address))
for t, a in uniq:
    print("  %016X (from %016X)  prologue: %s" % (t, a, ph(t)))
