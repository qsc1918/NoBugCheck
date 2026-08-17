#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Part 5: pin down KiBugCheckDispatch end, display function candidates."""
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

DISP = 0x1404FA160
CORE = 0x1405AE6F0

print("== end of function starting at 0x1404FA160: scan for ret ==")
for i in disasm(DISP, 0x400):
    if i.mnemonic in ("ret", "retn", "iretq", "jmp"):
        print("  %016X: %-8s %s" % (i.address, i.mnemonic, i.op_str))

print("\n== who contains 0x1404FAAB3 (call to BIGFN)? disasm 0x1404FA9F0..0x1404FAC00 ==")
for i in disasm(0x1404FA9F0, 0x220):
    print("  %016X: %-8s %s" % (i.address, i.mnemonic, i.op_str))

print("\n== KeBugCheck2 tail: 0x1405B15E0..0x1405B1850 ==")
for i in disasm(0x1405B15E0, 0x270):
    print("  %016X: %-8s %s" % (i.address, i.mnemonic, i.op_str))

print("\n== candidates in 0x140B7xxxx region ==")
for c in (0x140B74870, 0x140B76270, 0x140B77E30, 0x140B84EA0):
    print("  %016X prologue: %s" % (c, ph(c)))
    for i in disasm(c, 0x60):
        print("    %016X: %-8s %s" % (i.address, i.mnemonic, i.op_str))
    print()
