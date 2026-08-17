#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Part 3: identify the real KeBugCheck2 / KiDisplayBlueScreen on build 26100."""
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

KBCEX = 0x1404F9250
DISP  = 0x1404FA160   # KiBugCheckDispatch candidate
CORE  = 0x1405AE6F0   # final call from KeBugCheckEx
BIGFN = 0x140B63540   # big function called by DISP

print("== KeBugCheckEx 0x4F92E1..0x4F9370 (full tail) ==")
for i in disasm(0x1404F92E1, 0x90):
    print("  %016X: %-8s %s" % (i.address, i.mnemonic, i.op_str))

print("\n== CORE 0x1405AE6F0: prologue 0x120 bytes ==")
for i in disasm(CORE, 0x120):
    print("  %016X: %-8s %s" % (i.address, i.mnemonic, i.op_str))

print("\n== CORE 0x1405AE6F0: call/jmp targets (scan 0x3000) ==")
uniq = []
for i in disasm(CORE, 0x3000):
    if i.mnemonic in ("call", "jmp") and i.operands and i.operands[0].type == X86_OP_IMM:
        t = i.operands[0].imm
        if t not in [u[0] for u in uniq]:
            uniq.append((t, i.address))
for t, a in uniq:
    print("  %016X (from %016X)  prologue: %s" % (t, a, ph(t)))

print("\n== BIGFN 0x140B63540: prologue 0x100 bytes ==")
for i in disasm(BIGFN, 0x100):
    print("  %016X: %-8s %s" % (i.address, i.mnemonic, i.op_str))

print("\n== BIGFN 0x140B63540: call/jmp targets (scan 0x4000) ==")
uniq = []
for i in disasm(BIGFN, 0x4000):
    if i.mnemonic in ("call", "jmp") and i.operands and i.operands[0].type == X86_OP_IMM:
        t = i.operands[0].imm
        if t not in [u[0] for u in uniq]:
            uniq.append((t, i.address))
for t, a in uniq:
    print("  %016X (from %016X)  prologue: %s" % (t, a, ph(t)))

print("\n== BIGFN: contains hlt (0xF4)? scan for standalone hlt ==")
data = read(rva(BIGFN), 0x4000)
hlts = [i for i in range(len(data)) if data[i] == 0xF4]
print("  raw 0xF4 bytes at offsets:", ["%X" % h for h in hlts[:20]], "(count %d)" % len(hlts))

print("\n== XREFS: who calls 0x1404FA160 (DISP)? ==")
def find_xrefs(target_va, scan_len=0x400000):
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

for tgt in (DISP, CORE, BIGFN):
    refs = find_xrefs(tgt)
    print("  refs to %016X: %d" % (tgt, len(refs)))
    for src, op in refs[:40]:
        print("    %016X (%s)" % (src, "call" if op == 0xE8 else "jmp"))
