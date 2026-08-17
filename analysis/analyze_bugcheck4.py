#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Part 4: xrefs + find KiDisplayBlueScreen equivalent on 26100."""
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

DISP  = 0x1404FA160   # KiBugCheckDispatch candidate
CORE  = 0x1405AE6F0   # KeBugCheck2 (confirmed-ish)
BIGFN = 0x140B63540   # display candidate 1
BIGFN2= 0x140B77E30   # display candidate 2 (called by CORE)

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

print("== xrefs ==")
for tgt, name in ((DISP, "DISP(0x1404FA160)"), (CORE, "CORE(0x1405AE6F0)"), (BIGFN, "BIGFN(0x140B63540)"), (BIGFN2, "BIGFN2(0x140B77E30)")):
    refs = find_xrefs(tgt)
    print("  %s: %d refs" % (name, len(refs)))
    for src, op in refs[:30]:
        print("    %016X (%s)" % (src, "call" if op == 0xE8 else "jmp"))
    print()

print("== CORE 0x1405AE6F0: extended call scan 0x8000 bytes, unique targets ==")
uniq = []
for i in disasm(CORE, 0x8000):
    if i.mnemonic in ("call", "jmp") and i.operands and i.operands[0].type == X86_OP_IMM:
        t = i.operands[0].imm
        if t not in [u[0] for u in uniq]:
            uniq.append((t, i.address))
for t, a in uniq:
    tag = ""
    if 0x1404F0000 <= t < 0x140510000: tag = "  <-- bugcheck subsystem region"
    elif 0x140B60000 <= t < 0x140B90000: tag = "  <-- 0x140B6-0x140B9 region"
    print("  %016X (from %016X)%s" % (t, a, tag))
print("  total unique:", len(uniq))

print("\n== BIGFN 0x140B63540: first 0x120 bytes ==")
for i in disasm(BIGFN, 0x120):
    print("  %016X: %-8s %s" % (i.address, i.mnemonic, i.op_str))

print("\n== BIGFN 0x140B63540: scan 0x6000 for calls, unique ==")
uniq = []
for i in disasm(BIGFN, 0x6000):
    if i.mnemonic in ("call", "jmp") and i.operands and i.operands[0].type == X86_OP_IMM:
        t = i.operands[0].imm
        if t not in [u[0] for u in uniq]:
            uniq.append((t, i.address))
for t, a in uniq:
    print("  %016X (from %016X)  prologue: %s" % (t, a, ph(t)))
print("  total unique:", len(uniq))
