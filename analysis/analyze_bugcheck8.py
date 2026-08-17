#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Part 8: locate the display function via global refs + string table refs."""
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

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

# KeBugCheckCode global candidate: KeBugCheck2 stored code at 0x140F2CA00
KBCGLOB = 0x140F2CA00

def find_rip_refs(target_va):
    refs = []
    for sec in pe.sections:
        if b".text" not in sec.Name:
            continue
        base = sec.VirtualAddress
        data = sec.get_data()
        i = 0
        while i < len(data) - 7:
            b = data[i]
            # 48 8B 05/0D/15/1D/25/2D/35/3D (mov r64,[rip+disp]) and 8B 05/0D... (mov r32,[rip])
            if (b in (0x48, 0x4C, 0x8B, 0x44, 0x4C+0) and data[i+1] in (0x8B, 0x8D, 0x39, 0x3B) and (data[i+2] & 0xC7) == 0x05):
                disp = int.from_bytes(data[i+3:i+7], "little", signed=True)
                insn_va = image_base + base + i
                ref = insn_va + 7 + disp
                if ref == target_va:
                    refs.append(base + i)
                i += 7
            else:
                i += 1
    return refs

print("== rip refs to KeBugCheckCode global 0x140F2CA00 ==")
refs = find_rip_refs(KBCGLOB)
print("  count:", len(refs))
for r in refs[:60]:
    print("    %08X" % r)

print("\n== rip refs to P1 global 0x140F2CA08 ==")
refs = find_rip_refs(0x140F2CA08)
print("  count:", len(refs))
for r in refs[:30]:
    print("    %08X" % r)

print("\n== search bugcheck-name strings ==")
names = ["SYSTEM_SERVICE_EXCEPTION", "KERNEL_DATA_INPAGE_ERROR", "IRQL_NOT_LESS_OR_EQUAL",
         "KMODE_EXCEPTION_NOT_HANDLED", "CRITICAL_PROCESS_DIED", "MEMORY_MANAGEMENT",
         "PAGE_FAULT_IN_NONPAGED_AREA", "KERNEL_SECURITY_CHECK_FAILURE", "DPC_WATCHDOG_VIOLATION"]
def find_ascii(s):
    needle = s.encode("ascii") + b"\x00"
    hits = []
    for sec in pe.sections:
        data = sec.get_data()
        idx = 0
        while True:
            idx = data.find(needle, idx)
            if idx < 0:
                break
            hits.append((sec.VirtualAddress + idx, sec.Name.decode().strip('\x00')))
            idx += 1
    return hits

for n in names:
    hits = find_ascii(n)
    if hits:
        print("  %-32s -> %s" % (n, hits[:4]))

print("\n== function at 0x1405971E8: full-ish body calls ==")
uniq = []
for i in disasm(0x1405971E8, 0x1200):
    if i.mnemonic in ("call", "jmp") and i.operands and i.operands[0].type == X86_OP_IMM:
        t = i.operands[0].imm
        if t not in [u[0] for u in uniq]:
            uniq.append((t, i.address))
for t, a in uniq:
    print("  %016X (from %016X)  prologue: %s" % (t, a, ph(t)))

print("\n== BIGFN 0x140B63540: body calls (0x6000) ==")
uniq = []
for i in disasm(0x140B63540, 0x6000):
    if i.mnemonic in ("call", "jmp") and i.operands and i.operands[0].type == X86_OP_IMM:
        t = i.operands[0].imm
        if t not in [u[0] for u in uniq]:
            uniq.append((t, i.address))
for t, a in uniq:
    print("  %016X (from %016X)  prologue: %s" % (t, a, ph(t)))
