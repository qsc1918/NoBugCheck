#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Part 2: dig into the new bugcheck dispatcher found on build 26100."""
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM

NTOS = r"C:\Windows\System32\ntoskrnl.exe"
pe = pefile.PE(NTOS, fast_load=False)
image_base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

KBCEX = 0x1404F9250      # KeBugCheckEx
DISP  = 0x1404FA160      # internal pushfq-prologue fn called by KeBugCheckEx

def va_rva(x): return x - image_base
def read(rva, n): return pe.get_data(rva, n)
def disasm(start_va, length):
    return list(md.disasm(read(va_rva(start_va), length), start_va))
def prologue_hex(va_, n=24):
    try: return read(va_rva(va_), n).hex(" ")
    except Exception: return "?"

print("== KeBugCheckEx tail (0x4F92E1 .. +0x90) ==")
for i in disasm(0x1404F92E1, 0x90):
    print("  %016X: %-8s %s" % (i.address, i.mnemonic, i.op_str))

print("\n== internal dispatcher 0x1404FA160: first 0x100 bytes ==")
for i in disasm(DISP, 0x100):
    print("  %016X: %-8s %s" % (i.address, i.mnemonic, i.op_str))

print("\n== internal dispatcher 0x1404FA160: all call/jmp targets (scan 0x4000 bytes) ==")
seen = []
for i in disasm(DISP, 0x4000):
    if i.mnemonic in ("call", "jmp") and i.operands and i.operands[0].type == X86_OP_IMM:
        t = i.operands[0].imm
        seen.append((i.address, i.mnemonic, t))
for a, m, t in seen:
    print("  %016X %-4s -> %016X  prologue: %s" % (a, m, t, prologue_hex(t)))
print("  total call/jmp:", len(seen))

print("\n== unique targets ==")
uniq = []
for a, m, t in seen:
    if t not in [u[0] for u in uniq]:
        uniq.append((t, m, a))
for t, m, a in uniq:
    print("  %016X (first seen %s @ %016X)  prologue: %s" % (t, m, a, prologue_hex(t)))

print("\n== 'BugCheck' strings content ==")
for rva in (0x52360, 0x523E4):
    data = read(rva, 96)
    print("  RVA %08X: %r" % (rva, data))

print("\n== rip-relative refs to those strings ==")
def find_rip_refs(target_rva):
    refs = []
    for sec in pe.sections:
        if b".text" not in sec.Name:
            continue
        base = sec.VirtualAddress
        data = sec.get_data()
        i = 0
        while i < len(data) - 7:
            b = data[i]
            if b in (0x48, 0x4C) and data[i+1] == 0x8D and (data[i+2] & 0xC7) == 0x05:
                disp = int.from_bytes(data[i+3:i+7], "little", signed=True)
                insn_va = image_base + base + i
                ref = insn_va + 7 + disp
                if ref == image_base + target_rva:
                    refs.append(base + i)
                i += 7
            else:
                i += 1
    return refs

for rva in (0x52360, 0x523E4):
    refs = find_rip_refs(rva)
    print("  refs to %08X: %s" % (rva, ["%08X" % r for r in refs]))

print("\n== disasm the function containing the first 'BugCheck' string ref ==")
# walk disasm of DISP and find the call target whose body has a lea to 0x52360
def insn_hex(va_, n=16):
    return read(va_rva(va_), n).hex(" ")

# For each unique call target, check its first 0x400 bytes for refs to the strings
for t, m, a in uniq:
    found = []
    for ins in disasm(t, 0x400):
        if ins.mnemonic == "lea" and ins.operands and ins.operands[0].type == 3:
            op = ins.operands[0]
            if op.mem.base == 0 and op.mem.index == 0:
                # [rip + disp] style
                target = ins.address + ins.size + op.mem.disp
                if target in (image_base + 0x52360, image_base + 0x523E4):
                    found.append((ins.address, target))
    if found:
        print("  %016X references BugCheck strings: %s" % (t, ["%016X->%016X" % f for f in found]))
