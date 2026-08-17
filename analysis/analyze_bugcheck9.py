#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Part 9: final verification of display candidates + wrapper pattern."""
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

print("== 0x140B63540: does it end with ret or spin? scan 0x7000 for ret/pause/hlt ==")
found_ret = 0
for i in disasm(0x140B63540, 0x7000):
    if i.mnemonic in ("ret", "retn") and found_ret < 12:
        print("  ret at %016X" % i.address)
        found_ret += 1
    if i.mnemonic == "hlt":
        print("  hlt at %016X" % i.address)
    if i.mnemonic == "pause":
        print("  pause at %016X" % i.address)
print("  rets found:", found_ret)

print("\n== 0x140B63540 last 0x80 bytes of its body (before next fn) ==")
# find first function-end: ret followed by cc padding
data_all = read(rva(0x140B63540), 0x8000)
# find "cc cc cc cc" after a ret
idx = 0
for i in range(len(data_all) - 8):
    if data_all[i] in (0xC3, 0xCB) and data_all[i+1:i+5] == b"\xcc\xcc\xcc\xcc":
        print("  first ret+padding at offset 0x%X (VA %016X)" % (i, 0x140B63540 + i))
        idx = i
        break

print("\n== around KeBugCheckEx call inside 0x140B63540: 0x140B63B80..0x140B63C40 ==")
for i in disasm(0x140B63B80, 0xC0):
    print("  %016X: %-8s %s" % (i.address, i.mnemonic, i.op_str))

print("\n== around CR0 area: 0x140B651E0..0x140B65260 ==")
for i in disasm(0x140B651E0, 0x80):
    print("  %016X: %-8s %s" % (i.address, i.mnemonic, i.op_str))

print("\n== xrefs to text helpers 0x1404FE52C / 0x1404FEF58 / 0x1404FB208 ==")
for h in (0x1404FE52C, 0x1404FEF58, 0x1404FB208):
    refs = find_xrefs(h)
    print("  %016X: %d refs -> %s" % (h, len(refs), ["%016X" % r[0] for r in refs[:20]]))

print("\n== wrapper 0x1404FA9F0 raw bytes (0x30) ==")
print(" ", read(rva(0x1404FA9F0), 0x30).hex(" "))

print("\n== KeBugCheck2 prologue raw bytes (0x40) ==")
print(" ", read(rva(0x1405AE6F0), 0x40).hex(" "))

print("\n== dispatcher 0x1404FA160 raw bytes (0x20) ==")
print(" ", read(rva(0x1404FA160), 0x20).hex(" "))

print("\n== who calls dump-writer 0x1405971E8? ==")
refs = find_xrefs(0x1405971E8)
print("  %d refs: %s" % (len(refs), ["%016X" % r[0] for r in refs[:20]]))

print("\n== who calls wrapper 0x1404FA9F0? indirect-search: any 'call rax/rcx/r11' near? ==")
# scan .text for FF D0 (call rax) / FF D1 (call rcx) / 41 FF D3 (call r11) — too broad, skip.
# instead: check region before wrapper for possible table refs to 0x1404FA9F0 RVA
rva_w = rva(0x1404FA9F0)
hits = []
for sec in pe.sections:
    data = sec.get_data()
    # qword pointer to rva_w (image base + rva_w)
    import struct
    needle = struct.pack("<Q", image_base + rva_w)
    idx = 0
    while True:
        idx = data.find(needle, idx)
        if idx < 0:
            break
        hits.append((sec.VirtualAddress + idx, sec.Name.decode().strip('\x00')))
        idx += 1
print("  qword refs to wrapper VA:", hits[:10])
