#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Part 12: simulate the driver's resolution logic against real ntoskrnl.exe.
Verifies that the byte-level scan code written in driver.c finds:
  - KeBugCheck2    -> 0x1405AE6F0
  - KiBugCheckDispatch-ish -> 0x1404FA160
  - KiDisplayBlueScreen-ish -> 0x140B63540
"""
import pefile

NTOS = r"C:\Windows\System32\ntoskrnl.exe"
pe = pefile.PE(NTOS, fast_load=False)
image_base = pe.OPTIONAL_HEADER.ImageBase

def rva(x): return x - image_base
def read(rva_, n): return pe.get_data(rva_, n)

exports = {e.name.decode(): e.address for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name}
KBCEX = image_base + exports["KeBugCheckEx"]
print("KeBugCheckEx = 0x%016X (RVA %08X)" % (KBCEX, exports["KeBugCheckEx"]))

def scan_for_call(code_va, length, match_fn, self_va, label):
    data = read(rva(code_va), length)
    i = 0
    while i + 5 <= len(data):
        if data[i] in (0xE8, 0xE9):
            disp = int.from_bytes(data[i+1:i+5], "little", signed=True)
            target = code_va + i + 5 + disp
            if target < self_va - 0x2000000 or target > self_va + 0x2000000:
                i += 1
                continue
            if match_fn(target):
                print("  [%s] found %016X at offset +0x%X (opcode %s)"
                      % (label, target, i, "E8" if data[i] == 0xE8 else "E9"))
                return target
        i += 1
    print("  [%s] NOT FOUND" % label)
    return 0

def is_kebugcheck2_prologue(va):
    p = read(rva(va), 16)
    if p[:5] == bytes([0x48, 0x89, 0x5C, 0x24, 0x08]):
        return True
    sig = bytes([0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57])
    for i in range(16 - len(sig) + 1):
        if p[i:i+len(sig)] == sig:
            return True
    return False

def is_dispatch_prologue(va):
    p = read(rva(va), 6)
    return p[:6] == bytes([0x48, 0x9C, 0x48, 0x89, 0x41, 0x78])

print("\n== scan KeBugCheckEx body (0x150 bytes) ==")
kbc2 = scan_for_call(KBCEX, 0x150, is_kebugcheck2_prologue, KBCEX, "KeBugCheck2")
disp = scan_for_call(KBCEX, 0x150, is_dispatch_prologue, KBCEX, "Dispatch")

print("\n== scan for wrapper after dispatch (window 0x100..0x2000) ==")
pat = bytes([0x89, 0x4C, 0x24, 0x20, 0x9C, 0x48, 0x83, 0xEC, 0x30])
if disp:
    data = read(rva(disp), 0x2000)
    matches = []
    idx = 0x100
    while True:
        idx = data.find(pat, idx)
        if idx < 0:
            break
        matches.append(idx)
        idx += 1
    if matches:
        print("  wrapper-pattern matches at: " + ", ".join(["dispatch+0x%X" % m for m in matches]))
    else:
        print("  wrapper-pattern matches: none")
    if matches:
        wrapper = disp + matches[0]
        print("  wrapper = 0x%016X" % wrapper)
        # find the last E8 call BEFORE the first ret (0xC3) in the wrapper body
        wdata = read(rva(wrapper), 0x180)
        first_ret = wdata.find(b"\xc3")
        print("  first ret at +0x%X" % first_ret)
        last = None
        i = 0
        limit = first_ret if first_ret >= 0 else len(wdata)
        while i + 5 <= limit:
            if wdata[i] in (0xE8, 0xE9):
                d = int.from_bytes(wdata[i+1:i+5], "little", signed=True)
                t = wrapper + i + 5 + d
                if t < wrapper - 0x2000000 or t > wrapper + 0x2000000:
                    i += 1
                    continue
                print("    call at +0x%X -> 0x%016X" % (i, t))
                last = t
            i += 1
        if last:
            print("  => DISPLAY target = 0x%016X" % last)

print("\n== verify: KeBugCheck2 prologue bytes ==")
print("  0x%016X: %s" % (kbc2, read(rva(kbc2), 32).hex(" ")) if kbc2 else "  n/a")
print("  dispatch prologue bytes:")
print("  0x%016X: %s" % (disp, read(rva(disp), 32).hex(" ")) if disp else "  n/a")
