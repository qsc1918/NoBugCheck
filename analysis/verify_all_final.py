#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Final verification: simulate the UPDATED driver's resolution logic against
all 31 major ntoskrnl versions.  Uses the same algorithm as driver.c:
  1. Find function end (ret+cc boundary)
  2. Scan for Dispatch (pushfq prologue)
  3. Scan for KeBugCheck2 (3 prologue patterns)
  4. Fallback: last E8 call that isn't Dispatch or KiSaveProcCtrl
  5. Display: wrapper pattern scan
"""
import os, struct
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

MAJOR_DIR = r"D:\nt\ntoskrnl_major_versions"
md = Cs(CS_ARCH_X86, CS_MODE_64)

def read_bytes(pe, va, n):
    return pe.get_data(va - pe.OPTIONAL_HEADER.ImageBase, n)

def find_function_end(pe, func_va, max_scan=0x400):
    data = read_bytes(pe, func_va, max_scan)
    for i in range(1, len(data) - 1):
        if data[i] == 0xC3 and data[i+1] in (0xCC, 0x90, 0xC3):
            return i + 1
    return max_scan

def is_kebugcheck2(pe, va):
    p = read_bytes(pe, va, 20)
    if p[:5] == bytes([0x48, 0x89, 0x5C, 0x24, 0x08]):
        return True
    if p[:5] == bytes([0x48, 0x89, 0x5C, 0x24, 0x18]):
        return True
    sig = bytes([0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57])
    for i in range(16 - len(sig) + 1):
        if p[i:i+len(sig)] == sig:
            return True
    return False

def is_dispatch(pe, va):
    p = read_bytes(pe, va, 6)
    return p[:6] == bytes([0x48, 0x9C, 0x48, 0x89, 0x41, 0x78])

def is_kisave(pe, va):
    p = read_bytes(pe, va, 4)
    return p[:4] == bytes([0x0F, 0x20, 0xC0, 0x48])

WRAPPER_SIG = bytes([0x89, 0x4C, 0x24, 0x20, 0x9C, 0x48, 0x83, 0xEC, 0x30])

def find_display(pe, dispatch_va):
    data = read_bytes(pe, dispatch_va, 0x3000)
    idx = data.find(WRAPPER_SIG, 0x100)
    if idx < 0:
        return 0
    wrapper_va = dispatch_va + idx
    body = read_bytes(pe, wrapper_va, 0x180)
    first_ret = body.find(b"\xc3")
    if first_ret < 0:
        first_ret = len(body)
    last_call = 0
    for j in range(first_ret - 4):
        if body[j] in (0xE8, 0xE9):
            d = struct.unpack_from('<i', body, j+1)[0]
            t = wrapper_va + j + 5 + d
            if t >= wrapper_va - 0x2000000 and t <= wrapper_va + 0x2000000:
                last_call = t
    return last_call

def analyze(path):
    pe = pefile.PE(path, fast_load=False)
    ib = pe.OPTIONAL_HEADER.ImageBase
    exports = {e.name.decode(): e.address for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name}
    kbcx_rva = exports.get("KeBugCheckEx")
    if not kbcx_rva:
        return None
    kbcx_va = ib + kbcx_rva

    # 1. Function boundary
    func_size = find_function_end(pe, kbcx_va)

    # 2. Scan calls within function
    data = read_bytes(pe, kbcx_va, func_size)
    calls = []
    i = 0
    while i + 5 <= len(data):
        if data[i] in (0xE8, 0xE9):
            disp = struct.unpack_from('<i', data, i+1)[0]
            target = kbcx_va + i + 5 + disp
            if target >= ib and target <= ib + 0x2000000:
                calls.append((kbcx_va + i, target))
        i += 1

    # 3. Classify
    dispatch_va = 0
    kbc2_va = 0
    for src, tgt in calls:
        if is_dispatch(pe, tgt) and not dispatch_va:
            dispatch_va = tgt
        if is_kebugcheck2(pe, tgt) and not kbc2_va:
            kbc2_va = tgt

    # 4. Fallback for KeBugCheck2
    if not kbc2_va:
        last = 0
        for src, tgt in calls:
            if is_dispatch(pe, tgt) or is_kisave(pe, tgt) or tgt == dispatch_va:
                continue
            last = tgt
        kbc2_va = last

    # 5. Display
    display_va = find_display(pe, dispatch_va) if dispatch_va else 0

    return {
        "file": os.path.basename(path),
        "kbcx": kbcx_va,
        "func_size": func_size,
        "dispatch": dispatch_va,
        "kbc2": kbc2_va,
        "display": display_va,
        "call_count": len(calls),
        "calls": calls,
    }

# Run
files = sorted([f for f in os.listdir(MAJOR_DIR) if f.endswith(".exe")])
ok_count = 0
for fn in files:
    path = os.path.join(MAJOR_DIR, fn)
    try:
        r = analyze(path)
    except Exception as e:
        print(f"{fn:42s} ERROR: {e}")
        continue
    if not r:
        print(f"{fn:42s} NO KeBugCheckEx")
        continue

    ok = r["kbc2"] and r["dispatch"] and r["display"]
    ok_count += ok
    status = "OK" if ok else "FAIL"

    print(f"{fn:42s} size=0x{r['func_size']:03x}  "
          f"KBC2={'0x%x' % r['kbc2'] if r['kbc2'] else 'NONE':20s} "
          f"DISP={'0x%x' % r['dispatch'] if r['dispatch'] else 'NONE':14s} "
          f"DSP={'0x%x' % r['display'] if r['display'] else 'NONE':14s} "
          f"[{status}]")

print(f"\n=== {ok_count}/{len(files)} versions OK ===")
