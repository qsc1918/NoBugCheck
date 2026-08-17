#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Scan all major ntoskrnl versions for bugcheck hook targets.
For each version, resolves:
  - KeBugCheckEx (exported)
  - KeBugCheck2 (call-scan from KeBugCheckEx)
  - Dispatch/context-save (pushfq prologue call from KeBugCheckEx)
  - Display (wrapper pattern after dispatch, last call before ret)
Also detects classic vs 24H2+ architecture.
"""
import os, sys, struct
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM

MAJOR_DIR = r"D:\nt\ntoskrnl_major_versions"
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

def read_bytes(pe, va, n):
    rva = va - pe.OPTIONAL_HEADER.ImageBase
    return pe.get_data(rva, n)

def is_kebugcheck2_prologue(pe, va):
    p = read_bytes(pe, va, 20)
    # classic: mov [rsp+8], rbx
    if p[:5] == bytes([0x48, 0x89, 0x5C, 0x24, 0x08]):
        return True
    # 24H2+: 8 pushes
    sig = bytes([0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57])
    for i in range(16 - len(sig) + 1):
        if p[i:i+len(sig)] == sig:
            return True
    return False

def is_dispatch_prologue(pe, va):
    p = read_bytes(pe, va, 6)
    return p[:6] == bytes([0x48, 0x9C, 0x48, 0x89, 0x41, 0x78])

def find_call_target(pe, code_va, length, check_fn, self_va, window=0x2000000):
    data = read_bytes(pe, code_va, length)
    i = 0
    while i + 5 <= len(data):
        if data[i] in (0xE8, 0xE9):
            disp = struct.unpack_from('<i', data, i+1)[0]
            target = code_va + i + 5 + disp
            if target >= self_va - window and target <= self_va + window:
                if check_fn(pe, target):
                    return target
        i += 1
    return 0

def find_display_target(pe, dispatch_va):
    """Scan after dispatch fn for wrapper pattern, return last call target."""
    WRAPPER_SIG = bytes([0x89, 0x4C, 0x24, 0x20, 0x9C, 0x48, 0x83, 0xEC, 0x30])
    data = read_bytes(pe, dispatch_va, 0x3000)
    idx = data.find(WRAPPER_SIG, 0x100)
    if idx < 0:
        return 0
    wrapper_va = dispatch_va + idx
    # find last E8 call before first C3
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

def analyze_file(path):
    pe = pefile.PE(path, fast_load=False)
    ib = pe.OPTIONAL_HEADER.ImageBase

    # Find exports
    exports = {}
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name:
            exports[exp.name.decode()] = exp.address  # RVA

    result = {"file": os.path.basename(path), "image_base": ib}

    # Version info
    try:
        ffi = pe.VS_FIXEDFILEINFO[0]
        ver = "%d.%d.%d.%d" % (ffi.FileVersionMS >> 16, ffi.FileVersionMS & 0xFFFF,
                                ffi.FileVersionLS >> 16, ffi.FileVersionLS & 0xFFFF)
        result["version"] = ver
    except:
        result["version"] = "?"

    # KeBugCheckEx
    kbcx_rva = exports.get("KeBugCheckEx")
    if not kbcx_rva:
        result["error"] = "KeBugCheckEx not exported"
        return result
    kbcx_va = ib + kbcx_rva
    result["KeBugCheckEx"] = "0x%x" % kbcx_va

    # KeBugCheck
    kbc_rva = exports.get("KeBugCheck")
    if kbc_rva:
        result["KeBugCheck"] = "0x%x" % (ib + kbc_rva)

    # Scan KeBugCheckEx body for E8/E9 calls
    data = read_bytes(pe, kbcx_va, 0x200)
    calls = []
    i = 0
    while i + 5 <= len(data):
        if data[i] in (0xE8, 0xE9):
            disp = struct.unpack_from('<i', data, i+1)[0]
            target = kbcx_va + i + 5 + disp
            if target >= ib and target <= ib + 0x2000000:
                calls.append((kbcx_va + i, target))
        i += 1

    # Classify calls
    kbc2_va = 0
    dispatch_va = 0
    for src, tgt in calls:
        if is_kebugcheck2_prologue(pe, tgt) and not kbc2_va:
            kbc2_va = tgt
        if is_dispatch_prologue(pe, tgt) and not dispatch_va:
            dispatch_va = tgt

    if kbc2_va:
        result["KeBugCheck2"] = "0x%x" % kbc2_va
        pro = read_bytes(pe, kbc2_va, 12).hex(" ")
        result["kbc2_prologue"] = pro
    else:
        result["KeBugCheck2"] = "NOT_FOUND"

    if dispatch_va:
        result["Dispatch"] = "0x%x" % dispatch_va
    else:
        result["Dispatch"] = "NOT_FOUND"

    # Display
    display_va = 0
    if dispatch_va:
        display_va = find_display_target(pe, dispatch_va)
    if display_va:
        result["Display"] = "0x%x" % display_va
    else:
        result["Display"] = "NOT_FOUND"

    # KeBugCheckEx call targets (for debugging)
    call_list = []
    for src, tgt in calls:
        pro = read_bytes(pe, tgt, 6).hex()
        call_list.append("0x%x->0x%x(%s)" % (src, tgt, pro))
    result["calls"] = call_list

    return result

# Main
files = sorted([f for f in os.listdir(MAJOR_DIR) if f.endswith(".exe")])
print("Found %d major ntoskrnl versions\n" % len(files))
print("%-40s %-20s %-18s %-18s %-18s %-18s" % (
    "File", "Version", "KeBugCheckEx", "KeBugCheck2", "Dispatch", "Display"))
print("-" * 140)

for fn in files:
    path = os.path.join(MAJOR_DIR, fn)
    try:
        r = analyze_file(path)
    except Exception as e:
        print("%-40s ERROR: %s" % (fn, e))
        continue

    ver = r.get("version", "?")
    kbcx = r.get("KeBugCheckEx", "?")
    kbc2 = r.get("KeBugCheck2", "?")
    disp = r.get("Dispatch", "?")
    dsp  = r.get("Display", "?")

    print("%-40s %-20s %-18s %-18s %-18s %-18s" % (fn, ver, kbcx, kbc2, disp, dsp))

    # Print extra detail for each
    if "calls" in r:
        for c in r["calls"]:
            print("    %s" % c)
    if "kbc2_prologue" in r:
        print("    kbc2_prologue: %s" % r["kbc2_prologue"])
    print()
