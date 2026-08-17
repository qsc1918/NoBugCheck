#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Scan all major ntoskrnl versions for bugcheck hook targets.
Improved: stops scanning at function boundary (ret+padding), expanded prologue checks.
"""
import os, struct
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

MAJOR_DIR = r"D:\nt\ntoskrnl_major_versions"
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

def read_bytes(pe, va, n):
    return pe.get_data(va - pe.OPTIONAL_HEADER.ImageBase, n)

def find_function_end(pe, func_va, max_scan=0x600):
    """Find function end: look for ret (0xC3) followed by int3 (0xCC) or another ret."""
    data = read_bytes(pe, func_va, max_scan)
    for i in range(1, len(data) - 1):
        if data[i] == 0xC3 and data[i+1] in (0xCC, 0xC3, 0x90):
            return func_va + i + 1
    return func_va + max_scan  # fallback

def is_kebugcheck2_prologue(pe, va):
    """Check if function at va looks like KeBugCheck2."""
    p = read_bytes(pe, va, 20)
    # Pattern 1 (Win10 + Win11 22H2): mov [rsp+8], rbx
    if p[:5] == bytes([0x48, 0x89, 0x5C, 0x24, 0x08]):
        return True
    # Pattern 2 (Win11 24H2+): 8 pushes (rbp,rbx,rsi,rdi,r12..r15)
    sig = bytes([0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57])
    for i in range(16 - len(sig) + 1):
        if p[i:i+len(sig)] == sig:
            return True
    # Pattern 3 (Win11 21H2 build 22000): push rbx; sub rsp, 0xD0 or similar large frame
    # Also: mov [rsp+8], rcx (common wrapper start)
    if p[:5] == bytes([0x48, 0x89, 0x4C, 0x24, 0x08]):
        # Check if next instruction also looks like arg save
        if p[5:10] == bytes([0x48, 0x89, 0x54, 0x24, 0x10]):
            return True
    return False

def is_dispatch_prologue(pe, va):
    """pushfq; mov [rcx+78h], rax"""
    p = read_bytes(pe, va, 6)
    return p[:6] == bytes([0x48, 0x9C, 0x48, 0x89, 0x41, 0x78])

def is_kisave_prologue(pe, va):
    """KiSaveProcessorControlState: mov rax, cr0; mov [rcx], rax"""
    p = read_bytes(pe, va, 4)
    return p[:4] == bytes([0x0F, 0x20, 0xC0, 0x48])

def scan_calls_in_function(pe, func_va, func_end):
    """Scan func_va..func_end for E8/E9 call targets."""
    length = func_end - func_va
    data = read_bytes(pe, func_va, length)
    calls = []
    i = 0
    while i + 5 <= len(data):
        if data[i] in (0xE8, 0xE9):
            disp = struct.unpack_from('<i', data, i+1)[0]
            target = func_va + i + 5 + disp
            ib = pe.OPTIONAL_HEADER.ImageBase
            if target >= ib and target <= ib + 0x2000000:
                calls.append((func_va + i, data[i], target))
        i += 1
    return calls

def find_display_target(pe, dispatch_va):
    """Scan after dispatch for wrapper pattern, return last call before ret."""
    WRAPPER_SIG = bytes([0x89, 0x4C, 0x24, 0x20, 0x9C, 0x48, 0x83, 0xEC, 0x30])
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

def analyze_file(path):
    pe = pefile.PE(path, fast_load=False)
    ib = pe.OPTIONAL_HEADER.ImageBase
    exports = {e.name.decode(): e.address for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name}

    result = {"file": os.path.basename(path), "image_base": ib}

    try:
        ffi = pe.VS_FIXEDFILEINFO[0]
        result["version"] = "%d.%d.%d.%d" % (ffi.FileVersionMS >> 16, ffi.FileVersionMS & 0xFFFF,
                                              ffi.FileVersionLS >> 16, ffi.FileVersionLS & 0xFFFF)
        result["build"] = ffi.FileVersionLS >> 16
    except:
        result["version"] = "?"
        result["build"] = 0

    kbcx_rva = exports.get("KeBugCheckEx")
    if not kbcx_rva:
        result["error"] = "KeBugCheckEx not exported"
        return result
    kbcx_va = ib + kbcx_rva
    result["KeBugCheckEx"] = "0x%x" % kbcx_va
    result["_kbcx_rva"] = kbcx_rva

    # Find function boundary
    kbcx_end = find_function_end(pe, kbcx_va)
    result["kbcx_size"] = kbcx_end - kbcx_va

    # Scan calls within KeBugCheckEx function
    calls = scan_calls_in_function(pe, kbcx_va, kbcx_end)
    result["call_count"] = len(calls)

    # Classify
    dispatch_va = 0
    kbc2_va = 0
    kisave_va = 0
    classified = []

    for src, opcode, tgt in calls:
        call_type = "?"
        if is_dispatch_prologue(pe, tgt):
            call_type = "Dispatch"
            if not dispatch_va:
                dispatch_va = tgt
        elif is_kisave_prologue(pe, tgt):
            call_type = "KiSaveProcCtrl"
            kisave_va = tgt
        elif is_kebugcheck2_prologue(pe, tgt):
            call_type = "KeBugCheck2"
            if not kbc2_va:
                kbc2_va = tgt
        else:
            pro = read_bytes(pe, tgt, 6).hex(" ")
            call_type = f"unknown({pro})"

        classified.append((src, opcode, tgt, call_type))

    result["classified_calls"] = classified
    result["Dispatch"] = "0x%x" % dispatch_va if dispatch_va else "NOT_FOUND"
    result["KeBugCheck2"] = "0x%x" % kbc2_va if kbc2_va else "NOT_FOUND"
    result["KiSaveProcCtrl"] = "0x%x" % kisave_va if kisave_va else "NOT_FOUND"

    # If KeBugCheck2 not found by prologue, try: among calls that are NOT dispatch/kisave,
    # pick the one with the most arguments (the call with highest offset is usually KeBugCheck2)
    if not kbc2_va:
        unknown = [(src, op, tgt) for src, op, tgt, t in classified if t.startswith("unknown")]
        if unknown:
            # The last unknown call from KeBugCheckEx is likely KeBugCheck2
            last_src, last_op, last_tgt = unknown[-1]
            kbc2_va = last_tgt
            result["KeBugCheck2"] = "0x%x (fallback)" % kbc2_va

    # Display
    display_va = 0
    if dispatch_va:
        display_va = find_display_target(pe, dispatch_va)
    result["Display"] = "0x%x" % display_va if display_va else "NOT_FOUND"

    return result

# Main
files = sorted([f for f in os.listdir(MAJOR_DIR) if f.endswith(".exe")])
print("Found %d major ntoskrnl versions\n" % len(files))

all_ok = 0
for fn in files:
    path = os.path.join(MAJOR_DIR, fn)
    try:
        r = analyze_file(path)
    except Exception as e:
        print("%-42s ERROR: %s" % (fn, e))
        continue

    build = r.get("build", "?")
    ver = r.get("version", "?")
    kbc2 = r.get("KeBugCheck2", "?")
    disp = r.get("Dispatch", "?")
    dsp  = r.get("Display", "?")
    size = r.get("kbcx_size", 0)

    ok = "NOT_FOUND" not in kbc2 and "NOT_FOUND" not in disp and "NOT_FOUND" not in dsp
    all_ok += ok
    status = "OK" if ok else "PARTIAL"

    print("%-42s build=%-6s KBC2=%-20s Disp=%-14s Dsp=%-14s size=0x%x [%s]" % (
        fn, build, kbc2, disp, dsp, size, status))

    # Show classified calls
    for src, op, tgt, ct in r.get("classified_calls", []):
        opcode = "call" if op == 0xE8 else "jmp"
        kbcx_base = r["image_base"] + r.get("_kbcx_rva", 0)
        print("    %s KeBugCheckEx+0x%x -> 0x%x (%s)" % (opcode, src - kbcx_base, tgt, ct))
    print()

print("=== Summary: %d/%d versions have all 4 hooks ===" % (all_ok, len(files)))
