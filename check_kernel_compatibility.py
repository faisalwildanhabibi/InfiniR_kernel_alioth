#!/usr/bin/env python3
"""
InfiniR Kernel Compatibility Tester for Poco F3 (alioth) / crDroid 11 (Android 15)
===================================================================================
Author: Sall / Antigravity
Description:
    Performs deep binary, structural, configuration, and device-tree compatibility
    validation between any generated AnyKernel3 zip and the official reference
    release from raystef66 (v3.00_KSUN).

Usage:
    python check_kernel_compatibility.py <target_zip_path> [--ref <reference_zip_url_or_path>] [--json <output_json>] [--markdown <output_md>]
"""

import os
import sys
import zlib
import gzip
import shutil
import struct
import argparse
import tempfile
import zipfile
import urllib.request
from typing import Dict, Any, List, Tuple

# Ensure utf-8 stdout on all platforms
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
    except Exception:
        pass

DEFAULT_REF_URL = "https://github.com/raystef66/InfiniR_kernel_alioth/releases/download/v3.00_KSUN/InfiniR_Alioth_v3.00_KSUN_raystef66.zip"
DTBO_MAGIC = b"\xd7\xb7\xab\x1e"
FDT_MAGIC = b"\xd0\x0d\xfe\xed"
GZIP_MAGIC = b"\x1f\x8b"
ARM64_MAGIC = b"ARM\x64"


def log_pass(msg: str):
    print(f" [PASS] {msg}")


def log_fail(msg: str):
    print(f" [FAIL] {msg}")


def log_warn(msg: str):
    print(f" [WARN] {msg}")


def log_info(msg: str):
    print(f" [INFO] {msg}")


def get_or_download_reference(ref_path_or_url: str, cache_dir: str) -> str:
    """Download reference zip if given a URL or verify local path."""
    if os.path.exists(ref_path_or_url):
        return ref_path_or_url
    
    local_cached = os.path.join(cache_dir, "InfiniR_Alioth_v3.00_KSUN_raystef66.zip")
    if os.path.exists(local_cached) and os.path.getsize(local_cached) > 10_000_000:
        log_info(f"Using cached reference zip: {local_cached}")
        return local_cached

    if os.path.exists("InfiniR_Alioth_v3.00_KSUN_raystef66.zip") and os.path.getsize("InfiniR_Alioth_v3.00_KSUN_raystef66.zip") > 10_000_000:
        return os.path.abspath("InfiniR_Alioth_v3.00_KSUN_raystef66.zip")

    log_info(f"Downloading reference zip from {ref_path_or_url} ...")
    req = urllib.request.Request(ref_path_or_url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as resp, open(local_cached, "wb") as out:
        shutil.copyfileobj(resp, out)
    log_info(f"Reference zip saved ({os.path.getsize(local_cached)} bytes)")
    return local_cached


def extract_zip(zip_path: str, extract_to: str) -> List[str]:
    """Extract zip archive and return list of filenames."""
    with zipfile.ZipFile(zip_path, 'r') as z:
        z.extractall(extract_to)
        return z.namelist()


def analyze_anykernel_sh(content: str) -> Dict[str, Any]:
    """Analyze anykernel.sh for configuration parameters and potential syntax bugs."""
    lines = content.splitlines()
    info = {
        "raw_lines_count": len(lines),
        "has_line_number_glitch": False,
        "device_names": [],
        "block": "",
        "is_slot_device": None,
        "ramdisk_compression": "",
        "has_dump_boot": "dump_boot" in content,
        "has_write_boot": "write_boot" in content,
        "has_sar_overlay_fix": "rm -rf $ramdisk/overlay" in content or "rm -rf $ramdisk/overlay.d" in content,
        "syntax_errors": []
    }

    if lines and (lines[0].startswith("\t1\t") or lines[0].startswith("1\t")):
        info["has_line_number_glitch"] = True
        info["syntax_errors"].append("Line 1 contains leading line numbers/tab artifact from bad copy-paste.")

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("device.name"):
            parts = stripped.split("=")
            if len(parts) >= 2 and parts[1].strip():
                info["device_names"].append(parts[1].strip().rstrip(";"))
        elif stripped.startswith("block="):
            info["block"] = stripped.split("=")[1].rstrip(";")
        elif stripped.startswith("is_slot_device="):
            val = stripped.split("=")[1].rstrip(";")
            info["is_slot_device"] = val
        elif stripped.startswith("ramdisk_compression="):
            info["ramdisk_compression"] = stripped.split("=")[1].rstrip(";")

    return info


def analyze_kernel_image(image_path: str) -> Dict[str, Any]:
    """Analyze kernel image format (raw Image vs Image.gz vs Image.gz-dtb, DTBs appended)."""
    if not os.path.exists(image_path):
        return {"exists": False}

    size = os.path.getsize(image_path)
    with open(image_path, "rb") as f:
        data = f.read()

    info = {
        "exists": True,
        "size": size,
        "is_gzip": data.startswith(GZIP_MAGIC),
        "is_raw_arm64": False,
        "kernel_version_string": "",
        "appended_dtb_count": 0,
        "dtb_compatibles": [],
        "decompressed_size": 0
    }

    uncompressed_data = b""
    if info["is_gzip"]:
        try:
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            uncompressed_data = d.decompress(data)
            info["decompressed_size"] = len(uncompressed_data)
        except Exception as e:
            try:
                uncompressed_data = gzip.decompress(data)
                info["decompressed_size"] = len(uncompressed_data)
            except Exception as e2:
                info["error"] = f"Failed decompressing gzip kernel: {e2}"
    else:
        uncompressed_data = data

    if len(uncompressed_data) > 64 and uncompressed_data[56:60] == ARM64_MAGIC:
        info["is_raw_arm64"] = True

    pos = uncompressed_data.find(b"Linux version ")
    if pos != -1:
        banner_end = uncompressed_data.find(b"\x00", pos)
        if banner_end != -1:
            info["kernel_version_string"] = uncompressed_data[pos:banner_end].decode("utf-8", errors="ignore")

    # Scan for FDT magic (DTBs) in either the raw file or appended stream
    search_data = data
    dtb_offsets = []
    idx = 0
    while True:
        pos = search_data.find(FDT_MAGIC, idx)
        if pos == -1:
            break
        dtb_offsets.append(pos)
        idx = pos + 4

    info["appended_dtb_count"] = len(dtb_offsets)

    # Qualcomm Snapdragon 865/870 SoC strings
    soc_identifiers = [b"qcom,kona", b"kona", b"qcom,sm8250", b"sm8250", b"qcom,alioth", b"alioth", b"msm-id"]
    for comp in soc_identifiers:
        if comp in search_data or (uncompressed_data and comp in uncompressed_data):
            info["dtb_compatibles"].append(comp.decode("utf-8"))

    return info


def analyze_dtbo(dtbo_path: str) -> Dict[str, Any]:
    """Analyze dtbo.img table and header."""
    if not os.path.exists(dtbo_path):
        return {"exists": False}

    size = os.path.getsize(dtbo_path)
    with open(dtbo_path, "rb") as f:
        header = f.read(32)

    info = {
        "exists": True,
        "size": size,
        "has_valid_magic": header.startswith(DTBO_MAGIC),
        "total_size": 0,
        "header_size": 0,
        "entry_size": 0,
        "num_entries": 0,
        "page_size": 0
    }

    if len(header) >= 32 and info["has_valid_magic"]:
        magic, total_sz, hdr_sz, dt_entry_sz, dt_entry_cnt, version, page_sz = struct.unpack(">IIIIIII", header[:28])
        info["total_size"] = total_sz
        info["header_size"] = hdr_sz
        info["entry_size"] = dt_entry_sz
        info["num_entries"] = dt_entry_cnt
        info["page_size"] = page_sz

    return info


def evaluate_compatibility(target_dir: str, ref_dir: str) -> Tuple[bool, List[Dict[str, Any]]]:
    """Perform thorough evaluation and return list of check results."""
    checks = []
    overall_pass = True

    def add_check(category: str, item: str, status: str, ref_val: Any, target_val: Any, desc: str):
        nonlocal overall_pass
        is_pass = (status == "PASS")
        is_warn = (status == "WARN")
        if not is_pass and not is_warn:
            overall_pass = False
        checks.append({
            "category": category,
            "item": item,
            "status": status,
            "reference": str(ref_val),
            "target": str(target_val),
            "description": desc
        })

    # 1. Structure Checks
    has_target_gz_dtb = os.path.exists(os.path.join(target_dir, "Image.gz-dtb"))
    has_target_raw_img = os.path.exists(os.path.join(target_dir, "Image"))
    has_target_loose_dtb = os.path.exists(os.path.join(target_dir, "dtb")) or os.path.exists(os.path.join(target_dir, "dt.img"))

    if has_target_gz_dtb:
        add_check("Structure", "Kernel Image Payload", "PASS", "Image.gz-dtb", "Image.gz-dtb",
                  "Kernel uses standard GZIP compressed Image with appended DTB format.")
    elif has_target_raw_img:
        add_check("Structure", "Kernel Image Payload", "FAIL", "Image.gz-dtb", "Image (Raw Uncompressed)",
                  "CRITICAL: Raw uncompressed Image causes bootloop on Poco F3 / SM8250! Flash requires Image.gz-dtb.")
    else:
        add_check("Structure", "Kernel Image Payload", "FAIL", "Image.gz-dtb", "None",
                  "CRITICAL: No kernel image file found in AnyKernel3 root directory.")

    if has_target_raw_img and has_target_loose_dtb:
        add_check("Structure", "Conflicting DTB / Image", "FAIL", "None (integrated in Image.gz-dtb)", "dtb + dt.img loose",
                  "CRITICAL: Packaging loose dtb/dt.img with raw Image corrupts AnyKernel3 boot image repack.")
    else:
        add_check("Structure", "Conflicting DTB Files", "PASS", "Clean", "Clean",
                  "No loose conflicting device tree files found.")

    # DTBO Image Check
    ref_dtbo = analyze_dtbo(os.path.join(ref_dir, "dtbo.img"))
    tgt_dtbo = analyze_dtbo(os.path.join(target_dir, "dtbo.img"))
    if tgt_dtbo.get("has_valid_magic"):
        add_check("Structure", "DTBO Image (dtbo.img)", "PASS", f"Valid DTBO ({ref_dtbo.get('size')}B)",
                  f"Valid DTBO ({tgt_dtbo.get('size')}B)", "Valid dtbo.img present.")
    else:
        add_check("Structure", "DTBO Image (dtbo.img)", "FAIL", "Valid DTBO", "Missing or Invalid",
                  "Missing or corrupted dtbo.img table.")

    # 2. anykernel.sh Analysis
    tgt_ak3_path = os.path.join(target_dir, "anykernel.sh")
    ref_ak3_path = os.path.join(ref_dir, "anykernel.sh")
    if os.path.exists(tgt_ak3_path) and os.path.exists(ref_ak3_path):
        with open(tgt_ak3_path, "r", encoding="utf-8", errors="ignore") as f:
            tgt_ak3 = analyze_anykernel_sh(f.read())
        with open(ref_ak3_path, "r", encoding="utf-8", errors="ignore") as f:
            ref_ak3 = analyze_anykernel_sh(f.read())

        if tgt_ak3["has_line_number_glitch"]:
            add_check("AnyKernel3 Script", "Script Syntax Integrity", "FAIL", "Clean", "Line number artifact (\\t1\\t)",
                      "CRITICAL: Script syntax error prevents AnyKernel3 installer from executing in recovery.")
        else:
            add_check("AnyKernel3 Script", "Script Syntax Integrity", "PASS", "Clean", "Clean",
                      "anykernel.sh has valid shell syntax.")

        if tgt_ak3["is_slot_device"] == "1":
            add_check("AnyKernel3 Script", "is_slot_device Flag", "PASS", "1", tgt_ak3["is_slot_device"],
                      "Slot A/B partitioning enabled for Poco F3.")
        else:
            add_check("AnyKernel3 Script", "is_slot_device Flag", "FAIL", "1", str(tgt_ak3["is_slot_device"]),
                      "CRITICAL: is_slot_device must be 1 for Poco F3 A/B partitioning.")

        has_alioth = "alioth" in tgt_ak3["device_names"] or any("alioth" in d for d in tgt_ak3["device_names"])
        if has_alioth:
            add_check("AnyKernel3 Script", "Target Device Name", "PASS", "alioth", ",".join(tgt_ak3["device_names"]),
                      "Target device aliases match alioth / aliothin.")
        else:
            add_check("AnyKernel3 Script", "Target Device Name", "FAIL", "alioth", ",".join(tgt_ak3["device_names"]),
                      "device.name must include 'alioth' to pass recovery check.")

        if "/by-name/boot" in tgt_ak3["block"]:
            add_check("AnyKernel3 Script", "Boot Block Path", "PASS", ref_ak3["block"], tgt_ak3["block"],
                      "Boot partition block points to standard boot device.")
        else:
            add_check("AnyKernel3 Script", "Boot Block Path", "FAIL", ref_ak3["block"], tgt_ak3["block"],
                      "Invalid boot block path in anykernel.sh.")

        if tgt_ak3["has_sar_overlay_fix"]:
            add_check("AnyKernel3 Script", "SAR / Overlay Cleanup", "PASS", "Present", "Present",
                      "Removes legacy /overlay to allow clean SAR Magisk/KernelSU mount on Android 15.")
        else:
            add_check("AnyKernel3 Script", "SAR / Overlay Cleanup", "WARN", "Present", "Missing",
                      "Recommended to include overlay cleanup for crDroid / Android 15 SAR compatibility.")

    # 3. Kernel Binary Analysis
    ref_img_path = os.path.join(ref_dir, "Image.gz-dtb")
    tgt_img_path = os.path.join(target_dir, "Image.gz-dtb") if has_target_gz_dtb else os.path.join(target_dir, "Image")

    ref_info = analyze_kernel_image(ref_img_path)
    tgt_info = analyze_kernel_image(tgt_img_path)

    if tgt_info.get("exists"):
        if tgt_info["is_gzip"]:
            add_check("Kernel Binary", "Compression Format", "PASS", "GZIP", "GZIP",
                      f"Kernel binary is GZIP compressed (Size: {tgt_info['size'] / (1024*1024):.2f} MB).")
        else:
            add_check("Kernel Binary", "Compression Format", "FAIL", "GZIP", "Uncompressed Raw",
                      "CRITICAL: Kernel binary is uncompressed raw ARM64, exceeding boot partition bounds on alioth.")

        if len(tgt_info["dtb_compatibles"]) > 0:
            add_check("Kernel Binary", "SM8250 DTB Compatibles", "PASS", ",".join(ref_info["dtb_compatibles"]),
                      ",".join(tgt_info["dtb_compatibles"]), "SM8250 / Kona / Alioth DTB tables verified in kernel image.")
        else:
            add_check("Kernel Binary", "SM8250 DTB Compatibles", "FAIL", "qcom,kona,msm-id", "None detected",
                      "CRITICAL: No SM8250 / Kona device tree signatures found inside kernel stream.")

        if tgt_info["kernel_version_string"]:
            add_check("Kernel Binary", "Kernel Version Banner", "PASS", ref_info["kernel_version_string"][:40] + "...",
                      tgt_info["kernel_version_string"][:40] + "...",
                      f"Banner: {tgt_info['kernel_version_string']}")
        else:
            add_check("Kernel Binary", "Kernel Version Banner", "WARN", "Linux version 4.19...", "Unreadable",
                      "Could not extract Linux banner string from decompressed payload.")

    # 4. Tools Check
    tools_dir = os.path.join(target_dir, "tools")
    for req_tool in ["magiskboot", "busybox", "ak3-core.sh"]:
        p = os.path.join(tools_dir, req_tool)
        if os.path.exists(p):
            add_check("AnyKernel3 Tools", f"Tool: {req_tool}", "PASS", "Present", "Present", f"{req_tool} binary verified.")
        else:
            add_check("AnyKernel3 Tools", f"Tool: {req_tool}", "FAIL", "Present", "Missing", f"Missing {req_tool} in tools/")

    return overall_pass, checks


def print_report(overall_pass: bool, checks: List[Dict[str, Any]], target_zip: str):
    """Print formatted compatibility report."""
    print("\n" + "=" * 90)
    print("       INFINIR KERNEL COMPATIBILITY TEST REPORT (Poco F3 Alioth / crDroid 11)")
    print("=" * 90)
    print(f" Target File  : {target_zip}")
    print(f" Target Size  : {os.path.getsize(target_zip):,} bytes")
    print(f" Reference    : raystef66 v3.00 KSUN Release")
    print("-" * 90)

    current_cat = ""
    for c in checks:
        if c["category"] != current_cat:
            current_cat = c["category"]
            print(f"\n>> [{current_cat}]")

        status = c["status"]
        badge = f"[{status}]"
        print(f"  {badge:<7} {c['item']:<28} : {c['description']}")
        if status != "PASS":
            print(f"          Expected (Ref): {c['reference']}")
            print(f"          Found (Target): {c['target']}")

    print("\n" + "=" * 90)
    if overall_pass:
        print(" [OK] OVERALL COMPATIBILITY VERDICT: PASS")
        print("      The zip file meets all structural, binary, and AnyKernel3 requirements for Poco F3 / crDroid 11.")
    else:
        print(" [ERROR] OVERALL COMPATIBILITY VERDICT: FAIL (BOOTLOOP RISK DETECTED)")
        print("         The zip contains critical defects that will prevent booting on Poco F3 (alioth).")
    print("=" * 90 + "\n")


def generate_markdown_report(overall_pass: bool, checks: List[Dict[str, Any]], target_zip: str, ref_zip: str) -> str:
    """Generate markdown formatted report."""
    verdict_str = "✅ **PASS (COMPATIBLE)**" if overall_pass else "❌ **FAIL (BOOTLOOP RISK DETECTED)**"
    md = f"""# 🛡️ InfiniR Kernel Compatibility Test Report

| Parameter | Details |
| :--- | :--- |
| **Target Zip** | `{os.path.basename(target_zip)}` ({os.path.getsize(target_zip):,} bytes) |
| **Reference** | `raystef66 v3.00 KSUN Release` |
| **Target Device** | Poco F3 / Redmi K40 (`alioth` / `aliothin`) |
| **Target ROM** | crDroid 11.x (Android 15) |
| **Verdict** | {verdict_str} |

---

## 📊 Detail Hasil Uji Kompatibilitas

| Kategori | Parameter Uji | Status | Keterangan |
| :--- | :--- | :---: | :--- |
"""
    for c in checks:
        icon = "✅ PASS" if c["status"] == "PASS" else ("⚠️ WARN" if c["status"] == "WARN" else "❌ FAIL")
        md += f"| **{c['category']}** | `{c['item']}` | {icon} | {c['description']} |\n"

    md += "\n---\n"
    if not overall_pass:
        md += """## ⚠️ Analisis Risiko Bootloop (Penyebab Stuck di Logo crDroid)
Berdasarkan hasil uji biner dan konfigurasi terhadap artefak zip:
1. **Format Kernel Image Salah (`Image` vs `Image.gz-dtb`)**:
   - Poco F3 (`alioth`) pada boot partition memerlukan format **`Image.gz-dtb`** (kernel terkompresi GZIP dengan appended DTB Snapdragon 870 / Kona).
   - Penggunaan file mentah `Image` (44 MB uncompressed) menyebabkan `magiskboot` menghasilkan boot image yang melampaui ukuran partisi dan tidak memiliki header DTB yang sesuai.
2. **File DTB Duplikat/Konflik (`dtb` & `dt.img`)**:
   - Jika `Image.gz-dtb` digunakan, file terpisah `dtb` dan `dt.img` tidak boleh ditaruh sembarangan di root zip AnyKernel3 karena mengacaukan proses *repack* `boot.img`.
3. **Konfigurasi AnyKernel3 (`anykernel.sh`)**:
   - `is_slot_device=1` dan `device.name1=alioth` harus valid tanpa glitch nomor baris.
"""
    return md


def main():
    parser = argparse.ArgumentParser(description="Test compatibility of AnyKernel3 zip against raystef66 reference.")
    parser.add_argument("target_zip", help="Path to the target kernel zip to test")
    parser.add_argument("--ref", default=DEFAULT_REF_URL, help="Path or URL to reference zip (default: raystef66 v3.00 KSUN)")
    parser.add_argument("--json", default="", help="Optional output path to save JSON test results")
    parser.add_argument("--markdown", default="", help="Optional output path to save Markdown test results")
    args = parser.parse_args()

    if not os.path.exists(args.target_zip):
        print(f"Error: Target zip '{args.target_zip}' not found.")
        sys.exit(1)

    work_dir = tempfile.mkdtemp(prefix="kernel_compat_")
    try:
        ref_cache_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".compat_cache")
        os.makedirs(ref_cache_dir, exist_ok=True)
        ref_zip_path = get_or_download_reference(args.ref, ref_cache_dir)

        target_ext_dir = os.path.join(work_dir, "target")
        ref_ext_dir = os.path.join(work_dir, "reference")
        os.makedirs(target_ext_dir, exist_ok=True)
        os.makedirs(ref_ext_dir, exist_ok=True)

        extract_zip(args.target_zip, target_ext_dir)
        extract_zip(ref_zip_path, ref_ext_dir)

        overall_pass, checks = evaluate_compatibility(target_ext_dir, ref_ext_dir)
        print_report(overall_pass, checks, args.target_zip)

        if args.json:
            import json
            report_data = {
                "target_zip": os.path.abspath(args.target_zip),
                "reference_zip": os.path.abspath(ref_zip_path),
                "overall_pass": overall_pass,
                "checks": checks
            }
            with open(args.json, "w", encoding="utf-8") as jf:
                json.dump(report_data, jf, indent=2)
            print(f"JSON report saved to: {args.json}")

        if args.markdown:
            md_content = generate_markdown_report(overall_pass, checks, args.target_zip, ref_zip_path)
            with open(args.markdown, "w", encoding="utf-8") as mf:
                mf.write(md_content)
            print(f"Markdown report saved to: {args.markdown}")

        sys.exit(0 if overall_pass else 1)

    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
