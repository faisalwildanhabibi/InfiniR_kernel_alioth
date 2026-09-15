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
import hashlib
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
    print(f"  [PASS] {msg}")


def log_fail(msg: str):
    print(f"  [FAIL] {msg}")


def log_warn(msg: str):
    print(f"  [WARN] {msg}")


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


def extract_zip_info(zip_path: str) -> Dict[str, Any]:
    """Inspect and extract zip archive information."""
    res = {
        "file_path": zip_path,
        "file_size": os.path.getsize(zip_path),
        "sha256": "",
        "files": {},
        "namelist": []
    }
    with open(zip_path, "rb") as f:
        res["sha256"] = hashlib.sha256(f.read()).hexdigest()
        
    with zipfile.ZipFile(zip_path, 'r') as z:
        res["namelist"] = z.namelist()
        for info in z.infolist():
            if not info.is_dir():
                raw = z.read(info.filename)
                res["files"][info.filename] = {
                    "size": info.file_size,
                    "crc": info.CRC,
                    "sha256": hashlib.sha256(raw).hexdigest()
                }
    return res


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

    for idx, line in enumerate(lines, 1):
        clean = line.strip()
        if clean.startswith(("\t1\t", " 1\t", "1\t", "1  #", "1 #")):
            info["has_line_number_glitch"] = True
            info["syntax_errors"].append(f"Line {idx}: Line number artifact detected ('{clean[:20]}...')")
        
        if "is_slot_device=" in clean:
            val = clean.split("=")[1].strip().rstrip(";").strip('"').strip("'")
            info["is_slot_device"] = val
        if "block=" in clean:
            val = clean.split("=")[1].strip().rstrip(";").strip('"').strip("'")
            info["block"] = val
        if "device.name" in clean and "=" in clean:
            val = clean.split("=")[1].strip().rstrip(";").strip('"').strip("'")
            if val:
                info["device_names"].append(val)

    return info


def decompress_kernel_stream(raw_data: bytes) -> Tuple[bytes, bytes]:
    """
    Decompresses the primary GZIP kernel image and extracts any appended DTB payload.
    Returns (decompressed_kernel_bytes, appended_dtb_bytes).
    """
    gz_idx = raw_data.find(GZIP_MAGIC)
    if gz_idx == -1:
        return b"", b""
    
    decompressed = b""
    unused = b""
    try:
        # Decompress up to stream end (zlib with wbits=31 handles gzip headers)
        d = zlib.decompressobj(wbits=31)
        decompressed = d.decompress(raw_data[gz_idx:])
        unused = d.unused_data
    except Exception as e:
        # Fallback to standard gzip module if single stream
        try:
            decompressed = gzip.decompress(raw_data[gz_idx:])
        except Exception:
            pass

    return decompressed, unused


def analyze_dtb_stream(dtb_bytes: bytes) -> Dict[str, Any]:
    """Parses appended DTB stream for FDT header magics and SM8250 compatible strings."""
    info = {
        "size": len(dtb_bytes),
        "sha256": hashlib.sha256(dtb_bytes).hexdigest() if dtb_bytes else "",
        "fdt_count": 0,
        "has_fdt_magic": False,
        "compatibles": [],
        "models": [],
        "is_sm8250_kona": False
    }
    
    if not dtb_bytes:
        return info
    
    # Count 0xd00dfeed occurrences
    offset = 0
    while True:
        pos = dtb_bytes.find(FDT_MAGIC, offset)
        if pos == -1:
            break
        info["fdt_count"] += 1
        offset = pos + 4

    info["has_fdt_magic"] = (info["fdt_count"] > 0)
    
    # Scan for known SoC and Board compatible strings in DTB blobs
    for pattern in [b"qcom,sm8250", b"qcom,kona", b"xiaomi,alioth", b"xiaomi,aliothin", b"Qualcomm Technologies, Inc. Kona"]:
        if pattern in dtb_bytes:
            info["compatibles"].append(pattern.decode('ascii', errors='ignore'))
            
    if "qcom,kona" in info["compatibles"] or "qcom,sm8250" in info["compatibles"] or b"msm-id" in dtb_bytes:
        info["is_sm8250_kona"] = True

    return info


def analyze_kernel_binary(decompressed: bytes) -> Dict[str, Any]:
    """Inspect decompressed kernel for ARM64 header, banner, and symbols."""
    info = {
        "size": len(decompressed),
        "sha256": hashlib.sha256(decompressed).hexdigest() if decompressed else "",
        "is_arm64": False,
        "banner": "",
        "has_ksu": False,
        "has_susfs": False,
        "text_offset": None,
        "image_size": None
    }
    
    if len(decompressed) < 64:
        return info
    
    # ARM64 Image Header check
    # Offset 0x38: Magic "ARM\x64" (0x644d5241)
    if decompressed[0x38:0x3c] == ARM64_MAGIC:
        info["is_arm64"] = True
        try:
            info["text_offset"] = struct.unpack("<Q", decompressed[0x08:0x10])[0]
            info["image_size"] = struct.unpack("<Q", decompressed[0x10:0x18])[0]
        except Exception:
            pass

    # Extract Linux Banner string
    banner_idx = decompressed.find(b"Linux version 4.19.")
    if banner_idx != -1:
        end_idx = decompressed.find(b"\x00", banner_idx)
        if end_idx != -1:
            info["banner"] = decompressed[banner_idx:end_idx].decode('utf-8', errors='replace')

    # Scan for KernelSU & SuSFS strings / signatures
    if b"KernelSU" in decompressed or b"ksu_" in decompressed:
        info["has_ksu"] = True
    if b"susfs" in decompressed or b"susfs_" in decompressed:
        info["has_susfs"] = True

    return info


def analyze_dtbo(dtbo_bytes: bytes) -> Dict[str, Any]:
    """Analyze dtbo.img header and entries."""
    info = {
        "size": len(dtbo_bytes),
        "sha256": hashlib.sha256(dtbo_bytes).hexdigest() if dtbo_bytes else "",
        "is_valid": False,
        "entry_count": 0,
        "page_size": 0
    }
    if len(dtbo_bytes) >= 32 and dtbo_bytes[:4] == DTBO_MAGIC:
        info["is_valid"] = True
        try:
            # Android DTBO header: magic(4), total_size(4), header_size(4), dt_entry_size(4), dt_entry_count(4), dt_entries_offset(4), page_size(4), version(4)
            magic, total_size, hdr_size, entry_size, entry_count, entries_offset, page_size, version = struct.unpack(">8I", dtbo_bytes[:32])
            info["entry_count"] = entry_count
            info["page_size"] = page_size
        except Exception:
            pass
    return info


def run_full_comparison(target_zip: str, ref_zip: str) -> Dict[str, Any]:
    """Runs deep forensic comparison between target kernel zip and raystef66 reference."""
    report = {
        "target": extract_zip_info(target_zip),
        "reference": extract_zip_info(ref_zip),
        "checks": [],
        "verdict": "PASS",
        "errors": [],
        "warnings": []
    }

    # Extract payloads from both zips
    with zipfile.ZipFile(target_zip) as z_target, zipfile.ZipFile(ref_zip) as z_ref:
        target_files = z_target.namelist()
        ref_files = z_ref.namelist()
        
        # 1. AnyKernel3 Structural & File Layout Checks
        has_img_gz_dtb = "Image.gz-dtb" in target_files
        has_raw_img = "Image" in target_files
        has_loose_dtb = "dtb" in target_files or "dt.img" in target_files
        has_dtbo = "dtbo.img" in target_files
        
        if has_img_gz_dtb and not has_raw_img:
            report["checks"].append({
                "subsystem": "Structure",
                "name": "Kernel Image Payload",
                "status": "PASS",
                "detail": "Target zip contains standard Image.gz-dtb (GZIP + appended DTB format)."
            })
        elif has_raw_img:
            report["checks"].append({
                "subsystem": "Structure",
                "name": "Kernel Image Payload",
                "status": "FAIL",
                "detail": "CRITICAL: Target zip contains uncompressed raw 'Image' (44MB+) which exceeds boot partition bounds on Poco F3.",
                "expected": "Image.gz-dtb",
                "found": "Image"
            })
            report["errors"].append("Raw 'Image' payload detected instead of 'Image.gz-dtb'.")
        else:
            report["checks"].append({
                "subsystem": "Structure",
                "name": "Kernel Image Payload",
                "status": "FAIL",
                "detail": "CRITICAL: No kernel image payload found in zip root.",
                "expected": "Image.gz-dtb",
                "found": "None"
            })
            report["errors"].append("No kernel payload found.")

        if not has_loose_dtb:
            report["checks"].append({
                "subsystem": "Structure",
                "name": "Conflicting DTB Files",
                "status": "PASS",
                "detail": "No conflicting loose 'dtb' or 'dt.img' files in root."
            })
        else:
            report["checks"].append({
                "subsystem": "Structure",
                "name": "Conflicting DTB Files",
                "status": "FAIL",
                "detail": "CRITICAL: Loose 'dtb' or 'dt.img' found in AnyKernel3 root. AnyKernel3 may mis-flash and corrupt boot image.",
                "expected": "None (DTB appended directly to kernel image)",
                "found": "Loose dtb/dt.img"
            })
            report["errors"].append("Loose DTB files present in root.")

        # 2. DTBO Validation
        if has_dtbo:
            target_dtbo_raw = z_target.read("dtbo.img")
            target_dtbo_info = analyze_dtbo(target_dtbo_raw)
            ref_dtbo_raw = z_ref.read("dtbo.img")
            ref_dtbo_info = analyze_dtbo(ref_dtbo_raw)
            
            if target_dtbo_info["is_valid"]:
                dtbo_match = (target_dtbo_info["sha256"] == ref_dtbo_info["sha256"])
                report["checks"].append({
                    "subsystem": "Structure",
                    "name": "DTBO Image (dtbo.img)",
                    "status": "PASS",
                    "detail": f"Valid DTBO image present (Entries: {target_dtbo_info['entry_count']}, Page size: {target_dtbo_info['page_size']}, Match ref: {dtbo_match})."
                })
            else:
                report["checks"].append({
                    "subsystem": "Structure",
                    "name": "DTBO Image (dtbo.img)",
                    "status": "FAIL",
                    "detail": "CRITICAL: dtbo.img is present but has invalid magic header or corrupted structure.",
                    "expected": "Valid Android DTBO (0xd7b7ab1e)",
                    "found": "Invalid header"
                })
                report["errors"].append("Corrupted dtbo.img.")
        else:
            report["checks"].append({
                "subsystem": "Structure",
                "name": "DTBO Image (dtbo.img)",
                "status": "FAIL",
                "detail": "CRITICAL: dtbo.img is missing from zip. Hardware display / touchscreen overlays will fail to initialize.",
                "expected": "dtbo.img",
                "found": "Missing"
            })
            report["errors"].append("Missing dtbo.img.")

        # 3. AnyKernel3 Script Validation
        if "anykernel.sh" in target_files:
            target_ak3_content = z_target.read("anykernel.sh").decode('utf-8', errors='replace')
            target_ak3_info = analyze_anykernel_sh(target_ak3_content)
            
            if not target_ak3_info["has_line_number_glitch"] and not target_ak3_info["syntax_errors"]:
                report["checks"].append({
                    "subsystem": "AnyKernel3 Script",
                    "name": "Script Syntax Integrity",
                    "status": "PASS",
                    "detail": "anykernel.sh has clean syntax without line-number corruption or shell syntax errors."
                })
            else:
                report["checks"].append({
                    "subsystem": "AnyKernel3 Script",
                    "name": "Script Syntax Integrity",
                    "status": "FAIL",
                    "detail": f"CRITICAL: Syntax errors in anykernel.sh: {', '.join(target_ak3_info['syntax_errors'])}",
                    "expected": "Clean shell script",
                    "found": "Syntax errors / line number artifacts"
                })
                report["errors"].append("anykernel.sh syntax error.")

            # Slot device check
            if target_ak3_info["is_slot_device"] == "1":
                report["checks"].append({
                    "subsystem": "AnyKernel3 Script",
                    "name": "is_slot_device Flag",
                    "status": "PASS",
                    "detail": "is_slot_device=1 is configured (Required for Poco F3 A/B slot partition layout)."
                })
            else:
                report["checks"].append({
                    "subsystem": "AnyKernel3 Script",
                    "name": "is_slot_device Flag",
                    "status": "FAIL",
                    "detail": "CRITICAL: is_slot_device is not set to 1. Recovery cannot locate active boot partition slot.",
                    "expected": "is_slot_device=1",
                    "found": f"is_slot_device={target_ak3_info['is_slot_device']}"
                })
                report["errors"].append("is_slot_device not set to 1.")

            # Device names
            if "alioth" in target_ak3_info["device_names"] or "aliothin" in target_ak3_info["device_names"]:
                report["checks"].append({
                    "subsystem": "AnyKernel3 Script",
                    "name": "Target Device Aliases",
                    "status": "PASS",
                    "detail": f"Target device configured for: {', '.join(target_ak3_info['device_names'])}."
                })
            else:
                report["checks"].append({
                    "subsystem": "AnyKernel3 Script",
                    "name": "Target Device Aliases",
                    "status": "FAIL",
                    "detail": "CRITICAL: 'alioth' / 'aliothin' device names missing from device check.",
                    "expected": "alioth, aliothin",
                    "found": str(target_ak3_info["device_names"])
                })
                report["errors"].append("Device name mismatch in anykernel.sh.")

            # SAR Overlay removal
            if target_ak3_info["has_sar_overlay_fix"]:
                report["checks"].append({
                    "subsystem": "AnyKernel3 Script",
                    "name": "SAR / Overlay Cleanup",
                    "status": "PASS",
                    "detail": "Removes legacy /overlay in ramdisk to support System-As-Root (SAR) Magisk / KernelSU on Android 15."
                })
            else:
                report["checks"].append({
                    "subsystem": "AnyKernel3 Script",
                    "name": "SAR / Overlay Cleanup",
                    "status": "WARN",
                    "detail": "No explicit /overlay removal in ramdisk. May cause root mount collisions on SAR Android 15."
                })
                report["warnings"].append("SAR /overlay cleanup missing in anykernel.sh.")
        else:
            report["checks"].append({
                "subsystem": "AnyKernel3 Script",
                "name": "anykernel.sh Existence",
                "status": "FAIL",
                "detail": "CRITICAL: anykernel.sh missing from zip.",
                "expected": "anykernel.sh",
                "found": "Missing"
            })
            report["errors"].append("Missing anykernel.sh.")

        # 4. Kernel Binary & Appended DTB Deep Inspection
        target_payload_name = "Image.gz-dtb" if "Image.gz-dtb" in target_files else ("Image" if "Image" in target_files else None)
        if target_payload_name:
            target_raw = z_target.read(target_payload_name)
            target_decompressed, target_dtb_raw = decompress_kernel_stream(target_raw)
            target_kinfo = analyze_kernel_binary(target_decompressed)
            target_dtb_info = analyze_dtb_stream(target_dtb_raw)

            ref_raw = z_ref.read("Image.gz-dtb")
            ref_decompressed, ref_dtb_raw = decompress_kernel_stream(ref_raw)
            ref_kinfo = analyze_kernel_binary(ref_decompressed)
            ref_dtb_info = analyze_dtb_stream(ref_dtb_raw)

            # Check compression
            if len(target_decompressed) > 20_000_000 and target_raw[:2] == GZIP_MAGIC:
                report["checks"].append({
                    "subsystem": "Kernel Binary",
                    "name": "Compression & Payload Size",
                    "status": "PASS",
                    "detail": f"Kernel binary is GZIP compressed (Compressed: {len(target_raw)/1024/1024:.2f} MB, Decompressed: {len(target_decompressed)/1024/1024:.2f} MB)."
                })
            else:
                report["checks"].append({
                    "subsystem": "Kernel Binary",
                    "name": "Compression & Payload Size",
                    "status": "FAIL",
                    "detail": f"CRITICAL: Kernel binary is uncompressed or failed decompression (Size: {len(target_raw)} bytes).",
                    "expected": "GZIP (16-18 MB)",
                    "found": f"{len(target_raw)} bytes"
                })
                report["errors"].append("Invalid compression format.")

            # Check ARM64 header
            if target_kinfo["is_arm64"]:
                report["checks"].append({
                    "subsystem": "Kernel Binary",
                    "name": "ARM64 Architecture Header",
                    "status": "PASS",
                    "detail": f"Valid ARM64 64-byte Header (Magic: 0x644d5241, Text offset: 0x{target_kinfo['text_offset'] or 0:x}, Image size: {target_kinfo['image_size'] or 0} bytes)."
                })
            else:
                report["checks"].append({
                    "subsystem": "Kernel Binary",
                    "name": "ARM64 Architecture Header",
                    "status": "FAIL",
                    "detail": "CRITICAL: ARM64 header magic missing or invalid.",
                    "expected": "ARM64 header (0x644d5241)",
                    "found": "Invalid"
                })
                report["errors"].append("Corrupted ARM64 kernel header.")

            # Check Appended DTB
            if target_dtb_info["has_fdt_magic"] and target_dtb_info["is_sm8250_kona"]:
                dtb_exact_match = (target_dtb_info["size"] == ref_dtb_info["size"])
                report["checks"].append({
                    "subsystem": "Kernel Binary",
                    "name": "Appended SM8250 DTB Blobs",
                    "status": "PASS",
                    "detail": f"Appended DTBs verified ({target_dtb_info['fdt_count']} FDT blobs, {target_dtb_info['size']} bytes, SM8250/Kona verified, Length matches ref: {dtb_exact_match})."
                })
            else:
                report["checks"].append({
                    "subsystem": "Kernel Binary",
                    "name": "Appended SM8250 DTB Blobs",
                    "status": "FAIL",
                    "detail": f"CRITICAL: No valid SM8250 / Kona device tree blobs detected in appended payload ({target_dtb_info['size']} bytes). Poco F3 will fail early boot.",
                    "expected": f"SM8250 / Kona DTBs ({ref_dtb_info['size']} bytes)",
                    "found": f"{target_dtb_info['size']} bytes"
                })
                report["errors"].append("Missing SM8250 appended DTBs.")

            # Check Banner
            if target_kinfo["banner"]:
                report["checks"].append({
                    "subsystem": "Kernel Binary",
                    "name": "Linux Version Banner",
                    "status": "PASS",
                    "detail": f"Banner: {target_kinfo['banner']}"
                })
            else:
                report["checks"].append({
                    "subsystem": "Kernel Binary",
                    "name": "Linux Version Banner",
                    "status": "WARN",
                    "detail": "Could not extract Linux version banner string from decompressed payload."
                })
                report["warnings"].append("Could not extract Linux banner.")

        # 5. Tooling Binaries Check
        for tool in ["tools/magiskboot", "tools/busybox", "tools/ak3-core.sh", "tools/magiskpolicy"]:
            if tool in target_files:
                target_hash = report["target"]["files"][tool]["sha256"]
                ref_hash = report["reference"]["files"].get(tool, {}).get("sha256", "")
                is_match = (target_hash == ref_hash) if ref_hash else True
                report["checks"].append({
                    "subsystem": "AnyKernel3 Tools",
                    "name": f"Tool: {os.path.basename(tool)}",
                    "status": "PASS",
                    "detail": f"{tool} verified (Size: {report['target']['files'][tool]['size']} bytes, Matches ref: {is_match})."
                })
            else:
                report["checks"].append({
                    "subsystem": "AnyKernel3 Tools",
                    "name": f"Tool: {os.path.basename(tool)}",
                    "status": "WARN" if tool == "tools/magiskpolicy" else "FAIL",
                    "detail": f"Tool binary {tool} missing.",
                    "expected": tool,
                    "found": "Missing"
                })
                if tool != "tools/magiskpolicy":
                    report["errors"].append(f"Missing {tool}")

    # Calculate final verdict
    if report["errors"]:
        report["verdict"] = "FAIL"
    elif report["warnings"]:
        report["verdict"] = "PASS_WITH_WARNINGS"
    else:
        report["verdict"] = "PASS"

    return report


def print_cli_report(report: Dict[str, Any]):
    """Pretty prints compatibility analysis report to standard output."""
    print("\n" + "=" * 90)
    print("       INFINIR KERNEL COMPATIBILITY TEST REPORT (Poco F3 Alioth / crDroid 11)")
    print("=" * 90)
    print(f" Target File  : {report['target']['file_path']}")
    print(f" Target Size  : {report['target']['file_size']:,} bytes")
    print(f" Reference    : raystef66 v3.00 KSUN Release")
    print("-" * 90)

    current_sub = ""
    for check in report["checks"]:
        if check["subsystem"] != current_sub:
            current_sub = check["subsystem"]
            print(f"\n>> [{current_sub}]")
        
        status_tag = f"[{check['status']}]"
        print(f"  {status_tag:8s} {check['name']:28s} : {check['detail']}")
        if check["status"] == "FAIL" and "expected" in check:
            print(f"          Expected (Ref): {check['expected']}")
            print(f"          Found (Target): {check['found']}")

    print("\n" + "=" * 90)
    if report["verdict"] == "PASS":
        print(" [OK] OVERALL COMPATIBILITY VERDICT: PASS")
        print("      The zip file meets all structural, binary, and AnyKernel3 requirements for Poco F3 / crDroid 11.")
    elif report["verdict"] == "PASS_WITH_WARNINGS":
        print(" [!] OVERALL COMPATIBILITY VERDICT: PASS WITH WARNINGS")
        print("     The zip is structurally compatible, but review the warnings above before flashing.")
    else:
        print(" [ERROR] OVERALL COMPATIBILITY VERDICT: FAIL (BOOTLOOP RISK DETECTED)")
        print("         The zip contains critical defects that will prevent booting on Poco F3 (alioth).")
    print("=" * 90 + "\n")


def generate_markdown_report(report: Dict[str, Any]) -> str:
    """Formats report into GitHub-flavored Markdown for CI summaries."""
    md = []
    md.append("## 🛡️ InfiniR Kernel Compatibility Test Report")
    md.append(f"- **Target File**: `{os.path.basename(report['target']['file_path'])}` ({report['target']['file_size']:,} bytes)")
    md.append(f"- **Reference Standard**: `InfiniR_Alioth_v3.00_KSUN_raystef66.zip`")
    
    if report["verdict"] == "PASS":
        md.append("- **Verdict**: 🟢 **PASS** (100% Compatible with Poco F3 / crDroid 11)")
    elif report["verdict"] == "PASS_WITH_WARNINGS":
        md.append("- **Verdict**: 🟡 **PASS WITH WARNINGS**")
    else:
        md.append("- **Verdict**: 🔴 **FAIL (BOOTLOOP RISK DETECTED)**")
        
    md.append("\n| Subsystem | Check Item | Result | Details |")
    md.append("| :--- | :--- | :---: | :--- |")
    for check in report["checks"]:
        icon = "✅" if check["status"] == "PASS" else ("⚠️" if check["status"] == "WARN" else "❌")
        detail = check["detail"].replace("|", "\\|")
        md.append(f"| **{check['subsystem']}** | {check['name']} | {icon} {check['status']} | {detail} |")
        
    if report["errors"]:
        md.append("\n### ❌ Critical Defects Detected:")
        for err in report["errors"]:
            md.append(f"- 🔴 {err}")
            
    if report["warnings"]:
        md.append("\n### ⚠️ Advisory Warnings:")
        for warn in report["warnings"]:
            md.append(f"- 🟡 {warn}")

    return "\n".join(md)


def main():
    parser = argparse.ArgumentParser(description="Validate InfiniR kernel AnyKernel3 zip compatibility against raystef66 reference.")
    parser.add_argument("target", help="Path to generated kernel zip file")
    parser.add_argument("--ref", default=DEFAULT_REF_URL, help="Path or URL to raystef66 reference zip")
    parser.add_argument("--json", help="Save JSON report to file")
    parser.add_argument("--markdown", help="Save Markdown report to file")
    args = parser.parse_args()

    if not os.path.exists(args.target):
        print(f"::error::Target zip not found: {args.target}")
        sys.exit(1)

    cache_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".compat_cache")
    os.makedirs(cache_dir, exist_ok=True)
    ref_zip = get_or_download_reference(args.ref, cache_dir)

    report = run_full_comparison(args.target, ref_zip)
    print_cli_report(report)

    if args.json:
        import json
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"JSON report saved to: {args.json}")

    if args.markdown:
        md_text = generate_markdown_report(report)
        with open(args.markdown, "w", encoding="utf-8") as f:
            f.write(md_text)
        print(f"Markdown report saved to: {args.markdown}")

    if report["verdict"] == "FAIL":
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
