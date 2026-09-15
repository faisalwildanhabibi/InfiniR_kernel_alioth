import os
import sys

def patch_file(path, old_str, new_str):
    if not os.path.exists(path):
        print(f"[WARN] File not found: {path}")
        return False
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    if old_str in content:
        content = content.replace(old_str, new_str)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"[OK] Patched {path}")
        return True
    elif new_str in content:
        print(f"[OK] Already patched: {path}")
        return True
    else:
        print(f"[WARN] Target string not found in {path}")
        return False

def main():
    ksu_dir = sys.argv[1] if len(sys.argv) > 1 else "KernelSU-Next"
    
    # 1. Patch SELinux uninitialized SID checks (fixes early boot init freeze)
    selinux_c = os.path.join(ksu_dir, "kernel", "selinux", "selinux.c")
    patch_file(selinux_c, 
               "return unlikely(current_sid() == susfs_zygote_sid);",
               "return unlikely(susfs_zygote_sid && current_sid() == susfs_zygote_sid);")
    patch_file(selinux_c,
               "return unlikely(current_sid() == susfs_ksu_sid);",
               "return unlikely(susfs_ksu_sid && current_sid() == susfs_ksu_sid);")
    patch_file(selinux_c,
               "return unlikely(current_sid() == susfs_init_sid);",
               "return unlikely(susfs_init_sid && current_sid() == susfs_init_sid);")

    # 2. Patch APK signature verification in apk_sign.c (fixes Manager detection on Android 15)
    apk_sign_c = os.path.join(ksu_dir, "kernel", "manager", "apk_sign.c")
    if os.path.exists(apk_sign_c):
        with open(apk_sign_c, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()

        # A. Remove v3 signature rejection so Android 15 dual-signed APKs pass
        old_v3_check = """\tif (v3_signing_exist || v3_1_signing_exist) {
#ifdef CONFIG_KSU_DEBUG
\t\tpr_err("Unexpected v3 signature scheme found!\\n");
#endif
\t\treturn false;
\t}"""
        if old_v3_check in code:
            code = code.replace(old_v3_check, "/* v3 signature scheme allowed on Android 11+ */")
            print(f"[OK] Removed strict v3 signature rejection in {apk_sign_c}")

        # B. Support multiple Manager keys (Next 1.1.1/3.3.0 + Official KernelSU + Testkeys)
        old_block_cond = "if (*size4 == expected_size) {"
        new_block_cond = "if (*size4 > 0 && *size4 <= 1024) {"
        if old_block_cond in code:
            code = code.replace(old_block_cond, new_block_cond, 1)

        old_match = """\t\tif (strcmp(expected_sha256, hash_str) == 0) {
\t\t\treturn true;
\t\t}"""

        new_match = """\t\t// 1. KernelSU-Next official manager key
\t\tif (strcmp("79e590113c4c4c0c222978e413a5faa801666957b1212a328e46c00c69821bf7", hash_str) == 0)
\t\t\treturn true;
\t\t// 2. KernelSU official manager key (weishu)
\t\tif (strcmp("e848cf14ff57d549a099a4c2d431c34a413d5267d32c54ee9ee94f997637db91", hash_str) == 0)
\t\t\treturn true;
\t\t// 3. Android / KernelSU testkey
\t\tif (strcmp("c92257d0e408803ad73a87588b9c8b73f76da0e50e82c50a16c4983a48e7da47", hash_str) == 0)
\t\t\treturn true;
\t\t// 4. Default expected manager hash
\t\tif (expected_sha256 && strcmp(expected_sha256, hash_str) == 0)
\t\t\treturn true;"""

        if old_match in code:
            code = code.replace(old_match, new_match, 1)
            print(f"[OK] Added multi-key Manager support in {apk_sign_c}")

        with open(apk_sign_c, "w", encoding="utf-8") as f:
            f.write(code)

if __name__ == "__main__":
    main()
