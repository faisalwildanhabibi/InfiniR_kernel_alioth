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
    
    # 1. Patch SELinux uninitialized SID checks
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

    # 2. Patch APK signature verification in apk_sign.c
    apk_sign_c = os.path.join(ksu_dir, "kernel", "manager", "apk_sign.c")
    if os.path.exists(apk_sign_c):
        with open(apk_sign_c, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()

        # Allow dual v2+v3 signatures (standard on Android 11+)
        old_v3_check = """\tif (v3_signing_exist || v3_1_signing_exist) {
#ifdef CONFIG_KSU_DEBUG
\t\tpr_err("Unexpected v3 signature scheme found!\\n");
#endif
\t\treturn false;
\t}"""
        if old_v3_check in code:
            code = code.replace(old_v3_check, "\t// Allow v3 / v3.1 signatures since Android 11+ produces dual signatures\\n\t(void)v3_signing_exist;\\n\t(void)v3_1_signing_exist;")
            print(f"[OK] Removed strict v3 signature rejection in {apk_sign_c}")

        # Multi-key verification in check_block
        old_check_block = """\t\tchar hash_str[SHA256_DIGEST_SIZE * 2 + 1];
\t\thash_str[SHA256_DIGEST_SIZE * 2] = '\\0';

\t\tbin2hex(hash_str, digest, SHA256_DIGEST_SIZE);
\t\tpr_info("sha256: %s, expected: %s\\n", hash_str,
\t\t\texpected_sha256);
\t\tif (strcmp(expected_sha256, hash_str) == 0) {
\t\t\treturn true;
\t\t}"""

        new_check_block = """\t\tchar hash_str[SHA256_DIGEST_SIZE * 2 + 1];
\t\thash_str[SHA256_DIGEST_SIZE * 2] = '\\0';

\t\tbin2hex(hash_str, digest, SHA256_DIGEST_SIZE);
\t\tpr_info("manager apk sha256: %s, size: 0x%x\\n", hash_str, *size4);

\t\t// 1. KernelSU-Next official manager key
\t\tif (strcmp("79e590113c4c4c0c222978e413a5faa801666957b1212a328e46c00c69821bf7", hash_str) == 0)
\t\t\treturn true;
\t\t// 2. KernelSU official manager key (weishu)
\t\tif (strcmp("e848cf14ff57d549a099a4c2d431c34a413d5267d32c54ee9ee94f997637db91", hash_str) == 0)
\t\t\treturn true;
\t\t// 3. Android / KernelSU testkey
\t\tif (strcmp("c92257d0e408803ad73a87588b9c8b73f76da0e50e82c50a16c4983a48e7da47", hash_str) == 0)
\t\t\treturn true;
\t\t// 4. Expected manager hash from Kbuild
\t\tif (expected_sha256 && strcmp(expected_sha256, hash_str) == 0)
\t\t\treturn true;"""

        if old_check_block in code:
            code = code.replace(old_check_block, new_check_block)
            print(f"[OK] Added multi-key Manager support in {apk_sign_c}")

        with open(apk_sign_c, "w", encoding="utf-8") as f:
            f.write(code)

if __name__ == "__main__":
    main()
