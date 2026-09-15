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

    # 2. Patch manager_identity.h to treat root (UID 0) as manager as well
    mgr_id_h = os.path.join(ksu_dir, "kernel", "manager", "manager_identity.h")
    if os.path.exists(mgr_id_h):
        old_is_mgr = """static inline bool is_manager()
{
	return unlikely(ksu_manager_appid == current_uid().val % KSU_PER_USER_RANGE);
}"""
        new_is_mgr = """static inline bool is_manager()
{
	if (current_uid().val == 0)
		return true;
	if (ksu_manager_appid != KSU_INVALID_APPID &&
	    ksu_manager_appid == current_uid().val % KSU_PER_USER_RANGE)
		return true;
	return false;
}"""
        patch_file(mgr_id_h, old_is_mgr, new_is_mgr)

    # 3. Patch supercall.c (Auto-crowning manager on install_fd & SuSFS info query permissions)
    supercall_c = os.path.join(ksu_dir, "kernel", "supercall", "supercall.c")
    if os.path.exists(supercall_c):
        with open(supercall_c, "r", encoding="utf-8", errors="ignore") as f:
            sc_code = f.read()

        # A. Allow SuSFS info queries for manager and read-only commands
        old_susfs_perm = "if (magic2 == SUSFS_MAGIC && current_uid().val == 0) {"
        new_susfs_perm = "if (magic2 == SUSFS_MAGIC && (current_uid().val == 0 || is_manager() || cmd == CMD_SUSFS_SHOW_VERSION || cmd == CMD_SUSFS_SHOW_VARIANT || cmd == CMD_SUSFS_SHOW_ENABLED_FEATURES)) {"
        if old_susfs_perm in sc_code:
            sc_code = sc_code.replace(old_susfs_perm, new_susfs_perm)
            print(f"[OK] Patched SuSFS query permissions in {supercall_c}")

        # B. Auto-crown manager on install_fd if not yet crowned
        old_install_fd = """\t\tif (copy_to_user((void __user *)*arg, &fd, sizeof(fd))) {
\t\t\tpr_err("install ksu fd reply err\\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
\t\tclose_fd(fd);
#else
\t\t__close_fd(current->files, fd);
#endif
\t\t}
\t\treturn 0;"""

        new_install_fd = """\t\tif (copy_to_user((void __user *)*arg, &fd, sizeof(fd))) {
\t\t\tpr_err("install ksu fd reply err\\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
\t\tclose_fd(fd);
#else
\t\t__close_fd(current->files, fd);
#endif
\t\t} else {
\t\t\tif (!ksu_is_manager_appid_valid()) {
\t\t\t\tuid_t appid = current_uid().val % KSU_PER_USER_RANGE;
\t\t\t\tif (appid >= 10000) {
\t\t\t\t\tpr_info("ksu: auto-crowning manager appid %d from install_fd\\n", appid);
\t\t\t\t\tksu_set_manager_appid(appid);
\t\t\t\t}
\t\t\t}
\t\t}
\t\treturn 0;"""
        if old_install_fd in sc_code:
            sc_code = sc_code.replace(old_install_fd, new_install_fd)
            print(f"[OK] Patched install_fd auto-crowning in {supercall_c}")

        with open(supercall_c, "w", encoding="utf-8") as f:
            f.write(sc_code)

    # 4. Patch APK signature verification in apk_sign.c (Fixes Manager detection on Android 15 while keeping upstream hash)
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

        # B. Allow v1 signature alongside v2
        old_v1_check = """\tif (v2_signing_valid) {
\t\tint has_v1_signing = has_v1_signature_file(fp);
\t\tif (has_v1_signing) {
\t\t\tpr_err("Unexpected v1 signature scheme found!\\n");
\t\t\tfilp_close(fp, 0);
\t\t\treturn false;
\t\t}
\t}"""
        new_v1_check = """\tif (v2_signing_valid) {
\t\t// Allow v1 signature alongside v2 for standard production APKs
\t\t(void)has_v1_signature_file;
\t}"""
        if old_v1_check in code:
            code = code.replace(old_v1_check, new_v1_check)
            print(f"[OK] Removed strict v1 signature rejection in {apk_sign_c}")

        # C. Allow flexible certificate block length for upstream expected_sha256
        old_block_cond = "if (*size4 == expected_size) {"
        new_block_cond = "if (*size4 > 0 && *size4 <= 1024) {"
        if old_block_cond in code:
            code = code.replace(old_block_cond, new_block_cond, 1)
            print(f"[OK] Enabled flexible cert block length in {apk_sign_c}")

        with open(apk_sign_c, "w", encoding="utf-8") as f:
            f.write(code)

if __name__ == "__main__":
    main()

